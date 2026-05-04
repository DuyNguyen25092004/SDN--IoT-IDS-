#!/usr/bin/env python3
"""
ryu_controller.py — Ryu SDN Controller for IoT IDS
====================================================
Features:
  1. L2 learning switch (OpenFlow 1.3)
  2. Port mirroring — copies all traffic to mirror port (eth11)
     so tshark / traffic_capture.py can inspect without disruption
  3. REST Flow Enforcer — receives block/unblock commands from IDS API
     and installs DROP flow rules targeting malicious src IPs

Usage (inside ryu-env-py39):
    ryu-manager ryu_controller.py --observe-links \
                --wsapi-port 8080

REST endpoints exposed by this app:
  POST /ids/block   {"ip": "10.0.0.99"}   → install DROP rule
  POST /ids/unblock {"ip": "10.0.0.99"}   → remove DROP rule
  GET  /ids/rules                          → list active block rules
"""

import eventlet
eventlet.monkey_patch()

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.lib import hub

import json
import logging
import os

LOG = logging.getLogger("ryu.app.iot_ids")

# ─── Configuration ────────────────────────────────────────────────────────────
MIRROR_PORT     = 11      # s1-eth11 — mirror destination
BLOCK_PRIORITY  = 200     # higher than normal forwarding (100)
NORMAL_PRIORITY = 100
MISS_PRIORITY   = 1       # table-miss
BLOCK_IDLE      = 0       # permanent until explicitly removed
BLOCK_HARD      = 0


class IoTIDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}          # dpid → {mac: port}
        self.blocked_ips = set()       # currently blocked src IPs
        self.datapaths   = {}          # dpid → datapath object

        # Register REST controller
        wsgi = kwargs["wsgi"]
        wsgi.register(FlowEnforcerREST, {"ids_controller": self})

    # ─── Switch handshake ─────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.datapaths[dpid] = datapath
        LOG.info("Switch connected: dpid=%016x", dpid)

        # Table-miss rule: send unmatched packets to controller
        match  = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, MISS_PRIORITY, match, actions,
                       idle=0, hard=0)

        # Mirror rule: copy ALL ingress traffic to MIRROR_PORT
        # Uses a group table approach — output to both real dst AND mirror port
        # Simpler: use a catch-all flow with two output actions (applied before
        # learning rules overwrite it for specific MACs)
        self._install_mirror_rule(datapath)

    def _install_mirror_rule(self, datapath):
        """
        Install a low-priority rule that sends every packet to the mirror port.
        The L2 learning rules (higher priority) still forward normally;
        this rule ensures a copy always reaches the IDS capture interface.

        We achieve this by installing a GROUP of type SELECT or INDIRECT,
        but the simplest OVS-compatible approach is to use a packet_in
        handler that also outputs to mirror — OR use OVS port mirroring
        via ovs-vsctl (more reliable for high-speed capture).

        Here we use the ovs-vsctl approach via a shell command since it
        doesn't consume OpenFlow table entries and works at line rate.
        """
        import subprocess
        bridge = "s1"
        try:
            # Remove any existing mirror first
            subprocess.call(
                ["sudo", "ovs-vsctl", "--", "--id=@m", "get", "mirror",
                 "ids-mirror", "--", "remove", "bridge", bridge, "mirrors", "@m"],
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

        try:
            result = subprocess.call([
                "sudo", "ovs-vsctl",
                "--", "--id=@m", "create", "mirror", "name=ids-mirror",
                "select-all=true",
                f"output-port={MIRROR_PORT}",
                "--", "add", "bridge", bridge, "mirrors", "@m"
            ])
            if result == 0:
                LOG.info("OVS mirror installed: all → port %d", MIRROR_PORT)
            else:
                LOG.warning("OVS mirror setup failed (port %d may not exist yet)",
                            MIRROR_PORT)
        except Exception as e:
            LOG.warning("Could not set up OVS mirror: %s", e)

    # ─── Packet-in handler (L2 learning switch) ───────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match["in_port"]

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # Ignore LLDP
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        # Learn MAC → port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Check if src IP is blocked (check IP layer)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt and ip_pkt.src in self.blocked_ips:
            # Drop silently — block rule should already be installed
            return

        # Determine output port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow rule so future packets don't hit controller
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac,
                                    eth_src=src_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, NORMAL_PRIORITY, match, actions,
                               buffer_id=msg.buffer_id)
                return
            else:
                self._add_flow(datapath, NORMAL_PRIORITY, match, actions)

        # Send this packet out
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    # ─── Flow rule helpers ────────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  idle=10, hard=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        kwargs = dict(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle, hard_timeout=hard
        )
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    def _del_flow_by_ip(self, datapath, src_ip):
        """Remove DROP rule for a specific src IP."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=BLOCK_PRIORITY,
            match=match
        )
        datapath.send_msg(mod)

    # ─── Public API used by REST handler ──────────────────────────────────────

    def block_ip(self, src_ip: str) -> bool:
        """Install a DROP rule for src_ip on all connected switches."""
        if src_ip in self.blocked_ips:
            LOG.info("IP %s already blocked", src_ip)
            return False

        self.blocked_ips.add(src_ip)
        LOG.warning("BLOCKING IP: %s", src_ip)

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            # Empty actions list = DROP
            self._add_flow(datapath, BLOCK_PRIORITY, match, [],
                           idle=BLOCK_IDLE, hard=BLOCK_HARD)

        return True

    def unblock_ip(self, src_ip: str) -> bool:
        """Remove DROP rule for src_ip."""
        if src_ip not in self.blocked_ips:
            return False

        self.blocked_ips.discard(src_ip)
        LOG.info("UNBLOCKING IP: %s", src_ip)

        for dpid, datapath in self.datapaths.items():
            self._del_flow_by_ip(datapath, src_ip)

        return True

    def get_blocked_ips(self):
        return list(self.blocked_ips)


# ─── REST API ─────────────────────────────────────────────────────────────────

class FlowEnforcerREST(ControllerBase):
    """
    REST endpoints for IDS → Controller communication.

    POST /ids/block     {"ip": "10.0.0.99"}
    POST /ids/unblock   {"ip": "10.0.0.99"}
    GET  /ids/rules
    """

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.ids_ctrl = data["ids_controller"]

    @route("ids", "/ids/block", methods=["POST"])
    def block(self, req, **kwargs):
        try:
            body   = json.loads(req.body)
            src_ip = body.get("ip", "").strip()
            if not src_ip:
                return self._json({"error": "missing ip"}, 400)

            success = self.ids_ctrl.block_ip(src_ip)
            return self._json({
                "status": "blocked" if success else "already_blocked",
                "ip": src_ip
            })
        except Exception as e:
            return self._json({"error": str(e)}, 500)

    @route("ids", "/ids/unblock", methods=["POST"])
    def unblock(self, req, **kwargs):
        try:
            body   = json.loads(req.body)
            src_ip = body.get("ip", "").strip()
            if not src_ip:
                return self._json({"error": "missing ip"}, 400)

            success = self.ids_ctrl.unblock_ip(src_ip)

            # Notify IDS API to reset threat score + windows for this IP.
            # This ensures the IDS starts evaluating the IP fresh (clean slate)
            # after the operator has decided to unblock it.
            ids_api_url = os.environ.get("IDS_API_URL", "http://127.0.0.1:5000")
            try:
                import urllib.request as _urllib
                _data = json.dumps({"ip": src_ip}).encode()
                _req  = _urllib.Request(
                    ids_api_url + "/unblock",
                    data=_data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with _urllib.urlopen(_req, timeout=2.0) as _resp:
                    LOG.info("IDS state reset for %s: %s",
                             src_ip, _resp.read().decode())
            except Exception as e:
                LOG.warning("Could not notify IDS API to reset state for %s: %s",
                            src_ip, e)

            return self._json({
                "status": "unblocked" if success else "not_blocked",
                "ip": src_ip,
                "ids_state": "reset"
            })
        except Exception as e:
            return self._json({"error": str(e)}, 500)

    @route("ids", "/ids/rules", methods=["GET"])
    def list_rules(self, req, **kwargs):
        return self._json({
            "blocked_ips": self.ids_ctrl.get_blocked_ips(),
            "count": len(self.ids_ctrl.get_blocked_ips())
        })

    @staticmethod
    def _json(data, status=200):
        from webob import Response
        res = Response(content_type="application/json", status=status)
        res.text = json.dumps(data)
        return res
