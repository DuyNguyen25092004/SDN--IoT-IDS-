#!/usr/bin/env python3
"""
topology.py — SDN IoT IDS Mininet Topology
===========================================
Mirrors the physical diagram exactly:
  - s1         : OVS switch (OpenFlow 1.3)
  - h1..h6     : IoT Publisher hosts (ESP32 simulation)
  - h7, h8     : IoT Subscriber hosts
  - h_broker   : Mosquitto MQTT Broker (port 1883)
  - h_attacker : Attacker host (DoS/DDoS/brute-force)
  - mirror port: s1-eth11 → traffic_capture.py reads here

Controller: Ryu running separately on localhost:6633

Usage:
    sudo mn --custom topology.py --topo iot \
            --controller remote,ip=127.0.0.1,port=6633 \
            --switch ovsk,protocols=OpenFlow13 \
            --link tc
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time
import subprocess
import os


# ─── IP addressing plan ───────────────────────────────────────────────────────
#  10.0.0.1  – 10.0.0.6   : publishers  h1-h6
#  10.0.0.7  – 10.0.0.8   : subscribers h7-h8
#  10.0.0.10              : broker      h_broker
#  10.0.0.99              : attacker    h_attacker
#  (switch s1 has no IP — pure L2 forwarding via Ryu)

BROKER_IP   = "10.0.0.10"
MQTT_PORT   = 1883
MIRROR_PORT = 11          # s1-eth11 is the dedicated mirror port

PUBLISHER_IPS  = [f"10.0.0.{i}" for i in range(1, 7)]
SUBSCRIBER_IPS = ["10.0.0.7", "10.0.0.8"]
ATTACKER_IP    = "10.0.0.99"


class IoTTopo(Topo):
    """
    Single-switch IoT topology.

    Port assignment on s1:
      eth1  – eth6   : h1–h6  (publishers)
      eth7  – eth8   : h7–h8  (subscribers)
      eth9           : h_broker
      eth10          : h_attacker
      eth11          : mirror port (no host — tshark listens here)
    """

    def build(self):
        # ── Switch ────────────────────────────────────────────────────────────
        s1 = self.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow13")

        # ── Broker host ───────────────────────────────────────────────────────
        h_broker = self.addHost(
            "hbroker",
            ip=f"{BROKER_IP}/24",
            mac="00:00:00:00:00:10",
        )
        self.addLink(h_broker, s1, bw=100)   # eth9 on s1

        # ── Publisher hosts h1-h6 ─────────────────────────────────────────────
        for i in range(1, 7):
            h = self.addHost(
                f"h{i}",
                ip=f"10.0.0.{i}/24",
                mac=f"00:00:00:00:00:0{i}",
            )
            self.addLink(h, s1, bw=10)       # eth1-eth6 on s1

        # ── Subscriber hosts h7-h8 ────────────────────────────────────────────
        for i in range(7, 9):
            h = self.addHost(
                f"h{i}",
                ip=f"10.0.0.{i}/24",
                mac=f"00:00:00:00:00:0{i}",
            )
            self.addLink(h, s1, bw=10)       # eth7-eth8 on s1

        # ── Attacker host ─────────────────────────────────────────────────────
        h_attacker = self.addHost(
            "hattacker",
            ip=f"{ATTACKER_IP}/24",
            mac="00:00:00:00:00:63",
        )
        self.addLink(h_attacker, s1, bw=100)  # eth10 on s1

        # NOTE: eth11 (mirror port) is configured by Ryu controller at runtime.
        # No host is attached — tshark on the host machine binds to the
        # OVS internal port "s1" or a dedicated veth pair set up by run_all.sh.


topos = {"iot": IoTTopo}


# ─── Standalone runner (sudo python3 topology.py) ─────────────────────────────

def run():
    setLogLevel("info")
    topo = IoTTopo()
    net = Mininet(
        topo=topo,
        controller=RemoteController("c0", ip="127.0.0.1", port=6633),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    net.start()
    info("\n*** Topology started\n")

    # ── Assign IPs explicitly (redundant but safe) ────────────────────────────
    net["hbroker"].cmd(f"ip addr add {BROKER_IP}/24 dev hbroker-eth0 2>/dev/null; true")

    # ── Configure OVS switch for OpenFlow 1.3 ────────────────────────────────
    info("*** Configuring OVS for OpenFlow 1.3\n")
    subprocess.call(["sudo", "ovs-vsctl", "set", "bridge", "s1",
                     "protocols=OpenFlow13"])

    # ── Start Mosquitto broker on h_broker ───────────────────────────────────
    info("*** Starting Mosquitto broker on hbroker\n")
    broker = net["hbroker"]
    # broker.cmd("mosquitto -d -p 1883 -v > /tmp/mosquitto.log 2>&1")
    # broker.cmd("mosquitto -p 1883 --listener 1883 0.0.0.0 --allow-anonymous true > /tmp/mosquitto.log 2>&1 &")
    # time.sleep(1)
    broker.cmd("echo 'listener 1883 0.0.0.0\nallow_anonymous true' > /tmp/mosquitto.conf")
    broker.cmd("mosquitto -c /tmp/mosquitto.conf > /tmp/mosquitto.log 2>&1 &")
    time.sleep(1)
    # ── Set up default routes so all hosts can reach broker ──────────────────
    for h in net.hosts:
        h.cmd(f"ip route add default via {BROKER_IP} 2>/dev/null; true")

    # ── Print host info ───────────────────────────────────────────────────────
    info("\n*** Host summary:\n")
    for h in net.hosts:
        info(f"  {h.name:12s} {h.IP()}\n")

    info("\n*** Mirror port will be configured by Ryu controller (s1-eth11)\n")
    info("*** Normal traffic: run normal_traffic.py from each publisher host\n")
    info("*** Attack traffic: run attack scripts from hattacker\n")
    info("*** IDS capture:    run traffic_capture.py on the host machine\n\n")

    CLI(net)

    net.stop()
    info("*** Cleanup complete\n")


if __name__ == "__main__":
    run()