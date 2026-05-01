#!/usr/bin/env python3
"""
traffic_capture.py — Live Traffic Capture & Feature Extraction  (v5 — 16 features)
====================================================================================
Runs tshark on the OVS mirror interface, extracts the 12 static features used
by best_model.pkl (XGBoost v5) plus passes raw fields so ids_api.py can compute
the 4 per-IP aggregate features (time_delta_mean, time_delta_std, pkt_rate,
pub_to_conn_ratio) internally from its sliding window.

Static tshark features sent to /predict:
  tcp.len, tcp.time_delta, tcp.flags,
  mqtt.msgtype, mqtt.msgid, mqtt.qos, mqtt.dupflag,
  mqtt.len, mqtt.kalive, mqtt.conack.val, mqtt.conflag.passwd, mqtt.retain

Aggregate features (time_delta_mean, time_delta_std, pkt_rate,
pub_to_conn_ratio) are computed by ids_api.py — NOT sent from here.

Usage:
    sudo python3 traffic_capture.py --iface s1 --api http://127.0.0.1:5000
    sudo python3 traffic_capture.py --iface s1-eth11 --api http://127.0.0.1:5000

    # Save pcap for offline replay
    sudo python3 traffic_capture.py --iface s1 --pcap /tmp/capture.pcap
"""

import argparse
import csv
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CAPTURE] %(levelname)s %(message)s"
)
LOG = logging.getLogger("traffic_capture")

# ─── tshark fields to capture ────────────────────────────────────────────────
# Includes ip.src / ip.dst for routing + all 12 static model features.
# The 4 aggregate features are computed server-side by ids_api.py.
TSHARK_FIELDS = [
    "ip.src",               # routing / block — NOT a model feature
    "ip.dst",               # for logging  — NOT a model feature
    # ── 12 static model features (must be present in the payload to /predict) ─
    "tcp.len",
    "tcp.time_delta",       # also used by ids_api to compute time_delta_mean/std
    "tcp.flags",
    "mqtt.msgtype",         # also used by ids_api to compute pub_to_conn_ratio
    "mqtt.msgid",
    "mqtt.qos",
    "mqtt.dupflag",
    "mqtt.len",
    "mqtt.kalive",
    "mqtt.conack.val",
    "mqtt.conflag.passwd",
    "mqtt.retain",
]

# Features forwarded to IDS API (all TSHARK_FIELDS minus routing fields)
MODEL_FIELDS = [f for f in TSHARK_FIELDS if f not in ("ip.src", "ip.dst")]

# ─── Statistics ───────────────────────────────────────────────────────────────
captured    = 0
sent_to_api = 0
errors      = 0
start_time  = time.time()

DEBUG_DUMP_FIRST_N = 0
_debug_dumped     = 0
src_ip_counter    = Counter()
msgtype_counter   = Counter()
tcpflag_counter   = Counter()
api_label_counter = Counter()
zero_vector_count = 0
first_api_logged  = 0


def build_tshark_cmd(iface: str, pcap_out: str = None) -> list:
    """Build tshark command that outputs fields as pipe-separated CSV."""
    field_args = []
    for f in TSHARK_FIELDS:
        field_args += ["-e", f]

    cmd = [
        "tshark",
        "-i", iface,
        "-f", "tcp port 1883",   # BPF capture filter
        "-Y", "mqtt",            # display filter — MQTT packets only
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=d",         # double-quote strings
        "-E", "occurrence=f",    # first occurrence of repeated fields
        "-l",                    # line-buffered
    ] + field_args

    if pcap_out:
        cmd += ["-w", pcap_out, "--capture-comment", "SDN-IoT-IDS v5 capture"]

    return cmd


def _to_num_dbg(s: str) -> float:
    """Mirror of ids_api.to_num() — for local debug logs only."""
    if not s or s in ("nan", "None"):
        return 0.0
    if s.startswith(("0x", "0X")):
        try:
            return float(int(s, 16))
        except ValueError:
            return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def parse_line(line: str) -> dict:
    """Parse one tshark CSV line → feature dict."""
    global _debug_dumped, zero_vector_count
    line = line.strip()
    if not line:
        return {}

    parts = line.split("|")
    if len(parts) < len(TSHARK_FIELDS):
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))

    row = {}
    for i, field in enumerate(TSHARK_FIELDS):
        row[field] = parts[i].strip().strip('"')

    # Drop pure-TCP frames that slipped past -Y mqtt
    _mt = (row.get("mqtt.msgtype") or "").strip()
    _ml = (row.get("mqtt.len")     or "").strip()
    if _mt in ("", "-") and _ml in ("", "-"):
        return {}

    # Debug accounting
    src_ip_counter[row.get("ip.src", "")] += 1
    msgtype_counter[row.get("mqtt.msgtype", "") or "-"] += 1
    tcpflag_counter[row.get("tcp.flags",   "") or "-"] += 1

    # Check for all-zero static vector
    vec = [_to_num_dbg(row.get(f, "")) for f in MODEL_FIELDS]
    if all(v == 0.0 for v in vec):
        zero_vector_count += 1

    if _debug_dumped < DEBUG_DUMP_FIRST_N:
        _debug_dumped += 1
        LOG.info("[DBG-VEC #%d] %-15s -> %-15s",
                 _debug_dumped, row.get("ip.src"), row.get("ip.dst"))
        LOG.info("[DBG-VEC #%d]   static(12) = %s",
                 _debug_dumped, {k: row.get(k) for k in MODEL_FIELDS})

    return row


def send_to_api(api_url: str, row: dict, q: queue.Queue):
    """Send one packet's features to IDS API (worker thread)."""
    global sent_to_api, errors

    src_ip   = row.get("ip.src", "")
    # Only the 12 static model fields go in "features".
    # ids_api.py will add the 4 aggregate features from its own window.
    features = {k: v for k, v in row.items() if k in MODEL_FIELDS}

    payload = {
        "src_ip":   src_ip,
        "features": features,
    }

    try:
        resp = requests.post(
            api_url + "/predict",
            json=payload,
            timeout=1.0
        )
        if resp.status_code == 200:
            result = resp.json()
            sent_to_api += 1
            label  = result.get("label",        "?")
            mlabel = result.get("model_label",  label)
            conf   = result.get("confidence",   0)
            is_atk = result.get("is_attack",    False)
            agg    = result.get("agg_features", {})

            api_label_counter[mlabel] += 1

            global first_api_logged
            if first_api_logged < DEBUG_DUMP_FIRST_N:
                first_api_logged += 1
                LOG.info("[DBG-API #%d] src=%-15s model=%-12s refined=%-12s "
                         "conf=%.3f is_atk=%s agg=%s",
                         first_api_logged, src_ip, mlabel, label, conf,
                         is_atk, agg)

            if is_atk and result.get("blocked"):
                LOG.warning("⚠ ATTACK BLOCKED [%-12s] conf=%.2f src=%-15s agg=%s",
                            label, conf, src_ip, agg)
            else:
                LOG.debug("  OK  [%-12s] conf=%.2f src=%-15s", label, conf, src_ip)
        else:
            errors += 1
            LOG.error("API error %d: %s", resp.status_code, resp.text[:100])

    except requests.exceptions.ConnectionError:
        errors += 1
        if errors == 1:
            LOG.error("IDS API unreachable at %s — is ids_api.py running?", api_url)
    except requests.exceptions.Timeout:
        errors += 1
    except Exception as e:
        errors += 1
        LOG.error("Unexpected error: %s", e)


def api_worker(api_url: str, q: queue.Queue):
    """Thread that drains the queue and calls the IDS API."""
    while True:
        row = q.get()
        if row is None:
            break
        send_to_api(api_url, row, q)
        q.task_done()


def stats_printer():
    """Background thread: print capture + API stats every 10 s."""
    while True:
        time.sleep(10)
        elapsed = time.time() - start_time
        rate    = captured / max(elapsed, 1)
        LOG.info("Stats: captured=%d sent=%d errors=%d rate=%.1f pkt/s",
                 captured, sent_to_api, errors, rate)
        if DEBUG_DUMP_FIRST_N > 0:
            top_src = src_ip_counter.most_common(8)
            LOG.info("[DBG-SRC] top sources    : %s",
                     ", ".join(f"{ip}={n}" for ip, n in top_src))
            LOG.info("[DBG-MQT] mqtt.msgtype   : %s",
                     dict(msgtype_counter.most_common(8)))
            LOG.info("[DBG-TCP] tcp.flags      : %s",
                     dict(tcpflag_counter.most_common(8)))
            zr = (100 * zero_vector_count / captured) if captured else 0
            LOG.info("[DBG-VEC] all-zero static : %d/%d (%.1f%%)",
                     zero_vector_count, captured, zr)
            LOG.info("[DBG-API] model_label dist: %s",
                     dict(api_label_counter.most_common()))


def write_csv_header(csv_path: str):
    """Write CSV header with all captured tshark fields."""
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TSHARK_FIELDS + ["timestamp"])
        writer.writeheader()


def capture_loop(iface: str, api_url: str, pcap_out: str = None,
                 csv_out: str = None, max_packets: int = 0):
    """
    Main capture loop.
    Launches tshark, reads lines, parses features, queues to IDS API worker.
    """
    global captured

    cmd = build_tshark_cmd(iface, pcap_out)
    LOG.info("Starting tshark: %s", " ".join(cmd))
    LOG.info("Interface      : %s", iface)
    LOG.info("IDS API        : %s", api_url)
    LOG.info("Static features: %d  |  Aggregate features: 4 (computed by API)",
             len(MODEL_FIELDS))

    q      = queue.Queue(maxsize=500)
    worker = threading.Thread(target=api_worker, args=(api_url, q), daemon=True)
    worker.start()

    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()

    csv_file   = None
    csv_writer = None
    if csv_out:
        write_csv_header(csv_out)
        csv_file   = open(csv_out, "a", newline="")
        csv_writer = csv.DictWriter(csv_file,
                                    fieldnames=TSHARK_FIELDS + ["timestamp"])
        LOG.info("Writing CSV to : %s", csv_out)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        LOG.info("tshark PID=%d started", proc.pid)

        for line in proc.stdout:
            row = parse_line(line)
            if not row:
                continue

            captured += 1
            row["timestamp"] = datetime.now().isoformat()

            if csv_writer:
                csv_writer.writerow(row)
                if captured % 100 == 0:
                    csv_file.flush()

            try:
                q.put_nowait(row)
            except queue.Full:
                LOG.debug("Queue full — dropping packet (rate too high)")

            if max_packets and captured >= max_packets:
                LOG.info("Reached max_packets=%d — stopping", max_packets)
                break

    except KeyboardInterrupt:
        LOG.info("Capture interrupted by user")
    finally:
        proc.terminate()
        q.put(None)
        worker.join(timeout=5)
        if csv_file:
            csv_file.close()

        elapsed = time.time() - start_time
        LOG.info("─" * 60)
        LOG.info("Capture complete")
        LOG.info("  Duration  : %.1f s",   elapsed)
        LOG.info("  Captured  : %d pkts",  captured)
        LOG.info("  Sent→API  : %d",       sent_to_api)
        LOG.info("  Errors    : %d",       errors)
        if elapsed > 0:
            LOG.info("  Avg rate  : %.1f pkt/s", captured / elapsed)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MQTT Traffic Capture for IDS v5 (16-feature model)"
    )
    parser.add_argument("--iface",  default="s1",
                        help="Network interface to capture on (default: s1)")
    parser.add_argument("--api",    default="http://127.0.0.1:5000",
                        help="IDS API base URL")
    parser.add_argument("--pcap",   default=None,
                        help="Optional: save raw pcap to this path")
    parser.add_argument("--csv",    default=None,
                        help="Optional: save captured features as CSV")
    parser.add_argument("--max",    type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    parser.add_argument("--debug-vector", type=int, default=0,
                        help="Print full debug for first N packets (default: 0)")
    args = parser.parse_args()
    globals()["DEBUG_DUMP_FIRST_N"] = args.debug_vector

    if os.geteuid() != 0:
        LOG.warning("Not running as root — tshark may fail to open interface")
        LOG.warning("Run with: sudo python3 traffic_capture.py ...")

    capture_loop(
        iface=args.iface,
        api_url=args.api,
        pcap_out=args.pcap,
        csv_out=args.csv,
        max_packets=args.max,
    )
