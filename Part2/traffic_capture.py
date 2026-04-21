#!/usr/bin/env python3
"""
traffic_capture.py — Live Traffic Capture & Feature Extraction
===============================================================
Runs tshark on the OVS mirror interface, extracts the exact 33 features
used by best_model_xgb.pkl (MQTTset dataset), and streams each packet
to the IDS API for classification.

The 33 fields match exactly what MQTTset was built from:
  tcp.flags, tcp.time_delta, tcp.len,
  mqtt.conack.*, mqtt.conflag.*, mqtt.hdrflags, mqtt.kalive,
  mqtt.len, mqtt.msg, mqtt.msgid, mqtt.msgtype, mqtt.proto_len,
  mqtt.protoname, mqtt.qos, mqtt.retain, mqtt.sub.qos,
  mqtt.suback.qos, mqtt.ver, mqtt.willmsg*, mqtt.willtopic*

Usage:
    # Mirror interface is the OVS internal port — tshark binds to it
    sudo python3 traffic_capture.py --iface s1 --api http://127.0.0.1:5000

    # Or on a specific veth mirror port
    sudo python3 traffic_capture.py --iface s1-eth11 --api http://127.0.0.1:5000

    # Save pcap for offline replay (Người 2 / evaluation use)
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
from datetime import datetime

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CAPTURE] %(levelname)s %(message)s"
)
LOG = logging.getLogger("traffic_capture")

# ─── Exact 33 MQTTset feature columns ────────────────────────────────────────
# tshark field names → CSV column names used in MQTTset
TSHARK_FIELDS = [
    "ip.src",              # extra — used for Ryu block (not a model feature)
    "ip.dst",              # extra — for logging
    "tcp.flags",
    "tcp.time_delta",
    "tcp.len",
    "mqtt.conack.flags",
    "mqtt.conack.flags.reserved",
    "mqtt.conack.flags.sp",
    "mqtt.conack.val",
    "mqtt.conflag.cleansess",
    "mqtt.conflag.passwd",
    "mqtt.conflag.qos",
    "mqtt.conflag.reserved",
    "mqtt.conflag.retain",
    "mqtt.conflag.uname",
    "mqtt.conflag.willflag",
    "mqtt.conflags",
    "mqtt.dupflag",
    "mqtt.hdrflags",
    "mqtt.kalive",
    "mqtt.len",
    "mqtt.msg",
    "mqtt.msgid",
    "mqtt.msgtype",
    "mqtt.proto_len",
    "mqtt.protoname",
    "mqtt.qos",
    "mqtt.retain",
    "mqtt.sub.qos",
    "mqtt.suback.qos",
    "mqtt.ver",
    "mqtt.willmsg",
    "mqtt.willmsg_len",
    "mqtt.willtopic",
    "mqtt.willtopic_len",
]

# Model features (exclude ip.src and ip.dst which are routing only)
MODEL_FEATURES = [f for f in TSHARK_FIELDS if not f.startswith("ip.")]

# ─── Statistics ───────────────────────────────────────────────────────────────
captured   = 0
sent_to_api = 0
errors     = 0
start_time = time.time()


def build_tshark_cmd(iface: str, pcap_out: str = None) -> list:
    """
    Build tshark command that outputs fields as CSV (separator |).
    Filter: only MQTT traffic on port 1883.
    """
    field_args = []
    for f in TSHARK_FIELDS:
        field_args += ["-e", f]

    cmd = [
        "tshark",
        "-i", iface,
        "-f", "tcp port 1883",      # BPF capture filter — MQTT only
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=d",            # double-quote strings
        "-E", "occurrence=f",       # first occurrence of repeated fields
        "-l",                       # line-buffered output
    ] + field_args

    if pcap_out:
        # Also write a pcap file for Người 2's evaluation
        cmd += ["-w", pcap_out, "--capture-comment", "SDN-IoT-IDS capture"]

    return cmd


def parse_line(line: str) -> dict:
    """Parse one tshark CSV line into a feature dict."""
    line = line.strip()
    if not line:
        return {}

    # Remove surrounding quotes added by tshark -E quote=d
    parts = line.split("|")
    if len(parts) < len(TSHARK_FIELDS):
        # Pad with empty strings for missing fields
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))

    row = {}
    for i, field in enumerate(TSHARK_FIELDS):
        val = parts[i].strip().strip('"')
        row[field] = val

    return row


def send_to_api(api_url: str, row: dict, q: queue.Queue):
    """Send one packet's features to IDS API (runs in worker thread)."""
    global sent_to_api, errors

    src_ip   = row.get("ip.src", "")
    features = {k: v for k, v in row.items() if k in MODEL_FEATURES}

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
            label = result.get("label", "?")
            conf  = result.get("confidence", 0)
            is_atk = result.get("is_attack", False)

            if is_atk and result.get("blocked"):
                LOG.warning("⚠ ATTACK BLOCKED [%-12s] conf=%.2f src=%-15s",
                            label, conf, src_ip)
            else:
                LOG.debug("  OK     [%-12s] conf=%.2f src=%-15s",
                          label, conf, src_ip)
        else:
            errors += 1
            LOG.error("API error %d: %s", resp.status_code, resp.text[:100])
    except requests.exceptions.ConnectionError:
        errors += 1
        if errors == 1:
            LOG.error("IDS API unreachable at %s — is ids_api.py running?",
                      api_url)
    except requests.exceptions.Timeout:
        errors += 1
    except Exception as e:
        errors += 1
        LOG.error("Unexpected error: %s", e)


def api_worker(api_url: str, q: queue.Queue):
    """Thread that drains the queue and calls the IDS API."""
    while True:
        row = q.get()
        if row is None:   # poison pill — stop signal
            break
        send_to_api(api_url, row, q)
        q.task_done()


def stats_printer():
    """Background thread that prints capture statistics every 10 seconds."""
    while True:
        time.sleep(10)
        elapsed = time.time() - start_time
        rate    = captured / max(elapsed, 1)
        LOG.info("Stats: captured=%d sent=%d errors=%d rate=%.1f pkt/s",
                 captured, sent_to_api, errors, rate)


def write_csv_header(csv_path: str):
    """Write the MQTTset-compatible CSV header."""
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TSHARK_FIELDS + ["timestamp"])
        writer.writeheader()
    return csv_path


def capture_loop(iface: str, api_url: str, pcap_out: str = None,
                 csv_out: str = None, max_packets: int = 0):
    """
    Main capture loop.
    Runs tshark as a subprocess, reads lines, parses features,
    sends to IDS API via a worker thread queue.
    """
    global captured

    cmd = build_tshark_cmd(iface, pcap_out)
    LOG.info("Starting tshark: %s", " ".join(cmd))
    LOG.info("Listening on interface: %s", iface)
    LOG.info("IDS API endpoint: %s", api_url)

    # API worker thread + queue (non-blocking capture)
    q = queue.Queue(maxsize=500)
    worker = threading.Thread(target=api_worker, args=(api_url, q), daemon=True)
    worker.start()

    # Stats thread
    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()

    # CSV writer setup
    csv_file = None
    csv_writer = None
    if csv_out:
        write_csv_header(csv_out)
        csv_file = open(csv_out, "a", newline="")
        csv_writer = csv.DictWriter(csv_file,
                                    fieldnames=TSHARK_FIELDS + ["timestamp"])
        LOG.info("Writing CSV to: %s", csv_out)

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

            # Write to CSV if requested
            if csv_writer:
                csv_writer.writerow(row)
                if captured % 100 == 0:
                    csv_file.flush()

            # Send to IDS API (non-blocking — drop if queue full)
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
        q.put(None)   # stop worker
        worker.join(timeout=5)

        if csv_file:
            csv_file.close()

        elapsed = time.time() - start_time
        LOG.info("─" * 60)
        LOG.info("Capture complete")
        LOG.info("  Duration  : %.1f seconds", elapsed)
        LOG.info("  Captured  : %d packets", captured)
        LOG.info("  Sent→API  : %d", sent_to_api)
        LOG.info("  Errors    : %d", errors)
        if elapsed > 0:
            LOG.info("  Avg rate  : %.1f pkt/s", captured / elapsed)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Traffic Capture for IDS")
    parser.add_argument("--iface",  default="s1",
                        help="Network interface to capture on (default: s1)")
    parser.add_argument("--api",    default="http://127.0.0.1:5000",
                        help="IDS API base URL")
    parser.add_argument("--pcap",   default=None,
                        help="Optional: save raw pcap to this path")
    parser.add_argument("--csv",    default=None,
                        help="Optional: save features as CSV to this path")
    parser.add_argument("--max",    type=int, default=0,
                        help="Stop after N packets (0 = unlimited)")
    args = parser.parse_args()

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
