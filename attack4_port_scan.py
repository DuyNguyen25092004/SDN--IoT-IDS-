#!/usr/bin/env python3
"""
Attack 4 — Port Scan qua mạng SDN
Từ thiết bị IoT bị compromise, scan các host khác trong mạng.
Mô phỏng hành vi worm/botnet reconnaissance trong môi trường Mininet.

Chạy:
    python3 attack4_port_scan.py --subnet 10.0.0 --start 1 --end 10
"""

import socket
import time
import argparse
import threading
import logging
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# ── Ports phổ biến trên IoT devices ───────────────────────────────────────────
IOT_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    1883: "MQTT",
    8883: "MQTT/TLS",
    5683: "CoAP",
    8080: "HTTP-alt",
    554:  "RTSP (camera)",
    502:  "Modbus",
}

scan_results = {}
results_lock = threading.Lock()


def tcp_connect_scan(host: str, port: int, timeout: float = 0.5) -> bool:
    """TCP connect scan — không cần root, hoạt động trong Mininet"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_host(host: str, ports: list, timeout: float):
    open_ports = {}
    for port in ports:
        if tcp_connect_scan(host, port, timeout):
            service = IOT_PORTS.get(port, "unknown")
            open_ports[port] = service
            log.info(f"  [OPEN] {host}:{port} ({service})")

    with results_lock:
        scan_results[host] = {
            "host":       host,
            "is_alive":   len(open_ports) > 0,
            "open_ports": open_ports,
            "scan_time":  datetime.now().isoformat(),
        }

    status = f"{len(open_ports)} ports open: {list(open_ports.keys())}" if open_ports else "no open ports"
    log.info(f"  [{host}] {status}")


def mqtt_recon(broker_host: str, broker_port: int = 1883):
    """Subscribe $SYS/# để lấy thông tin broker (recon không cần xác thực)"""
    log.info(f"\n  [Phase 2] MQTT RECON — {broker_host}:{broker_port}")
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("  paho-mqtt chưa cài, bỏ qua MQTT recon")
        return {}

    recon_data = {}

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            log.info("  Kết nối broker không cần xác thực — broker không bảo mật!")
            client.subscribe("$SYS/#")
        else:
            log.warning(f"  Bị từ chối (rc={rc})")

    def on_message(client, userdata, msg):
        recon_data[msg.topic] = msg.payload.decode(errors="ignore")
        log.info(f"  $SYS {msg.topic} = {msg.payload.decode(errors='ignore')[:60]}")

    client = mqtt.Client(client_id="recon-001")
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(broker_host, broker_port, keepalive=10)
        client.loop_start()
        time.sleep(4)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        log.warning(f"  Lỗi: {e}")

    return recon_data


def main():
    parser = argparse.ArgumentParser(description="IoT Port Scanner (SDN network)")
    parser.add_argument("--subnet",      default="10.0.0",  help="Subnet (vd: 10.0.0)")
    parser.add_argument("--start",       type=int, default=1)
    parser.add_argument("--end",         type=int, default=10)
    parser.add_argument("--timeout",     type=float, default=0.5)
    parser.add_argument("--threads",     type=int, default=20)
    parser.add_argument("--mqtt-broker", default="", help="IP broker MQTT để recon")
    args = parser.parse_args()

    host_range = range(args.start, args.end + 1)
    ports      = list(IOT_PORTS.keys())
    start_time = time.time()

    log.info("=" * 60)
    log.info("  ATTACK 4 — PORT SCAN qua MẠNG SDN")
    log.info(f"  Target  : {args.subnet}.{args.start} → {args.subnet}.{args.end}")
    log.info(f"  Ports   : {ports}")
    log.info(f"  Threads : {args.threads}  |  Timeout: {args.timeout}s")
    log.info("=" * 60)

    # Phase 1: TCP horizontal scan
    log.info(f"\n  [Phase 1] TCP HORIZONTAL SCAN — {len(host_range)} hosts")
    threads = []
    for i in host_range:
        host = f"{args.subnet}.{i}"
        t = threading.Thread(target=scan_host, args=(host, ports, args.timeout), daemon=True)
        threads.append(t)
        t.start()
        while sum(1 for th in threads if th.is_alive()) >= args.threads:
            time.sleep(0.05)
    for t in threads:
        t.join()

    # Phase 2: MQTT recon
    mqtt_data = {}
    if args.mqtt_broker:
        mqtt_data = mqtt_recon(args.mqtt_broker)

    elapsed   = time.time() - start_time
    alive     = [h for h, r in scan_results.items() if r["is_alive"]]
    all_open  = {}
    for r in scan_results.values():
        for p, s in r["open_ports"].items():
            all_open.setdefault(p, []).append(r["host"])

    log.info("\n" + "=" * 60)
    log.info(f"  Hosts scanned  : {len(scan_results)}")
    log.info(f"  Hosts alive    : {len(alive)} — {alive}")
    log.info(f"  Open ports map : {dict(all_open)}")
    log.info(f"  Thời gian      : {elapsed:.2f}s")
    log.info("=" * 60)

    output = {
        "attack": "port_scan", "subnet": args.subnet,
        "duration_s": elapsed, "hosts": scan_results,
        "mqtt_recon": mqtt_data, "timestamp": datetime.now().isoformat(),
    }
    with open("attack4_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info("  Kết quả → attack4_scan_results.json")

    scan_rate = (len(host_range) * len(ports)) / elapsed if elapsed > 0 else 0
    log.info("\n  [DETECTION INDICATORS]")
    log.info(f"  Connection rate  : {scan_rate:.1f}/s  (normal < 1/s)")
    log.info(f"  Unique dst IPs   : {len(host_range)}  (bất thường nếu > 3)")
    log.info(f"  Unique dst ports : {len(ports)}  (bất thường nếu > 2)")


if __name__ == "__main__":
    main()
