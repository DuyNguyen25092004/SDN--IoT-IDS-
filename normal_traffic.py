#!/usr/bin/env python3
"""
Normal Traffic Generator — Baseline cho so sánh với attack traffic
Sinh traffic MQTT bình thường mô phỏng nhiều loại thiết bị IoT.
Dùng để tạo dữ liệu train/test cho ML model.

Chạy:
    python3 normal_traffic.py --host 10.0.0.1 --duration 60 --devices 5
"""

import paho.mqtt.client as mqtt
import time
import argparse
import json
import random
import threading
import logging
import math
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(threadName)s] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# ── Cấu hình thiết bị IoT thực tế ─────────────────────────────────────────────
IOT_DEVICES = [
    {
        "name":       "thermostat",
        "topic":      "home/thermostat/data",
        "interval":   10,    # giây giữa các lần publish
        "qos":        1,
        "payload_fn": lambda i: {
            "temperature": round(20 + math.sin(i * 0.1) * 3 + random.uniform(-0.5, 0.5), 2),
            "setpoint":    22.0,
            "mode":        "heat",
            "battery":     round(95 - i * 0.01, 1),
        },
    },
    {
        "name":       "door_sensor",
        "topic":      "home/door/status",
        "interval":   30,
        "qos":        1,
        "payload_fn": lambda i: {
            "state":    random.choices(["closed", "open"], weights=[9, 1])[0],
            "battery":  round(80 - i * 0.005, 1),
            "rssi":     random.randint(-80, -40),
        },
    },
    {
        "name":       "motion_sensor",
        "topic":      "home/motion/living_room",
        "interval":   15,
        "qos":        0,
        "payload_fn": lambda i: {
            "detected": random.choices([False, True], weights=[8, 2])[0],
            "lux":      round(random.uniform(50, 500), 1),
        },
    },
    {
        "name":       "weather_station",
        "topic":      "outdoor/weather",
        "interval":   20,
        "qos":        0,
        "payload_fn": lambda i: {
            "temp":     round(15 + math.sin(i * 0.05) * 8 + random.uniform(-1, 1), 2),
            "humidity": round(65 + random.uniform(-10, 10), 1),
            "pressure": round(1013 + random.uniform(-5, 5), 1),
            "wind":     round(random.uniform(0, 30), 1),
        },
    },
    {
        "name":       "smart_plug",
        "topic":      "home/plug/kitchen",
        "interval":   5,
        "qos":        0,
        "payload_fn": lambda i: {
            "power_w":   round(random.uniform(0, 2000), 1),
            "voltage_v": round(220 + random.uniform(-5, 5), 1),
            "state":     "on",
        },
    },
]

stats_lock  = threading.Lock()
total_published = 0
total_errors    = 0


def device_worker(host: str, port: int, device: dict, duration: int):
    global total_published, total_errors

    client_id = f"iot-{device['name']}-{random.randint(1000, 9999)}"
    client    = mqtt.Client(client_id=client_id)

    connected = [False]
    def on_connect(c, u, f, rc):
        connected[0] = (rc == 0)
    client.on_connect = on_connect

    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        time.sleep(0.5)
        if not connected[0]:
            log.error(f"[{device['name']}] Không kết nối được")
            return
    except Exception as e:
        log.error(f"[{device['name']}] Lỗi kết nối: {e}")
        return

    log.info(f"[{device['name']}] Kết nối OK → topic={device['topic']} interval={device['interval']}s")

    end_time = time.time() + duration
    seq      = 0

    while time.time() < end_time:
        payload_data = device["payload_fn"](seq)
        payload_data.update({
            "device_id": client_id,
            "seq":       seq,
            "ts":        datetime.now().isoformat(),
        })
        payload_str = json.dumps(payload_data)

        result = client.publish(device["topic"], payload=payload_str, qos=device["qos"])

        with stats_lock:
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                total_published += 1
            else:
                total_errors += 1

        log.debug(f"[{device['name']}] publish seq={seq}  {payload_str[:60]}...")
        seq += 1

        # Jitter nhẹ để bắt chước thiết bị thực
        jitter = random.uniform(-device["interval"] * 0.1, device["interval"] * 0.1)
        time.sleep(max(0.5, device["interval"] + jitter))

    client.loop_stop()
    client.disconnect()
    log.info(f"[{device['name']}] Kết thúc sau {seq} messages")


def main():
    parser = argparse.ArgumentParser(description="Normal MQTT Traffic Generator")
    parser.add_argument("--host",     default="127.0.0.1",  help="IP broker MQTT")
    parser.add_argument("--port",     type=int, default=1883)
    parser.add_argument("--duration", type=int, default=60,  help="Thời gian chạy (giây)")
    parser.add_argument("--devices",  type=int, default=5,   help="Số thiết bị (1–5)")
    args = parser.parse_args()

    devices = IOT_DEVICES[:min(args.devices, len(IOT_DEVICES))]
    start_time = time.time()

    log.info("=" * 60)
    log.info("  NORMAL TRAFFIC GENERATOR")
    log.info(f"  Broker   : {args.host}:{args.port}")
    log.info(f"  Devices  : {[d['name'] for d in devices]}")
    log.info(f"  Duration : {args.duration}s")
    log.info("=" * 60)

    threads = []
    for device in devices:
        t = threading.Thread(
            target=device_worker,
            args=(args.host, args.port, device, args.duration),
            name=device["name"],
            daemon=True,
        )
        threads.append(t)
        t.start()
        time.sleep(random.uniform(0.1, 0.5))  # Stagger startup

    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    rate    = total_published / elapsed if elapsed > 0 else 0

    log.info("=" * 60)
    log.info(f"  KẾT QUẢ NORMAL TRAFFIC")
    log.info(f"  Tổng published : {total_published}")
    log.info(f"  Lỗi            : {total_errors}")
    log.info(f"  Rate           : {rate:.2f} msg/s")
    log.info(f"  Duration       : {elapsed:.1f}s")
    log.info("=" * 60)
    log.info("\n  [NORMAL BASELINE INDICATORS]")
    log.info(f"  Msg rate        : {rate:.2f}/s  (nhỏ, đều đặn)")
    log.info(f"  Unique topics   : {len(devices)}  (ổn định)")
    log.info(f"  Payload entropy : trung bình (JSON có cấu trúc)")
    log.info(f"  Pattern         : periodic, không đột biến")


if __name__ == "__main__":
    main()
