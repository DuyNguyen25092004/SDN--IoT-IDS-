#!/usr/bin/env python3
"""
normal_traffic.py — Legitimate MQTT Traffic Generator
======================================================
Simulates the ESP32 publisher/subscriber behaviour from your topology diagram.
Generates traffic that the MQTTset model classifies as "legitimate":
  - Regular CONNECT with credentials
  - Periodic PUBLISH of sensor data (temperature, humidity, etc.)
  - SUBSCRIBE to relevant topics
  - Proper DISCONNECT and reconnect cycles
  - Keep-alive PINGREQ at correct intervals

Usage inside Mininet (run from each host):
    # Publisher (run on h1..h6)
    python3 normal_traffic.py publisher \
            --broker 10.0.0.10 --id h1 --topic sensors/h1

    # Subscriber (run on h7, h8)
    python3 normal_traffic.py subscriber \
            --broker 10.0.0.10 --id h7 --topic sensors/#

    # Run all publishers at once (for testing outside Mininet)
    python3 normal_traffic.py all --broker 10.0.0.10

MQTTset "legitimate" traffic characteristics:
  - Packet rate: steady, low (1–5 msg/s per device)
  - QoS: 0 or 1 (not 2, which is rare in IoT)
  - Payload: small JSON, 20–100 bytes
  - Topic: consistent, hierarchical (sensors/<device>/<metric>)
  - CONNECT: includes ClientID, optional username/password
  - Keep-alive: 60 seconds (standard IoT default)
"""

import argparse
import json
import logging
import random
import sys
import time
import threading
from datetime import datetime

import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s"
)

# ─── Configuration ────────────────────────────────────────────────────────────
BROKER_IP    = "10.0.0.10"
BROKER_PORT  = 1883
KEEP_ALIVE   = 60          # seconds — standard IoT value
QOS_LEVEL    = 1           # QoS 1 — at least once (most common in IoT)
PUBLISH_RATE = 2.0         # seconds between publishes per device

# Publisher host → topic mapping (mirrors your diagram: h1-h6 are publishers)
PUBLISHER_CONFIG = {
    "h1": {"topic": "sensors/h1", "metrics": ["temperature", "humidity"]},
    "h2": {"topic": "sensors/h2", "metrics": ["pressure", "altitude"]},
    "h3": {"topic": "sensors/h3", "metrics": ["light", "uv"]},
    "h4": {"topic": "sensors/h4", "metrics": ["motion", "vibration"]},
    "h5": {"topic": "sensors/h5", "metrics": ["co2", "voc"]},
    "h6": {"topic": "sensors/h6", "metrics": ["battery", "rssi"]},
}

# Subscriber config (h7, h8)
SUBSCRIBER_CONFIG = {
    "h7": {"topics": ["sensors/#", "alerts/#"]},
    "h8": {"topics": ["sensors/h1", "sensors/h2", "sensors/h3"]},
}


# ─── Payload generators ───────────────────────────────────────────────────────

def make_sensor_payload(host_id: str, metrics: list) -> str:
    """Generate realistic sensor JSON payload (20–100 bytes)."""
    data = {
        "device":    host_id,
        "ts":        int(time.time()),
    }
    for metric in metrics:
        if metric == "temperature":
            data[metric] = round(random.uniform(18.0, 35.0), 2)
        elif metric == "humidity":
            data[metric] = round(random.uniform(30.0, 90.0), 2)
        elif metric == "pressure":
            data[metric] = round(random.uniform(990.0, 1030.0), 2)
        elif metric == "altitude":
            data[metric] = round(random.uniform(0.0, 500.0), 1)
        elif metric == "light":
            data[metric] = random.randint(0, 65535)
        elif metric == "uv":
            data[metric] = round(random.uniform(0.0, 11.0), 1)
        elif metric == "motion":
            data[metric] = random.choice([0, 1])
        elif metric == "vibration":
            data[metric] = round(random.uniform(0.0, 1.0), 3)
        elif metric == "co2":
            data[metric] = random.randint(400, 2000)
        elif metric == "voc":
            data[metric] = random.randint(0, 500)
        elif metric == "battery":
            data[metric] = round(random.uniform(2.5, 4.2), 2)
        elif metric == "rssi":
            data[metric] = random.randint(-90, -30)
        else:
            data[metric] = random.random()

    return json.dumps(data)


# ─── Publisher ────────────────────────────────────────────────────────────────

class MQTTPublisher:
    def __init__(self, host_id: str, broker_ip: str, broker_port: int,
                 topic: str, metrics: list, rate: float = PUBLISH_RATE):
        self.host_id     = host_id
        self.broker_ip   = broker_ip
        self.broker_port = broker_port
        self.topic       = topic
        self.metrics     = metrics
        self.rate        = rate
        self.log         = logging.getLogger(f"pub.{host_id}")
        self.running     = False

        self.client = mqtt.Client(
            client_id=f"esp32_{host_id}",
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )
        self.client.username_pw_set(
            username="admin",
            password="admin"
        )
        self.client.on_connect    = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_publish    = self._on_publish

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.log.info("Connected to broker %s:%d",
                          self.broker_ip, self.broker_port)
        else:
            self.log.error("Connection failed rc=%d", rc)

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            self.log.warning("Unexpected disconnect rc=%d — will retry", rc)

    def _on_publish(self, client, userdata, mid):
        self.log.debug("Message published mid=%d", mid)

    def run(self, duration: float = 0):
        """
        Publish sensor data at self.rate interval.
        duration=0 → run forever.
        """
        self.running = True
        try:
            self.client.connect(self.broker_ip, self.broker_port,
                                keepalive=KEEP_ALIVE)
            self.client.loop_start()

            end_time = time.time() + duration if duration > 0 else float("inf")

            while self.running and time.time() < end_time:
                payload = make_sensor_payload(self.host_id, self.metrics)
                result  = self.client.publish(
                    self.topic,
                    payload=payload,
                    qos=QOS_LEVEL,
                    retain=False
                )
                self.log.info("PUBLISH topic=%s payload=%s",
                              self.topic, payload[:60])
                time.sleep(self.rate + random.uniform(-0.1, 0.3))

        except KeyboardInterrupt:
            self.log.info("Publisher stopped by user")
        except Exception as e:
            self.log.error("Publisher error: %s", e)
        finally:
            self.client.loop_stop()
            self.client.disconnect()
            self.log.info("Publisher disconnected")

    def stop(self):
        self.running = False


# ─── Subscriber ───────────────────────────────────────────────────────────────

class MQTTSubscriber:
    def __init__(self, host_id: str, broker_ip: str, broker_port: int,
                 topics: list):
        self.host_id     = host_id
        self.broker_ip   = broker_ip
        self.broker_port = broker_port
        self.topics      = topics
        self.log         = logging.getLogger(f"sub.{host_id}")
        self.running     = False
        self.msg_count   = 0

        self.client = mqtt.Client(
            client_id=f"subscriber_{host_id}",
            clean_session=True,
            protocol=mqtt.MQTTv311,
        )
        self.client.username_pw_set(
            username="admin",
            password="admin"
        )
        self.client.on_connect    = self._on_connect
        self.client.on_message    = self._on_message
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            for topic in self.topics:
                client.subscribe(topic, qos=QOS_LEVEL)
                self.log.info("Subscribed to %s", topic)
        else:
            self.log.error("Connection failed rc=%d", rc)

    def _on_message(self, client, userdata, msg):
        self.msg_count += 1
        self.log.info("RECV [%s] %s", msg.topic, msg.payload.decode()[:80])

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            self.log.warning("Unexpected disconnect rc=%d", rc)

    def run(self, duration: float = 0):
        self.running = True
        try:
            self.client.connect(self.broker_ip, self.broker_port,
                                keepalive=KEEP_ALIVE)
            if duration > 0:
                self.client.loop_start()
                time.sleep(duration)
                self.client.loop_stop()
            else:
                self.client.loop_forever()
        except KeyboardInterrupt:
            self.log.info("Subscriber stopped")
        finally:
            self.client.disconnect()
            self.log.info("Total messages received: %d", self.msg_count)

    def stop(self):
        self.running = False
        self.client.disconnect()


# ─── Run-all mode (for testing / demo) ───────────────────────────────────────

def run_all(broker_ip: str, duration: float = 120):
    """Launch all 6 publishers and 2 subscribers in threads."""
    threads = []

    for hid, cfg in PUBLISHER_CONFIG.items():
        pub = MQTTPublisher(
            host_id=hid,
            broker_ip=broker_ip,
            broker_port=BROKER_PORT,
            topic=cfg["topic"],
            metrics=cfg["metrics"],
            rate=PUBLISH_RATE + random.uniform(0, 1),
        )
        t = threading.Thread(target=pub.run, args=(duration,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.2)   # stagger connections slightly

    for hid, cfg in SUBSCRIBER_CONFIG.items():
        sub = MQTTSubscriber(
            host_id=hid,
            broker_ip=broker_ip,
            broker_port=BROKER_PORT,
            topics=cfg["topics"],
        )
        t = threading.Thread(target=sub.run, args=(duration,), daemon=True)
        t.start()
        threads.append(t)

    print(f"[*] Running {len(threads)} clients for {duration}s on {broker_ip}")
    print("[*] Ctrl+C to stop early")

    try:
        for t in threads:
            t.join(timeout=duration + 5)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Legitimate MQTT Traffic Generator")
    sub_cmds = parser.add_subparsers(dest="mode")

    # Publisher subcommand
    pub_parser = sub_cmds.add_parser("publisher")
    pub_parser.add_argument("--broker",   default=BROKER_IP)
    pub_parser.add_argument("--port",     type=int, default=BROKER_PORT)
    pub_parser.add_argument("--id",       required=True, help="Host ID e.g. h1")
    pub_parser.add_argument("--topic",    required=True)
    pub_parser.add_argument("--metrics",  nargs="+", default=["temperature"])
    pub_parser.add_argument("--rate",     type=float, default=PUBLISH_RATE)
    pub_parser.add_argument("--duration", type=float, default=0)

    # Subscriber subcommand
    sub_parser = sub_cmds.add_parser("subscriber")
    sub_parser.add_argument("--broker",   default=BROKER_IP)
    sub_parser.add_argument("--port",     type=int, default=BROKER_PORT)
    sub_parser.add_argument("--id",       required=True)
    sub_parser.add_argument("--topic",    nargs="+", default=["sensors/#"])
    sub_parser.add_argument("--duration", type=float, default=0)

    # All-in-one subcommand
    all_parser = sub_cmds.add_parser("all")
    all_parser.add_argument("--broker",   default=BROKER_IP)
    all_parser.add_argument("--duration", type=float, default=120)

    args = parser.parse_args()

    if args.mode == "publisher":
        cfg = PUBLISHER_CONFIG.get(args.id, {})
        metrics = cfg.get("metrics", args.metrics)
        pub = MQTTPublisher(
            host_id=args.id,
            broker_ip=args.broker,
            broker_port=args.port,
            topic=args.topic,
            metrics=metrics,
            rate=args.rate,
        )
        pub.run(duration=args.duration)

    elif args.mode == "subscriber":
        sub = MQTTSubscriber(
            host_id=args.id,
            broker_ip=args.broker,
            broker_port=args.port,
            topics=args.topic,
        )
        sub.run(duration=args.duration)

    elif args.mode == "all":
        run_all(broker_ip=args.broker, duration=args.duration)

    else:
        parser.print_help()
        sys.exit(1)
