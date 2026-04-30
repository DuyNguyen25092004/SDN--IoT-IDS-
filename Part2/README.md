# SDN IoT IDS — Run Guide

Full setup and execution guide for the 4-terminal demo.

---

## Prerequisites

Install system-wide dependencies (needed by Mininet hosts):

```bash
sudo pip3 install paho-mqtt --break-system-packages
```

Install venv dependencies (for IDS API and capture):

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate
pip install flask joblib numpy requests xgboost scikit-learn
```

---

## Terminal Layout

| Terminal | Role |
|----------|------|
| **T1** | Ryu SDN Controller |
| **T2** | IDS API (XGBoost classifier) |
| **T3** | Traffic Capture (tshark → API) |
| **T4** | Mininet topology + attack scripts |

---

## T1 — Ryu Controller

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source ~/ryu-env-py39/bin/activate
ryu-manager ryu_controller.py --observe-links --wsapi-port 8080
```

Wait until you see:
```
Switch connected: dpid=0000000000000001
```

---

## T2 — IDS API

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate
python3 ids_api.py \
    --model ../Part1/best_model_xgb_v2.pkl \
    --scaler ../Part1/scaler_v2.pkl \
    --encoder ../Part1/label_encoder_v2.pkl
```

> **Note:** Use the `venv` virtualenv here, NOT `ryu-env-py39`. The pkl files are `best_model_xgb_v2.pkl`, `scaler_v2.pkl`, and `label_encoder_v2.pkl` (v2 versions).

Wait until you see:
```
Running on http://127.0.0.1:5000
```

---

## T3 — Traffic Capture

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate

# Bring up the OVS internal port
sudo ip link set s1 up

# Set up OVS mirror (copy all switch traffic to s1 for tshark)
sudo ovs-vsctl -- set Bridge s1 mirrors=@m \
  -- --id=@s1 get Port s1 \
  -- --id=@m create Mirror name=ids-mirror \
     select-all=true \
     output-port=@s1

# Start capture
sudo python3 traffic_capture.py --iface s1 --api http://127.0.0.1:5000
```

> **Note:** If the mirror already exists from a previous run, `ovs-vsctl` will error — that's fine, just run the capture directly.

---

## T4 — Mininet Topology

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
sudo python3 topology.py
```

### Inside Mininet CLI

**Start the MQTT broker on hbroker:**
```
mininet> hbroker bash -c "echo -e 'listener 1883 0.0.0.0\nallow_anonymous true' > /tmp/mosquitto.conf && mosquitto -d -c /tmp/mosquitto.conf"
```

**Verify broker is listening on all interfaces:**
```
mininet> hbroker netstat -tlnp | grep 1883
# Should show: 0.0.0.0:1883
```

**Test connectivity:**
```
mininet> hattacker mosquitto_pub -h 10.0.0.10 -t test -m hello
```

---

## Running the Attacks

### Attack 1 — MQTT Flood (DoS)

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack1_mqtt_flood.py --host 10.0.0.10 --port 1883 --threads 10 --count 5000
```

Expected IDS output: `flood` / `malformed` detected at 93–98% confidence, blocked.

---

### Attack 2 — C2 Malware

Clear any existing block first (see "Unblocking" section below), then:

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack2_c2_malware.py --mode bot --host 10.0.0.10 &
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack2_c2_malware.py --mode server --host 10.0.0.10
```

Expected IDS output: `malformed` / `dos` at 91–100% confidence, blocked.

---

### Attack 3 — Brute Force

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack3_brute_force.py --host 10.0.0.10 --delay 0.1
```

Expected IDS output: `malformed` at 90–100% confidence, blocked.

---

### Attack 4 — Port Scan

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack4_port_scan.py --subnet 10.0.0 --start 1 --end 10 --mqtt-broker 10.0.0.10
```

Expected IDS output: `malformed` at 100% confidence, blocked.

---

### Attack 5 — Slow Drip Exfiltration

This attack mimics normal traffic and must be run while `10.0.0.99` is whitelisted in the IDS (otherwise it gets blocked before connecting).

**Step 1 — Whitelist hattacker in IDS:**
```bash
curl -s -X POST http://127.0.0.1:5000/whitelist/add \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.99"}'
```

**Step 2 — Unblock via Ryu:**
```bash
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.99"}'
```

**Step 3 — Run the attack:**
```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack5_slow_drip.py --host 10.0.0.10 --rate 0.5
```

**Step 4 — Restore normal IDS operation after attack finishes:**
```bash
curl -s -X POST http://127.0.0.1:5000/whitelist/remove \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.99"}'
```

Expected IDS output: `slowite` at ~47% confidence (low by design — hardest attack to detect).

---

## Unblocking Between Attacks

After each attack, `10.0.0.99` (hattacker) gets blocked. Unblock before running the next attack:

```bash
# Remove block via Ryu (clears both OVS flow rule AND Ryu's internal state)
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.99"}'
```

Verify no block rule remains:
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 10.0.0.99
```

---

## Broker Restart (if broker dies)

If attacks fail with `Connection refused` or `TimeoutError`:

```
mininet> hbroker bash -c "pkill mosquitto; sleep 1; echo -e 'listener 1883 0.0.0.0\nallow_anonymous true' > /tmp/mosquitto.conf && mosquitto -d -c /tmp/mosquitto.conf"
```

---

## IDS Stats & Monitoring

```bash
# View detection statistics
curl -s http://127.0.0.1:5000/stats | python3 -m json.tool

# View health + loaded model info
curl -s http://127.0.0.1:5000/health | python3 -m json.tool

# View current whitelist
curl -s http://127.0.0.1:5000/whitelist | python3 -m json.tool

# View active Ryu block rules
curl -s http://127.0.0.1:8080/ids/rules | python3 -m json.tool
```

---

## Attack Results Summary

| # | Attack | IDS Label | Confidence | Blocked |
|---|--------|-----------|------------|---------|
| 1 | MQTT Flood | `flood` / `malformed` | 93–98% | ✅ Yes |
| 2 | C2 Malware | `malformed` / `dos` | 91–100% | ✅ Yes |
| 3 | Brute Force | `malformed` | 90–100% | ✅ Yes |
| 4 | Port Scan | `malformed` | 100% | ✅ Yes |
| 5 | Slow Drip | `slowite` | ~47% | ⚠ Low confidence (by design) |

---

## Host IP Reference

| Host | IP |
|------|----|
| h1–h8 | 10.0.0.1 – 10.0.0.8 |
| hbroker | 10.0.0.10 |
| hattacker | 10.0.0.99 |