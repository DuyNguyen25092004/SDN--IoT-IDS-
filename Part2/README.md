# SDN IoT IDS — Người 1 (Network Engineer) Implementation

## Project Structure

```
sdn-iot-ids/
├── topology.py          Mininet topology (6 publishers, 2 subscribers, broker, attacker)
├── ryu_controller.py    Ryu app: L2 switch + OVS port mirror + REST flow enforcer
├── ids_api.py           Flask ML API wrapping best_model_xgb.pkl
├── traffic_capture.py   tshark → 33 MQTTset features → IDS API
├── normal_traffic.py    Legitimate paho-mqtt publisher/subscriber traffic
└── run_all.sh           Master launch script
```

## Network Topology

```
 h1 (10.0.0.1)  ─┐                        ┌─ h7 (10.0.0.7)  Subscriber
 h2 (10.0.0.2)  ─┤                        ├─ h8 (10.0.0.8)  Subscriber
 h3 (10.0.0.3)  ─┤                        │
 h4 (10.0.0.4)  ─┼──── s1 (OVS) ──────────┤
 h5 (10.0.0.5)  ─┤   OpenFlow 1.3         │
 h6 (10.0.0.6)  ─┘   port 11 = mirror     ├─ hbroker   (10.0.0.10) Mosquitto
                                           └─ hattacker (10.0.0.99) Attack scripts

 Ryu Controller ← port 6633 (OpenFlow)
 Ryu REST API   ← port 8080 /ids/block /ids/unblock /ids/rules

 IDS Pipeline:
 tshark(s1) → 33 features → POST /predict → XGBoost → label
                                                      ↓ if attack
                                           POST /ids/block → Ryu DROP rule
```

## Setup

### 1. Get model files
Download from https://github.com/DuyNguyen25092004/SDN--IoT-IDS-
Extract `all_outputs.zip` and place these files in the project directory:
- `best_model_xgb.pkl`
- `scaler.pkl`
- `label_encoder.pkl`
- `feature_encoders.pkl`

### 2. Activate environment
```bash
source ~/ryu-env-py39/bin/activate
```

### 3. Run everything
```bash
chmod +x run_all.sh
./run_all.sh
```

Or manually, in separate terminals:

**Terminal 1 — Ryu Controller:**
```bash
source ~/ryu-env-py39/bin/activate
ryu-manager ryu_controller.py --wsapi-port 8080
```

**Terminal 2 — IDS API:**
```bash
source ~/ryu-env-py39/bin/activate
python ids_api.py --model best_model_xgb.pkl --scaler scaler.pkl \
                  --encoder label_encoder.pkl --feat-encoder feature_encoders.pkl
```

**Terminal 3 — Traffic Capture:**
```bash
sudo python3 traffic_capture.py --iface s1 --api http://127.0.0.1:5000 \
             --csv /tmp/capture.csv --pcap /tmp/capture.pcap
```

**Terminal 4 — Mininet:**
```bash
sudo mn --custom topology.py --topo iot \
        --controller remote,ip=127.0.0.1,port=6633 \
        --switch ovsk,protocols=OpenFlow13 --link tc --mac
```

## Using the Mininet CLI

```
# Start normal publisher traffic on h1
mn> h1 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h1 --topic sensors/h1 &

# Start subscriber on h7
mn> h7 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h7 --topic sensors/# &

# Connectivity test
mn> pingall

# Check Ryu blocked IPs
mn> sh curl -s http://127.0.0.1:8080/ids/rules

# Manually block an IP (test)
mn> sh curl -s -X POST http://127.0.0.1:8080/ids/block -H "Content-Type: application/json" -d '{"ip":"10.0.0.99"}'

# IDS stats
mn> sh curl -s http://127.0.0.1:5000/stats
```

## For Người 3 (Attack Simulation)

Run attack scripts from `hattacker` inside Mininet:
```
mn> hattacker python3 attack_dos.py --target 10.0.0.10 --rate 1000 &
mn> hattacker python3 attack_brute.py --target 10.0.0.10 &
```

The IDS pipeline will detect and Ryu will auto-block `10.0.0.99`.

## MQTTset Feature Mapping

The 33 features captured by tshark match exactly what `best_model_xgb.pkl` expects:

| Feature | Source |
|---------|--------|
| tcp.flags, tcp.time_delta, tcp.len | TCP layer |
| mqtt.conack.* | CONNACK packets |
| mqtt.conflag.* | CONNECT flags |
| mqtt.hdrflags, mqtt.kalive, mqtt.len | MQTT fixed header |
| mqtt.msg, mqtt.msgid, mqtt.msgtype | Message fields |
| mqtt.qos, mqtt.retain, mqtt.dupflag | QoS/delivery flags |
| mqtt.sub.qos, mqtt.suback.qos | Subscribe fields |
| mqtt.will* | Will message fields |

## Detection Classes

The model classifies traffic into 6 classes (from MQTTset):
- `legitimate` → allow
- `bruteforce` → block src IP
- `dos` → block src IP  
- `flood` → block src IP
- `malformed` → block src IP
- `slowite` → block src IP

## Logs

All logs written to `/tmp/sdn-iot-ids-logs/`:
- `ryu.log` — Ryu controller events
- `ids_api.log` — ML predictions
- `capture.log` — tshark capture stats
- `capture_YYYYMMDD_HHMMSS.csv` — raw features (for Người 2 evaluation)
- `capture_YYYYMMDD_HHMMSS.pcap` — raw packets (for Người 2 evaluation)
