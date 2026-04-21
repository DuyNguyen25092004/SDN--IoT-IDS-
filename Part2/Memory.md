
# SDN + Mininet + Ryu + MQTT IDS — Full Project Documentation
## Người 1: Hạ tầng SDN & Mininet (Network Engineer)

> **Project:** Kết hợp IDS và Firewall cho Mạng IoT trên nền tảng SDN  
> **Team:** Trần Duy Nguyên · Bùi Trịnh Thế Viên · Lê Thanh Trà  
> **Role documented here:** Người 1 — Network Engineer  
> **Last updated:** April 2026

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Technology Stack & Rationale](#2-technology-stack--rationale)
3. [Environment Setup — Full History](#3-environment-setup--full-history)
4. [Project File Structure](#4-project-file-structure)
5. [File-by-File Documentation](#5-file-by-file-documentation)
6. [MQTTset Dataset & Feature Compatibility](#6-mqttset-dataset--feature-compatibility)
7. [Network Topology Detail](#7-network-topology-detail)
8. [IDS Pipeline — End-to-End Flow](#8-ids-pipeline--end-to-end-flow)
9. [Running the System](#9-running-the-system)
10. [Coordination with Người 2 & Người 3](#10-coordination-with-người-2--người-3)
11. [Troubleshooting](#11-troubleshooting)
12. [Key Design Decisions Log](#12-key-design-decisions-log)

---

## 1. System Architecture Overview

The system replicates and extends the paper's approach (Suricata IDS + MQTT parsing engine) into an SDN-controlled virtual environment, replacing physical ESP32 devices with Mininet software hosts and replacing Suricata with an ML-based IDS using a pre-trained XGBoost model (MQTTset dataset).

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (Linux Mint)                     │
│                                                                      │
│  ┌─────────────┐    OpenFlow 1.3    ┌──────────────────────────┐   │
│  │ Ryu         │◄───────────────────│  Mininet (OVS switch s1) │   │
│  │ Controller  │    port 6633       │                          │   │
│  │ :6633/:8080 │                    │  h1-h6  Publishers       │   │
│  └──────┬──────┘                    │  h7-h8  Subscribers      │   │
│         │ REST                      │  hbroker  Mosquitto      │   │
│         │ /ids/block                │  hattacker Attack host   │   │
│         ▼                           │                          │   │
│  ┌─────────────┐                    │  s1-eth11 = mirror port  │   │
│  │ IDS API     │◄── POST /predict   └──────────────────────────┘   │
│  │ Flask :5000 │                              │                      │
│  │ XGBoost     │              tshark captures │ mirrored traffic     │
│  │ MQTTset     │◄─────────────────────────────┘                     │
│  └─────────────┘   traffic_capture.py                               │
│                     extracts 33 features                             │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow Summary

```
IoT Publishers (h1-h6)
    │ paho-mqtt PUBLISH
    ▼
OVS Switch s1  ──mirror──► tshark on s1 interface
    │                           │
    │ OpenFlow forwarding       │ 33 MQTTset features extracted
    ▼                           │
Mosquitto Broker (hbroker)      ▼
    │                      IDS API (Flask + XGBoost)
    ▼                           │
IoT Subscribers (h7-h8)         │ if label ∈ {bruteforce,dos,flood,malformed,slowite}
                                ▼
                       POST /ids/block → Ryu Controller
                                │
                                ▼
                       OFPFlowMod DROP rule installed on s1
                       (malicious src IP permanently blocked)
```

---

## 2. Technology Stack & Rationale

### Why SDN + Ryu?

The paper (slide deck reference) identifies that traditional networks cannot automatically isolate attack sources. SDN separates the control plane (Ryu) from the data plane (OVS switch), allowing the IDS to push real-time blocking rules without human intervention.

### Why Mininet instead of physical ESP32?

- Physical topology: 6× ESP32 publishers + 2× ESP32 subscribers + PC/Server (Mosquitto + Suricata)
- Mininet simulation: identical logical topology, all hosts are software processes on the same machine
- Advantage: reproducible, no hardware needed, attack simulation safe to run

### Why XGBoost on MQTTset instead of Suricata?

The paper uses Suricata v4.1.8 with a custom C MQTT parser. Our extension adds ML-based anomaly detection using the MQTTset dataset. The XGBoost model achieves **90.8% accuracy** across 6 traffic classes. The Suricata approach is signature-based; XGBoost adds anomaly detection capability.

### Why Python 3.9 for Ryu?

| Python Version | Ryu 4.34 Compatibility |
|---|---|
| 3.12 (system) | ❌ Breaks — `distutils` removed |
| 3.11 | ❌ Partially broken |
| 3.10 | ⚠️ Unstable |
| **3.9** | **✅ Fully compatible** |
| 3.8 | ✅ Compatible but not available |

Python 3.9.25 was already installed at `/usr/lib/python3.9` and a working venv existed at `~/ryu-env-py39`.

---

## 3. Environment Setup — Full History

### 3.1 Host Machine Specifications

```
OS:        Linux Mint (Ubuntu 24 base)
Kernel:    6.14.0-34-generic
CPU:       (x86_64)
RAM:       15.6 GB total, ~8.8 GB available
Disk /:    23 GB (96% full at start → freed to ~80%)
Disk /home: 36 GB (97% full at start → freed to ~87% after cleanup)
```

### 3.2 Disk Space Crisis & Resolution

At the start of setup, both partitions were critically full (96%+). Items cleaned:

| Action | Space Freed |
|---|---|
| `rm ~/Downloads/reconstructed_signals.csv` | 1.8 GB |
| `rm -rf ~/.cache/vscode-cpptools` | ~700 MB |
| `rm -rf ~/.cache/google-chrome` | ~475 MB |
| `rm -rf ~/.cache/arduino` | ~265 MB |
| `pip3 cache purge` | ~533 packages |
| **Total freed** | **~3.5 GB** |

### 3.3 Pre-existing Software (Already Installed)

Everything below was found already installed — no reinstallation needed:

```
Open vSwitch:    3.3.4  (ovs-vsctl)
Mininet:         2.3.0  (/usr/bin/mn)
Python 3.9:      3.9.25 (/usr/lib/python3.9)
Ryu venv:        ~/ryu-env-py39  (ryu 4.34 inside)
Flask:           3.0.2  (system pip)
```

### 3.4 Newly Installed Packages

**System packages (apt):**
```bash
sudo apt install -y mosquitto mosquitto-clients tshark python3.9-venv python3.9-dev
# tshark prompt: select YES for non-root capture
```

Versions installed:
- Mosquitto: 2.0.18
- TShark: 4.2.2 (Wireshark)

**Python packages (inside ~/ryu-env-py39):**
```bash
source ~/ryu-env-py39/bin/activate
pip install paho-mqtt flask requests joblib xgboost scikit-learn scapy pandas numpy
```

### 3.5 Final Environment Verification

All green before coding began:
```
ryu-manager 4.34    ✅
paho-mqtt           ✅
flask               ✅
xgboost             ✅
scikit-learn        ✅
joblib              ✅
scapy               ✅
mosquitto 2.0.18    ✅
tshark 4.2.2        ✅
mn --test pingall   ✅ (completed in 0.274s)
```

### 3.6 Existing Ryu Venvs (Do Not Delete)

```
~/ryu-env/        — Python 3.12 venv, Ryu not installed
~/ryu-env-py39/   — Python 3.9 venv, Ryu 4.34 ✅ USE THIS ONE
~/ryu-env-py311/  — Python 3.11 venv, Ryu installed but unstable
~/ryu/            — Ryu source code (cloned repo, 62MB)
```

**Always activate before running any project code:**
```bash
source ~/ryu-env-py39/bin/activate
```

---

## 4. Project File Structure

```
SDN--IoT-IDS-/
├── all_outputs.zip                          ← Người 2's ML artifacts
│   ├── best_model_xgb.pkl                   ← XGBoost model (USE THIS)
│   ├── scaler.pkl                           ← StandardScaler
│   ├── label_encoder.pkl                    ← LabelEncoder for output classes
│   ├── feature_encoders.pkl                 ← LabelEncoders for categorical features
│   ├── model_metadata.json                  ← Classes, feature names, accuracy scores
│   ├── confusion_matrix_best.png
│   ├── model_comparison.png
│   ├── feature_importance_rf.png
│   └── per_class_performance.png
│
├── mqtt-ids_after_run.ipynb                 ← Người 2: executed notebook
├── mqttset_ids_notebook_before_run.ipynb    ← Người 2: clean notebook
├── README.md                                ← Top-level README
│
└── Part2/                                   ← Người 1's implementation
    ├── topology.py                          ← Mininet topology
    ├── ryu_controller.py                    ← Ryu SDN controller
    ├── ids_api.py                           ← ML IDS REST API
    ├── traffic_capture.py                   ← tshark capture + feature extraction
    ├── normal_traffic.py                    ← Legitimate MQTT traffic generator
    ├── run_all.sh                           ← Master launch script
    ├── README.md                            ← This file
    └── Structure/                           ← (additional structure docs)
```

---

## 5. File-by-File Documentation

### 5.1 `topology.py`

**Purpose:** Define the Mininet network topology that mirrors the physical diagram exactly.

**Topology class:** `IoTTopo` — registered as `--topo iot`

**IP Addressing Plan:**

| Host | IP | Role | Port on s1 |
|---|---|---|---|
| h1 | 10.0.0.1 | Publisher (sensor) | eth1 |
| h2 | 10.0.0.2 | Publisher (sensor) | eth2 |
| h3 | 10.0.0.3 | Publisher (sensor) | eth3 |
| h4 | 10.0.0.4 | Publisher (sensor) | eth4 |
| h5 | 10.0.0.5 | Publisher (sensor) | eth5 |
| h6 | 10.0.0.6 | Publisher (sensor) | eth6 |
| h7 | 10.0.0.7 | Subscriber | eth7 |
| h8 | 10.0.0.8 | Subscriber | eth8 |
| hbroker | 10.0.0.10 | Mosquitto MQTT Broker | eth9 |
| hattacker | 10.0.0.99 | Attacker (Người 3) | eth10 |
| *(mirror)* | *(none)* | tshark capture point | eth11 |

**Key design choices:**
- Single switch `s1` (OVS, OpenFlow 1.3) — matches the paper's flat IoT network
- `TCLink` for bandwidth control (publishers: 10Mbps, broker/attacker: 100Mbps)
- MACs assigned as `00:00:00:00:00:XX` for readability
- Mosquitto is started directly on `hbroker` inside the `run()` function
- Mirror port eth11 has no host attached — OVS mirrors all traffic there for tshark

**Run standalone:**
```bash
sudo python3 topology.py
# Opens Mininet CLI directly
```

**Run via mn command (recommended):**
```bash
sudo mn --custom topology.py --topo iot \
        --controller remote,ip=127.0.0.1,port=6633 \
        --switch ovsk,protocols=OpenFlow13 \
        --link tc --mac
```

---

### 5.2 `ryu_controller.py`

**Purpose:** SDN controller handling three responsibilities:
1. L2 learning switch (forward traffic between hosts)
2. Port mirroring setup (copy all traffic to eth11 for IDS)
3. REST flow enforcer (receive block commands from IDS API)

**Class:** `IoTIDSController(app_manager.RyuApp)`

**OpenFlow version:** 1.3 only (`OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]`)

**Flow priority levels:**

| Priority | Purpose |
|---|---|
| 200 | BLOCK rules (DROP, highest — evaluated first) |
| 100 | Normal L2 forwarding rules |
| 1 | Table-miss (send to controller) |

**Port mirroring approach:**

Uses `ovs-vsctl` to create an OVS mirror named `ids-mirror` that copies ALL traffic to port 11. This is done at the OVS level (not via OpenFlow flow rules) because:
- Works at line rate without consuming flow table entries
- Survives flow table modifications
- Compatible with OVS 3.3.4

```bash
# What the controller runs internally:
sudo ovs-vsctl -- --id=@m create mirror name=ids-mirror \
    select-all=true output-port=11 \
    -- add bridge s1 mirrors @m
```

**REST API (via Ryu WSGIApplication on port 8080):**

```
POST /ids/block    Body: {"ip": "10.0.0.99"}
                   → Installs OFPFlowMod DROP rule for ipv4_src=<ip>
                   → Returns: {"status": "blocked", "ip": "10.0.0.99"}

POST /ids/unblock  Body: {"ip": "10.0.0.99"}
                   → Removes DROP rule via OFPFlowMod DELETE
                   → Returns: {"status": "unblocked", "ip": "10.0.0.99"}

GET  /ids/rules    → Returns: {"blocked_ips": [...], "count": N}
```

**Block rule details:**
- Match: `eth_type=0x0800` (IPv4) + `ipv4_src=<malicious_ip>`
- Actions: `[]` (empty = DROP)
- Priority: 200 (overrides all forwarding rules)
- Idle/hard timeout: 0 (permanent until explicitly removed)
- Applied on ALL connected datapaths

**Run:**
```bash
source ~/ryu-env-py39/bin/activate
ryu-manager ryu_controller.py --wsapi-port 8080 --observe-links
```

---

### 5.3 `ids_api.py`

**Purpose:** Flask REST API wrapping the pre-trained XGBoost model. Receives packet features from `traffic_capture.py`, classifies them, and triggers Ryu block for malicious traffic.

**Model:** `best_model_xgb.pkl` — XGBoost, trained on MQTTset dataset
- Accuracy: 90.8%
- F1 Score: 90.6%
- 6 output classes: `bruteforce`, `dos`, `flood`, `legitimate`, `malformed`, `slowite`
- Input: 33 features (exact MQTTset columns)

**Preprocessing pipeline** (mirrors `mqttset_ids_notebook_before_run.ipynb`):
1. Fill missing values with 0
2. Convert hex strings (`0x002`) to int
3. Apply `feature_encoders.pkl` (LabelEncoders) for categorical fields
4. Apply `scaler.pkl` (StandardScaler) for normalization
5. Run `MODEL.predict_proba()` → argmax → decode with `label_encoder.pkl`

**Attack detection logic:**
```python
ATTACK_LABELS = {"bruteforce", "dos", "flood", "malformed", "slowite"}
if label in ATTACK_LABELS and src_ip:
    POST http://127.0.0.1:8080/ids/block {"ip": src_ip}
```

**Endpoints:**

```
GET  /health          → {"status": "ok", "model": "XGBoost (MQTTset)", "uptime_s": N}

POST /predict         Body: {"src_ip": "10.0.0.99", "features": {33 fields}}
                      → {"label": "flood", "confidence": 0.97, "is_attack": true, ...}

POST /predict/batch   Body: [{...}, {...}]
                      → [{...}, {...}]

GET  /stats           → {"total_packets": N, "by_label": {...}, "blocked_events": [...]}
```

**Run:**
```bash
source ~/ryu-env-py39/bin/activate
python ids_api.py \
    --model best_model_xgb.pkl \
    --scaler scaler.pkl \
    --encoder label_encoder.pkl \
    --feat-encoder feature_encoders.pkl \
    --port 5000
```

**Environment variable override for Ryu URL:**
```bash
export RYU_URL=http://127.0.0.1:8080/ids/block
```

---

### 5.4 `traffic_capture.py`

**Purpose:** Run tshark on the OVS mirror interface, extract the exact 33 MQTTset features per packet, and stream to the IDS API for classification.

**Why tshark and not Scapy?**
The MQTTset dataset was built using tshark/Wireshark field names (e.g. `mqtt.conack.flags`, `tcp.time_delta`). Using tshark directly guarantees field naming and extraction logic is identical to the training data — zero feature mismatch.

**The 33 model features extracted (in order):**
```
tcp.flags, tcp.time_delta, tcp.len,
mqtt.conack.flags, mqtt.conack.flags.reserved, mqtt.conack.flags.sp,
mqtt.conack.val, mqtt.conflag.cleansess, mqtt.conflag.passwd,
mqtt.conflag.qos, mqtt.conflag.reserved, mqtt.conflag.retain,
mqtt.conflag.uname, mqtt.conflag.willflag, mqtt.conflags,
mqtt.dupflag, mqtt.hdrflags, mqtt.kalive, mqtt.len, mqtt.msg,
mqtt.msgid, mqtt.msgtype, mqtt.proto_len, mqtt.protoname,
mqtt.qos, mqtt.retain, mqtt.sub.qos, mqtt.suback.qos,
mqtt.ver, mqtt.willmsg, mqtt.willmsg_len, mqtt.willtopic,
mqtt.willtopic_len
```

Plus `ip.src` and `ip.dst` (extracted but NOT sent to model — used for Ryu block targeting).

**tshark command built internally:**
```bash
tshark -i s1 \
  -f "tcp port 1883" \        # BPF capture filter
  -Y "mqtt" \                  # display filter: confirmed MQTT only
  -T fields \
  -E separator=| \
  -E quote=d \
  -E occurrence=f \
  -l \                         # line-buffered
  -e ip.src -e ip.dst \
  -e tcp.flags ... (all 33 fields)
```

**Architecture:**
- Main thread: tshark subprocess → reads stdout line by line → puts in queue
- Worker thread: drains queue → POSTs to `/predict` endpoint
- Stats thread: prints capture rate every 10 seconds
- Queue max size: 500 (drops packets if IDS API is slow — captures don't stall)

**Output files:**
- `--csv /tmp/capture.csv` → MQTTset-compatible CSV (for Người 2 evaluation)
- `--pcap /tmp/capture.pcap` → raw pcap (for Người 3 evaluation / Wireshark analysis)

**Run:**
```bash
# Must run as root (or tshark configured for non-root)
sudo python3 traffic_capture.py \
    --iface s1 \
    --api http://127.0.0.1:5000 \
    --csv /tmp/capture.csv \
    --pcap /tmp/capture.pcap
```

---

### 5.5 `normal_traffic.py`

**Purpose:** Generate legitimate MQTT traffic inside Mininet that the XGBoost model classifies as `legitimate`. Simulates the ESP32 PubSubClient behavior from the physical topology.

**MQTTset "legitimate" traffic characteristics:**
- Packet rate: 1–5 msg/s per device (steady, low)
- QoS: level 1 (at least once — most common in IoT)
- Payload: small JSON, 20–100 bytes
- Topic: hierarchical (`sensors/<device>/<metric>`)
- CONNECT: includes ClientID + username/password
- Keep-alive: 60 seconds (standard IoT default)
- No anomalous patterns: no CONNECT bursts, no topic entropy spikes

**Publisher config (maps to h1-h6):**

| Host | Topic | Simulated Sensors |
|---|---|---|
| h1 | sensors/h1 | temperature, humidity |
| h2 | sensors/h2 | pressure, altitude |
| h3 | sensors/h3 | light, UV |
| h4 | sensors/h4 | motion, vibration |
| h5 | sensors/h5 | CO2, VOC |
| h6 | sensors/h6 | battery, RSSI |

**Subscriber config (maps to h7-h8):**

| Host | Subscribed Topics |
|---|---|
| h7 | sensors/#, alerts/# |
| h8 | sensors/h1, sensors/h2, sensors/h3 |

**Usage inside Mininet CLI:**
```
# Start publisher on h1
mn> h1 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h1 --topic sensors/h1 &

# Start subscriber on h7
mn> h7 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h7 --topic sensors/# &

# Run all 6 publishers + 2 subscribers at once (from host machine for testing)
python3 normal_traffic.py all --broker 10.0.0.10 --duration 120
```

---

### 5.6 `run_all.sh`

**Purpose:** Orchestrate all components in the correct startup order with proper dependency checking.

**Startup sequence:**
1. Pre-flight checks (venv, scripts, model files, tools)
2. Clean previous state (`mn -c`, kill old processes)
3. Start Ryu controller (background, log to `/tmp/sdn-iot-ids-logs/ryu.log`)
4. Start IDS API (background, health check via curl)
5. Start traffic capture (background)
6. Launch Mininet CLI (foreground — interactive session)
7. On exit: cleanup all PIDs, `mn -c`, kill mosquitto

**Log directory:** `/tmp/sdn-iot-ids-logs/`
```
ryu.log                         ← Ryu controller events + OpenFlow messages
ids_api.log                     ← ML predictions, block events
capture.log                     ← tshark stats
capture_YYYYMMDD_HHMMSS.csv     ← raw features per packet
capture_YYYYMMDD_HHMMSS.pcap    ← raw packets
```

---

## 6. MQTTset Dataset & Feature Compatibility

### Dataset Source
- **Name:** MQTTset
- **URL:** https://www.kaggle.com/datasets/cnrieiit/mqttset
- **Used by:** Người 2 for ML model training

### Traffic Classes (6)

| Label | Type | Maps to Attack Scenario |
|---|---|---|
| `legitimate` | Benign | Normal ESP32 sensor publishing |
| `bruteforce` | Attack | Repeated CONNECT with wrong credentials |
| `dos` | Attack | 1000 pkt/s PUBLISH flood (Python script) |
| `flood` | Attack | 3000 pkt/s DDoS (MQTTSA tool) |
| `malformed` | Attack | Packets with invalid length/fields (LC, RFC, LEC vulnerabilities) |
| `slowite` | Attack | Slow drip exfiltration — mimics legitimate but sustained |

### Model Performance (from model_metadata.json)

| Model | Accuracy | F1 | Precision | Recall |
|---|---|---|---|---|
| **XGBoost** | **90.85%** | **90.62%** | **91.00%** | **90.85%** |
| Random Forest | 88.31% | 88.51% | 89.63% | 88.31% |

XGBoost selected as best model, saved as `best_model_xgb.pkl`.

### Why These 33 Features?

MQTTset is built by capturing real MQTT traffic with tshark and exporting packet-level fields. Every field corresponds to a raw Wireshark dissector field. This means:

- **No aggregation needed** — classification is per-packet, not per-flow
- **Exact tshark field names** — `traffic_capture.py` uses identical `-e` arguments
- **No feature re-engineering** — what tshark outputs goes directly to the model after scaling

This is the critical design decision that makes `traffic_capture.py` → `ids_api.py` work seamlessly.

---

## 7. Network Topology Detail

### Physical Diagram Reference (from slides)

```
IoT Publishers              PC / Server                IoT Subscribers
─────────────              ─────────────              ────────────────
ESP32 #1 (Sensor) ─┐       ┌─────────────┐            ┌─ ESP32 #7 (Sub)
ESP32 #2 (Sensor) ─┤       │  Mosquitto  │            │
ESP32 #3 (Sensor) ─┼──────►│  MQTT Broker│◄───────────┤
ESP32 #4 (Sensor) ─┤  1883 │     +       │  Port 1883 └─ ESP32 #8 (Sub)
ESP32 #5 (Sensor) ─┤       │  Suricata   │
ESP32 #6 (Sensor) ─┘       │  IDS+Parser │
                            └─────────────┘
                                  ▲
                            Malicious traffic
                                  │
                            Attacker (PC)
                            DoS: 1000 pkt/s
                            DDoS: 3000 pkt/s (MQTTSA)
                            hping3 (UDP test)
```

### Mininet Translation

```
Physical Device     → Mininet Host    IP
──────────────────────────────────────────
ESP32 #1 Publisher  → h1              10.0.0.1
ESP32 #2 Publisher  → h2              10.0.0.2
ESP32 #3 Publisher  → h3              10.0.0.3
ESP32 #4 Publisher  → h4              10.0.0.4
ESP32 #5 Publisher  → h5              10.0.0.5
ESP32 #6 Publisher  → h6              10.0.0.6
ESP32 #7 Subscriber → h7              10.0.0.7
ESP32 #8 Subscriber → h8              10.0.0.8
PC/Server (broker)  → hbroker         10.0.0.10
Attacker PC         → hattacker       10.0.0.99
Physical switch     → s1 (OVS)        (no IP)
```

### OVS Switch Port Mapping

```
s1-eth1   ← h1  (publisher)
s1-eth2   ← h2  (publisher)
s1-eth3   ← h3  (publisher)
s1-eth4   ← h4  (publisher)
s1-eth5   ← h5  (publisher)
s1-eth6   ← h6  (publisher)
s1-eth7   ← h7  (subscriber)
s1-eth8   ← h8  (subscriber)
s1-eth9   ← hbroker
s1-eth10  ← hattacker
s1-eth11  ← MIRROR PORT (no host, tshark reads here)
```

---

## 8. IDS Pipeline — End-to-End Flow

### Normal Traffic (Happy Path)

```
h1 normal_traffic.py publisher
  │ CONNECT (ClientID=esp32_h1, user=user_h1, pass=iot_pass_2024, keepalive=60)
  │ PUBLISH (topic=sensors/h1, qos=1, payload={"device":"h1","temperature":23.4,...})
  ▼
s1 (OVS switch)
  │ L2 forward to hbroker (eth9)
  │ MIRROR copy to eth11
  ▼
tshark on s1 interface
  │ Extracts 35 fields (33 model features + ip.src + ip.dst)
  │ Parse line → dict
  ▼
IDS API POST /predict
  │ Preprocess: hex→int, encode categoricals, StandardScaler
  │ XGBoost predict_proba → ["legitimate": 0.94, ...]
  │ label = "legitimate", is_attack = False
  ▼
  LOG: "OK [legitimate] conf=0.94 src=10.0.0.1"
  (no Ryu action taken)
```

### Attack Traffic (Block Path)

```
hattacker attack_dos.py
  │ 1000× PUBLISH per second → broker overwhelmed
  ▼
s1 (OVS switch)
  │ Forwards to hbroker (until block rule installed)
  │ MIRROR copy to eth11
  ▼
tshark → feature extraction
  │ High tcp.len, high mqtt.msgtype frequency, etc.
  ▼
IDS API POST /predict
  │ XGBoost → label = "dos", confidence = 0.97
  │ is_attack = True
  ▼
POST http://127.0.0.1:8080/ids/block {"ip": "10.0.0.99"}
  ▼
Ryu Controller
  │ OFPFlowMod (OFPFC_ADD)
  │   priority=200, match={eth_type=0x0800, ipv4_src=10.0.0.99}
  │   actions=[] (DROP)
  │   idle_timeout=0, hard_timeout=0 (permanent)
  ▼
s1 now DROPs all packets from 10.0.0.99 at line rate
  → hbroker CPU returns to normal
  → Broker protected
```

---

## 9. Running the System

### Quick Start (All-in-One)

```bash
# Terminal 1 — activate venv and run everything
source ~/ryu-env-py39/bin/activate
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-
unzip all_outputs.zip -d Part2/   # extract model files
cd Part2/
chmod +x run_all.sh
./run_all.sh
```

### Manual Start (Separate Terminals — Better for Debugging)

**Terminal 1 — Ryu Controller:**
```bash
source ~/ryu-env-py39/bin/activate
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
ryu-manager ryu_controller.py --wsapi-port 8080 --observe-links
```

**Terminal 2 — IDS API:**
```bash
source ~/ryu-env-py39/bin/activate
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
python ids_api.py \
    --model best_model_xgb.pkl \
    --scaler scaler.pkl \
    --encoder label_encoder.pkl \
    --feat-encoder feature_encoders.pkl
```

**Terminal 3 — Traffic Capture:**
```bash
source ~/ryu-env-py39/bin/activate
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
sudo python3 traffic_capture.py \
    --iface s1 \
    --api http://127.0.0.1:5000 \
    --csv /tmp/capture.csv \
    --pcap /tmp/capture.pcap
```

**Terminal 4 — Mininet:**
```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
sudo mn \
    --custom topology.py --topo iot \
    --controller remote,ip=127.0.0.1,port=6633 \
    --switch ovsk,protocols=OpenFlow13 \
    --link tc --mac
```

### Mininet CLI Commands

```bash
# Test connectivity
mn> pingall

# Start ALL publishers + subscribers at once (background)
mn> h1 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h1 --topic sensors/h1 &
mn> h2 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h2 --topic sensors/h2 &
mn> h3 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h3 --topic sensors/h3 &
mn> h4 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h4 --topic sensors/h4 &
mn> h5 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h5 --topic sensors/h5 &
mn> h6 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h6 --topic sensors/h6 &
mn> h7 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h7 --topic sensors/# &
mn> h8 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h8 --topic sensors/h1 sensors/h2 sensors/h3 &

# Check Ryu block rules
mn> sh curl -s http://127.0.0.1:8080/ids/rules | python3 -m json.tool

# Manually block an IP (test the enforcer)
mn> sh curl -s -X POST http://127.0.0.1:8080/ids/block \
    -H "Content-Type: application/json" -d '{"ip":"10.0.0.99"}'

# Manually unblock
mn> sh curl -s -X POST http://127.0.0.1:8080/ids/unblock \
    -H "Content-Type: application/json" -d '{"ip":"10.0.0.99"}'

# IDS classification stats
mn> sh curl -s http://127.0.0.1:5000/stats | python3 -m json.tool

# Check OVS flow table (verify block rules)
mn> sh sudo ovs-ofctl -O OpenFlow13 dump-flows s1

# Check OVS mirror is active
mn> sh sudo ovs-vsctl list mirror
```

### Cleanup

```bash
# From Mininet CLI
mn> exit

# Or force cleanup
sudo mn -c
sudo pkill -f ryu-manager
sudo pkill -f ids_api.py
sudo pkill -f traffic_capture.py
```

---

## 10. Coordination with Người 2 & Người 3

### Interface with Người 2 (Data Scientist)

Người 2 owns the ML model. Người 1 consumes it via files:

| File | Owner | Consumer |
|---|---|---|
| `best_model_xgb.pkl` | Người 2 | `ids_api.py` (Người 1) |
| `scaler.pkl` | Người 2 | `ids_api.py` (Người 1) |
| `label_encoder.pkl` | Người 2 | `ids_api.py` (Người 1) |
| `feature_encoders.pkl` | Người 2 | `ids_api.py` (Người 1) |
| `capture_*.csv` | Người 1 | Người 2 (evaluation) |
| `capture_*.pcap` | Người 1 | Người 2 (evaluation) |

**Critical contract:** The 33 feature names in `ids_api.py → FEATURE_NAMES` must exactly match the column names in `model_metadata.json → feature_names`. Do not rename or reorder.

### Interface with Người 3 (Security Tester)

Người 3 runs attack scripts from `hattacker` (10.0.0.99) inside Mininet. The attack types must match MQTTset classes:

| Attack Script | MQTTset Class | Expected Block |
|---|---|---|
| DoS: 1000 pkt/s PUBLISH flood | `dos` | Yes — src IP blocked |
| DDoS: 3000 pkt/s (MQTTSA) | `flood` | Yes — src IP blocked |
| Brute force CONNECT | `bruteforce` | Yes — src IP blocked |
| Malformed packets | `malformed` | Yes — src IP blocked |
| Slow drip exfiltration | `slowite` | Yes — src IP blocked |

**Attack script placement:**
```
mn> hattacker python3 /path/to/attack_dos.py --target 10.0.0.10 --rate 1000 &
```

**Evaluation data:** After each attack scenario, Người 3 collects:
- `/tmp/sdn-iot-ids-logs/capture_*.csv` → run through sklearn metrics
- OVS flow dump → verify block rules were installed
- Ryu log → measure detection latency (time from first attack packet to flow rule push)

---

## 11. Troubleshooting

### Ryu fails to start

```bash
# Check if port 6633 is already in use
sudo lsof -i :6633
# Kill old ryu
sudo pkill -f ryu-manager
# Check Python version inside venv
source ~/ryu-env-py39/bin/activate && python --version
# Must be Python 3.9.x
```

### "eventlet" or "hub" import error in Ryu

```bash
source ~/ryu-env-py39/bin/activate
pip install eventlet==0.30.2
```

### tshark: "permission denied" on interface

```bash
# Option 1: Run with sudo
sudo python3 traffic_capture.py --iface s1

# Option 2: Add user to wireshark group (permanent)
sudo usermod -aG wireshark $USER
# Log out and back in
```

### "No such device" error for interface s1

The OVS bridge `s1` only exists while Mininet is running. Start Mininet first, then run `traffic_capture.py`. The script will wait/retry.

### IDS API: "Model not loaded" response

The `.pkl` files must be in the same directory as `ids_api.py` OR specified with `--model` flag. Check:
```bash
ls -la best_model_xgb.pkl scaler.pkl label_encoder.pkl feature_encoders.pkl
```

### Ryu REST block endpoint unreachable

```bash
# Check Ryu is running and port 8080 is open
curl http://127.0.0.1:8080/ids/rules
# If connection refused, check ryu.log
tail -50 /tmp/sdn-iot-ids-logs/ryu.log
```

### Mosquitto not starting in Mininet

```bash
# Check if mosquitto is running on hbroker
mn> hbroker ps aux | grep mosquitto
# Check mosquitto log
mn> hbroker cat /tmp/mosquitto.log
# Start manually
mn> hbroker mosquitto -d -p 1883 -v > /tmp/mosquitto.log 2>&1
```

### Mininet hosts can't ping each other

```bash
# Verify Ryu is connected to switch
# In ryu.log you should see: "Switch connected: dpid=0000..."
# If not, check controller IP/port
mn> sh ovs-vsctl show
# Should show: is_connected: true
```

---

## 12. Key Design Decisions Log

This section documents every significant decision made during design, with the reasoning, so future developers understand why things are the way they are.

### Decision 1: Python 3.9 venv instead of upgrading Ryu

**Why:** Ryu 4.34 is essentially unmaintained and does not support Python 3.10+. The system already had Python 3.9.25 installed and `~/ryu-env-py39` with Ryu already working. Creating a new venv would waste disk space and risk introducing incompatibilities.

**Alternative considered:** Docker container. Rejected because network namespaces interact poorly with Mininet's veth pairs inside Docker.

### Decision 2: OVS-level port mirroring instead of OpenFlow group tables

**Why:** OVS `ovs-vsctl mirror` operates at the OVS datapath level before OpenFlow processing. This means:
- Mirror traffic is captured even for packets that hit cached flow rules (no controller involvement)
- Does not consume flow table entries
- Works at line rate even during DDoS (3000 pkt/s)

**Alternative considered:** OpenFlow group table with INDIRECT type. Rejected because it adds an output action to every forwarding rule, complicating the flow table.

### Decision 3: tshark instead of Scapy for packet capture

**Why:** MQTTset features are tshark/Wireshark dissector field names. Scapy uses different field names and parsing logic, which would require a translation layer that could introduce subtle mismatches. tshark gives identical field values to what the training data was built from.

**Alternative considered:** pyshark (Python tshark wrapper). Rejected because it has significant performance overhead for live capture; subprocess + stdout parsing is faster.

### Decision 4: Per-packet classification instead of per-flow

**Why:** MQTTset is a per-packet dataset — each row is one packet, not a flow aggregate. The model was trained on per-packet features. Using flow aggregates would require different features (flow duration, packet count, etc.) and the model would need retraining.

**Implication:** The IDS makes a blocking decision on every packet. A single malicious packet (if classified with high confidence) triggers a block. This is intentional — it matches the paper's goal of real-time response.

### Decision 5: Permanent block rules (timeout=0)

**Why:** Once an IP is classified as attacking (e.g. a botnet node), allowing it back automatically is a security risk. Manual unblock via `POST /ids/unblock` is required.

**Alternative considered:** 60-second idle timeout. Rejected for production but could be added for demo purposes to show the unblock flow.

### Decision 6: Single switch topology

**Why:** The paper's experimental topology uses a flat network (all devices on same segment via a PC server). A multi-switch topology would add complexity without corresponding benefit for the demo/evaluation. Can be extended later by adding a second switch and testing inter-switch flow rule propagation.

### Decision 7: Queue-based async API calls in traffic_capture.py

**Why:** At 3000 pkt/s (DDoS scenario), synchronous HTTP POST to the IDS API would create a backlog that stalls tshark. The queue (max 500) decouples capture from classification — if the API is slow, packets are dropped from the queue (not from the network). This preserves capture accuracy.

---

*Documentation written by Claude (Anthropic) based on full session discussion — April 2026*
*For questions: refer to the GitHub repository https://github.com/DuyNguyen25092004/SDN--IoT-IDS-*
