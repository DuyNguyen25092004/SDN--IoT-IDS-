# Người 3 — Attack Simulation & Evaluation
## Hướng dẫn sử dụng toàn bộ scripts

---

## 📁 Danh sách files

| File | Mô tả |
|------|-------|
| `attack1_mqtt_flood.py`   | Tấn công DoS — gửi flood PUBLISH messages |
| `attack2_c2_malware.py`   | C2 Malware — nhận lệnh ẩn, exfil dữ liệu |
| `attack3_bruteforce.py`   | Brute Force CONNECT username/password |
| `attack4_port_scan.py`    | Port Scan toàn bộ mạng SDN |
| `attack5_slow_drip.py`    | Slow Drip Exfiltration — ẩn trong normal traffic |
| `normal_traffic.py`       | Sinh traffic bình thường làm baseline |
| `evaluation.py`           | Tính P/R/F1/ROC, đo latency |
| `mininet_topology.py`     | Topology Mininet đầy đủ |

---

## ⚙️ Cài đặt dependencies

```bash
pip install paho-mqtt
# Mininet đã có sẵn trên Ubuntu VM
sudo apt install mosquitto -y
```

---

## 🚀 Quy trình chạy đầy đủ
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
### Run sau khi chayj Mininet
```bash
sudo ip link set s1 up
sudo python3 ~/sdn/Final_project/Part2/traffic_capture.py \
  --iface s1-eth1 \
  --api http://127.0.0.1:5000 \
  --csv capture.csv
```

**Terminal 4 — Mininet:**
```bash
cd part3
sudo python3 ~/part3/mininet_topology.py

### Check broker in mininet
```bash
mininet> hbroker netstat -tlnp | grep 1883
```
#### Output:
```bash
tcp        0      0 0.0.0.0:1883            0.0.0.0:*               LISTEN      12415/mosquitto     
```

### Neu khong co output nhu vay thi run:
```bash
mininet> hbroker mosquitto -p 1883 --listener 1883 0.0.0.0 --allow-anonymous true > /tmp/mosq2.log 2>&1 &
```

### Chạy tiếp theo trong Mininet CLI
Bước 1 — Normal traffic (chạy ngầm, redirect log)
```bash
h1 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h1 --topic sensors/h1 &
h2 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h2 --topic sensors/h2 &
h3 python3 normal_traffic.py publisher --broker 10.0.0.10 --id h3 --topic sensors/h3 &
h7 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h7 --topic sensors/# &
h8 python3 normal_traffic.py subscriber --broker 10.0.0.10 --id h8 --topic sensors/# &
```
### Chạy từng attack từ mininet

Sau moi lan chay attacker thi se bi block ip 10.0.0.99:
Can chay lenh unblock:
```
sh curl -s -X POST http://127.0.0.1:8080/ids/unblock \-H "Content-Type: application/json" \-d '{"ip":"10.0.0.99"}'
```

Kiem tra da unblock hay chua:
```
sh curl -s http://127.0.0.1:8080/ids/rules
```
#### Attack 1: MQTT Flood
```
hattacker python3 attack1_mqtt_flood.py --host 10.0.0.10
```

#### Attack 2: C2 Malware (cần 2 terminal)
```bash
hattacker python3 attack2_c2_malware.py --mode bot --host 10.0.0.10 &
hattacker python3 attack2_c2_malware.py --mode server --host 10.0.0.10
```

#### Attack 3: Brute Force
```
hattacker python3 attack3_brute_force.py --host 10.0.0.10
```

#### Attack 4: Port Scan
```
hattacker python3 attack4_port_scan.py --subnet 10.0.0 --start 1 --end 10
```

#### Attack 5: Slow Drip Exfiltration
```
hattacker python3 attack5_slow_drip.py --host 10.0.0.10
```

---

## 📊 Chạy Evaluation

### Sau khi có kết quả từ IDS (Người 2 cung cấp CSV):
```bash
python3 evaluation.py --input ids_results.csv --output report/
```

**Format CSV đầu vào** (`ids_results.csv`):
```
timestamp,true_label,predicted_label,confidence_score
1700000001,normal,normal,0.92
1700000002,flood,flood,0.98
1700000003,normal,flood,0.61
```

**Nhãn hợp lệ**: `normal`, `flood`, `c2_malware`, `bruteforce`, `port_scan`, `slow_drip`

**Output**:
- `report/evaluation_report.json` — toàn bộ metrics
- `report/roc_curve.html` — ROC curve tương tác

---

## 🔬 Đặc trưng phát hiện từng attack

| Attack | Feature chính để phát hiện |
|--------|---------------------------|
| Flood | Packet rate đột biến, nhiều PUBLISH cùng topic |
| C2 Malware | Topic bất thường (`$SYS/malware/*`), payload entropy cao, beacon periodic |
| Brute Force | CONNECT rate cao, nhiều CONNACK = refused (rc=4/5) |
| Port Scan | Nhiều TCP SYN đến port khác nhau, packet-in tại SDN controller tăng |
| Slow Drip | Payload `data` field có Shannon entropy cao bất thường so với sensor value |

---

## 📋 Kịch bản so sánh Normal vs Attack

| Trạng thái | Packet rate | Topic pattern | Payload entropy |
|------------|-------------|---------------|-----------------|
| Bình thường | Ổn định ~0.2 msg/s | Nhất quán | Thấp (JSON đơn giản) |
| Flood | Đột biến 2500+ msg/s | Lặp lại 1 topic | Trung bình |
| C2 Malware | Bình thường + beacon 10s | `$SYS/malware/*` | Cao (base64 encrypted) |
| Brute Force | CONNECT rate cao | N/A | N/A |
| Port Scan | Nhiều TCP SYN | N/A | N/A |
| Slow Drip | Bình thường ~1 msg/s | Trông normal | Cao ở field `data` |

---

## 📌 Lưu ý khi tích hợp với nhóm

- **Người 1 (Network)**: Cần bật port mirroring trên OVS để capture traffic từ h4
- **Người 2 (ML)**: Scripts export traffic characteristics, đặt biệt `attack5` log entropy để làm training feature
- Evaluation script đọc CSV từ ML model của Người 2, không cần sửa code

# SDN--IoT-IDS-