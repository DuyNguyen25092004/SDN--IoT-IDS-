# SDN IoT IDS — Run Guide (v5 — 16 features)

4-terminal demo. Chạy theo đúng thứ tự bên dưới.

---

## 0. Prerequisites

- Linux + sudo (cache password một lần bằng `sudo -v` **mỗi terminal**)
- Python 3.9 venv cho **Ryu** tại `~/ryu-env-py39/`
- Python 3.12 venv cho **IDS** tại `Part2/venv/`
- `mininet`, `openvswitch`, `mosquitto`, `tshark`

### Artifacts model v5 (đặt trong `Part2/`)

| File               | Mô tả                        |
|--------------------|------------------------------|
| `best_model.pkl`   | XGBoost v5, 16 features      |
| `scaler.pkl`       | StandardScaler khớp v5       |
| `label_encoder.pkl`| LabelEncoder 6 classes       |
| `model.metadata`   | metadata JSON                |

> ⚠ **Không dùng** `best_model_xgb_v2.pkl` / `scaler_v2.pkl` cũ — scaler
> của v2 (8 features) sẽ crash khi nhận vector 16 chiều.

---

## 1. Clean slate (chạy 1 lần trước mỗi demo)

```bash
sudo -v
sudo sh -c 'mn -c >/dev/null 2>&1; \
            killall -9 mosquitto ryu-manager 2>/dev/null; \
            pkill -9 -f "ids_api.py|traffic_capture.py|topology.py" 2>/dev/null; \
            ovs-vsctl --if-exists del-br s1; echo CLEAN'
mkdir -p /tmp/part2_demo
```

---

## 2. Terminal layout

| #  | Terminal     | Chạy gì                              |
|----|--------------|--------------------------------------|
| T1 | Ryu          | SDN controller (port 8080)           |
| T2 | IDS API      | Flask ML API — 16 features (port 5000)|
| T3 | Capture      | tshark → IDS API (khởi động sau T4) |
| T4 | Mininet      | topology + mosquitto broker          |

---

## 3. T1 — Ryu controller

```bash
source ~/ryu-env-py39/bin/activate
cd Part2
sudo -v      # cache sudo cho greenthread (_install_mirror_rule dùng sudo ovs-vsctl)
ryu-manager ryu_controller.py --observe-links --wsapi-port 8080 \
    2>&1 | tee /tmp/part2_demo/T1_ryu.log
```

✅ Chờ thấy dòng: `Switch connected: dpid=0000000000000001`

> Cảnh báo `OVS mirror setup failed (port 11 may not exist yet)` là **bình thường**
> — mirror thực sẽ được tạo từ T3.

---

## 4. T2 — IDS API (model v5, 16 features)

```bash
cd Part2

# Các biến môi trường quan trọng:
#   IDS_BLOCK_VOTES : số packet attack cần trước khi block (default 20, demo dùng 10)
#   IDS_BLOCK_CONF  : ngưỡng confidence để block        (default 0.90, demo dùng 0.30)
#   IDS_VOTE_WINDOW : kích thước cửa sổ vote             (default 30)
#   IDS_AGG_WINDOW  : giây tính aggregate features       (default 10)

IDS_BLOCK_VOTES=10 IDS_BLOCK_CONF=0.8 IDS_VOTE_WINDOW=20 IDS_AGG_WINDOW=10 RYU_URL=http://127.0.0.1:8080/ids/block ./venv/bin/python3 ids_api.py     --model best_model.pkl     --scaler scaler.pkl     --encoder label_encoder.pkl     2>&1 | tee /tmp/part2_demo/T2_ids.log

```

✅ Kiểm tra health (terminal rảnh):
```bash
curl -s http://127.0.0.1:5000/health | python3 -m json.tool
```

Kết quả mong đợi:
```json
{
  "model": "XGBoost v5 (MQTTset, 16 features)",
  "features": ["tcp.len", "tcp.time_delta", "tcp.flags", "mqtt.msgtype",
               "mqtt.msgid", "mqtt.qos", "mqtt.dupflag", "mqtt.len",
               "mqtt.kalive", "mqtt.conack.val", "mqtt.conflag.passwd",
               "mqtt.retain", "time_delta_mean", "time_delta_std",
               "pkt_rate", "pub_to_conn_ratio"],
  "status": "ok"
}
```

> **Lưu ý về 16 features:**
> - 12 features đầu (tcp.*, mqtt.*) lấy trực tiếp từ tshark qua `traffic_capture.py`
> - 4 features cuối (`time_delta_mean`, `time_delta_std`, `pkt_rate`,
>   `pub_to_conn_ratio`) được **ids_api.py tự tính** từ sliding window per-IP
>   → `traffic_capture.py` **không cần gửi** 4 trường này

---

## 5. T4 — Mininet (khởi động trước T3)

```bash
cd Part2
sudo -v
sudo python3 topology.py
```

> ❌ KHÔNG dùng `echo PASS | sudo -S python3 topology.py` — sudo tiêu thụ
> stdin, Mininet CLI thoát ngay lập tức.

✅ Chờ prompt `mininet>` xuất hiện.

### CHECK Cấu hình mosquitto broker lắng nghe 0.0.0.0

```bash
mininet> hbroker netstat -tlnp | grep 1883
```
#### Output:
```bash
tcp        0      0 0.0.0.0:1883            0.0.0.0:*               LISTEN      12415/mosquitto     
```
---

## 6. T3 — Traffic capture

**Mở terminal MỚI** (không dùng terminal Mininet).

```bash
cd Part2
sudo -v

# Bước 1: Bring s1 up + tạo OVS mirror → tshark có thể nhìn thấy traffic
sudo ip link set s1 up
sudo ovs-vsctl -- set Bridge s1 mirrors=@m \
               -- --id=@s1 get Port s1 \
               -- --id=@m create Mirror name=ids-mirror \
                  select-all=true output-port=@s1

# Bước 2: Khởi động capture
sudo -E ./venv/bin/python3 traffic_capture.py \
    --iface s1 \
    --api http://127.0.0.1:5000 \
    --csv capture.csv \
    2>&1 | tee /tmp/part2_demo/T3_capture.log
```

✅ Bạn sẽ thấy 2 loại dòng log:

```
Stats: captured=… sent=… errors=0 rate=… pkt/s
⚠ ATTACK BLOCKED [flood] conf=1.00 src=10.0.0.99 agg={pkt_rate: 312.4, ...}
```

> Nếu tshark thoát ngay với 0 packets → chạy lại 2 lệnh `ovs-vsctl` ở Bước 1.

### Bật debug chi tiết (khi cần troubleshoot)

```bash
sudo -E ./venv/bin/python3 traffic_capture.py \
    --iface s1 --api http://127.0.0.1:5000 \
    --debug-vector 20    # in full vector cho 20 packet đầu
```

Phía ids_api, bật debug qua env:
```bash
IDS_DEBUG_N=20 ./venv/bin/python3 ids_api.py ...
```

---

## 7. Attacks (chạy từ T4 / Mininet CLI)

**Sau moi lan chay attacker thi se bi block ip 10.0.0.99**

Can chay lenh unblock:
```
sh curl -s -X POST http://127.0.0.1:8080/ids/unblock \-H "Content-Type: application/json" \-d '{"ip":"10.0.0.99"}'
```

**Reset cac vote**

Can reset vote bang cach mo Terminal moi va chay lenh:
```bash
curl -X POST http://127.0.0.1:5000/reset
```
---

### Attack 1 — MQTT Flood

```text
mininet> hattacker python3 attack1_mqtt_flood.py --host 10.0.0.10 --threads 5
```

✅ Mong đợi: `⚠ ATTACK BLOCKED [flood] conf≈1.00`

### Attack dos 
```text
mininet> hattacker python3 attack2_dos.py --host 10.0.0.10 --threads 5
```
✅ Mong đợi: `⚠ ATTACK BLOCKED [dos] conf≈0.99`
---

### Attack 3 — Brute Force CONNECT

```text
mininet> hattacker python3 attack3_brute_force.py --host 10.0.0.10 --delay 0.1
```

✅ Mong đợi: `⚠ ATTACK BLOCKED [brute_force] conf≈0.94`

---

### Attack 4 — Malformed Packets

```text
mininet> hattacker python3 attack4_malformed.py --target 10.0.0.10 --port 1883 --rate 50 --duration 15
```

✅ Mong đợi: `⚠ ATTACK BLOCKED [malformed] conf≈0.98`

---
### Attack 5 — Slow Drip Exfiltration

```text
mininet> hattacker python3 attack5_slow_drip.py --host 10.0.0.10 --rate 1.0
```

✅ Mong đợi: `⚠ ATTACK BLOCKED [slow_drip] conf≈0.98`

---


## 8. Kiểm tra aggregate features

Sau khi chạy attack, kiểm tra IDS API đã tính aggregate features đúng chưa:

```bash
curl -s http://127.0.0.1:5000/stats | python3 -m json.tool | grep -A5 "ip_agg"
```

Hoặc test thủ công bằng cách gửi packet giả:

```bash
curl -s -X POST http://127.0.0.1:5000/predict \
  -H 'Content-Type: application/json' \
  -d '{
    "src_ip": "10.0.0.99",
    "features": {
      "tcp.len": "120",
      "tcp.time_delta": "0.001",
      "tcp.flags": "0x018",
      "mqtt.msgtype": "3",
      "mqtt.msgid": "1",
      "mqtt.qos": "0",
      "mqtt.dupflag": "0",
      "mqtt.len": "100",
      "mqtt.kalive": "60",
      "mqtt.conack.val": "0",
      "mqtt.conflag.passwd": "0",
      "mqtt.retain": "0"
    }
  }' | python3 -m json.tool
```

Kết quả sẽ có thêm trường `agg_features`:
```json
{
  "label": "legitimate",
  "confidence": 0.87,
  "agg_features": {
    "time_delta_mean": 0.001,
    "time_delta_std": 0.0,
    "pkt_rate": 1.0,
    "pub_to_conn_ratio": 1.0
  }
}
```

---

## 9. Useful REST endpoints

| Method | URL                                  | Mục đích                             |
|--------|--------------------------------------|--------------------------------------|
| GET    | `http://127.0.0.1:5000/health`       | model info + uptime + agg_window     |
| GET    | `http://127.0.0.1:5000/stats`        | counters, config, ip_agg_windows     |
| POST   | `http://127.0.0.1:5000/reset`        | clear vote + behavior + agg window   |
| GET    | `http://127.0.0.1:5000/whitelist`    | list whitelisted IPs                 |
| GET    | `http://127.0.0.1:8080/ids/rules`    | active OpenFlow block rules          |
| POST   | `http://127.0.0.1:8080/ids/unblock`  | xóa block rule cho 1 IP              |

---

## 10. Tear down

Tại T4:
```text
mininet> exit
```

Terminal bất kỳ:
```bash
sudo sh -c 'mn -c >/dev/null 2>&1; \
            killall -9 mosquitto 2>/dev/null; \
            pkill -9 -f "ryu-manager|ids_api.py|traffic_capture.py"; \
            ovs-vsctl --if-exists del-br s1; echo DONE'
```

Xóa chỉ mirror (nếu giữ bridge):
```bash
sudo ovs-vsctl clear Bridge s1 mirrors
```

---

## 11. Common gotchas

| Vấn đề | Nguyên nhân | Fix |
|--------|-------------|-----|
| `ValueError: X has 8 features but scaler expects 16` | Dùng nhầm `scaler_v2.pkl` cũ | Dùng `scaler.pkl` mới |
| tshark bắt được 0 packet | Mirror chưa tạo | Chạy lại 2 lệnh `ovs-vsctl` ở T3 |
| `pingall` toàn `X` | Sudo chưa cache ở T1 | `sudo -v` trong terminal T1 rồi restart Ryu |
| Attacker TCP RST | mosquitto bind 127.0.0.1 | Restart broker với `/tmp/mosq_open.conf` |
| Vote window tràn từ attack trước | State per-IP còn sót | `curl /reset` + `/ids/unblock` giữa attack |
| Mininet CLI thoát ngay | `sudo -S` tiêu thụ stdin | Dùng `sudo -v` trước rồi `sudo python3 topology.py` |
| Attack 5 spam log đè lên input | Process chưa kill | `hattacker pkill -9 -f attack5_slow_drip` trước |

---

## 12. Host IP reference

| Host       | IP          | Role        |
|------------|-------------|-------------|
| h1–h8      | 10.0.0.1–8  | sensors     |
| hbroker    | 10.0.0.10   | MQTT broker |
| hattacker  | 10.0.0.99   | attacker    |
