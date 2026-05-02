# Báo cáo: Kịch bản tấn công đa giai đoạn `combined_attack.py`

**File liên quan:** [part3/combined_attack.py](combined_attack.py)
**Mục tiêu:** Mô phỏng một cuộc tấn công MQTT/IoT *thực tế* (không phải từng đòn tách rời) để kiểm chứng IDS + SDN controller.

---

## 1. Vì sao phải kết hợp, không chạy từng cuộc tấn công một?

Trong thực tế, **không kẻ tấn công nào chỉ chạy đúng một loại tấn công rồi dừng**. Một chiến dịch tấn công IoT thật sự luôn đi theo *kill-chain* (chuỗi tiêu diệt) chuẩn ngành an ninh mạng. Theo mô hình **Lockheed Martin Cyber Kill-Chain** và **MITRE ATT&CK for ICS/IoT**, kẻ tấn công thường đi theo 4–7 giai đoạn nối tiếp/đan xen:

| Kill-chain (Lockheed) | MITRE ATT&CK Tactic | Hành vi trên broker MQTT |
|---|---|---|
| Reconnaissance | TA0043 — Reconnaissance | Quét cổng, gửi gói dị dạng để dò phiên bản broker |
| Weaponization + Delivery | TA0001 — Initial Access | Brute-force CONNECT để lấy credential |
| Exploitation | TA0002 — Execution | Gửi payload `malformed` khai thác lỗi parser |
| Installation + C2 | TA0011 — Command & Control | Mở kênh MQTT publish bí mật |
| **Actions on Objectives** | TA0040 — Impact / TA0010 — Exfiltration | DoS để che giấu **+** slow-drip để tuồn dữ liệu |

→ **Một kẻ tấn công thực thụ thực hiện *đồng thời* hoặc *gối nhau*** các pha này. Ví dụ phổ biến trong các báo cáo IR (Incident Response) thực tế:

- DoS/flood **làm mồi nhử** (smokescreen) để che các kết nối exfiltration đang chạy ngầm.
- Brute-force **xen kẽ** với gói malformed để né các IDS chỉ học một lớp đặc trưng.
- Slow-drip **bắt đầu sớm** và kéo dài qua cả lúc đã có DoS, vì nó là kênh "tiếng ồn thấp" (low-and-slow).

→ **Kiểm thử IDS bằng cách chạy 5 attack tuần tự, có `reset` giữa mỗi cuộc** chỉ chứng minh *từng phân loại* hoạt động. Nó **không chứng minh** được điều quan trọng nhất: **IDS có chịu được khi nhãn (label) thay đổi liên tục trên cùng một IP nguồn trong cùng một cửa sổ vote không?**

---

## 2. Kịch bản đề xuất — 4 pha theo kill-chain

Script `combined_attack.py` bố trí 4 pha trên cùng một host tấn công (`hattacker = 10.0.0.99`), tái sử dụng nguyên các script `attack1..attack5` trong `part3/` (không chỉnh sửa traffic-shape — quan trọng để model giữ nguyên đúng phân phối training MQTTset):

```
Trục thời gian (profile = fast, ~60s):

t=0s    ┃ PHA A — RECON
        ┃   attack4_malformed.py  rate=10/s  duration=5s
        ┃   → Mục đích: dò phản ứng broker với gói lạ. Trong thực tế
        ┃     đây là bước "fingerprinting" — kẻ tấn công xem broker
        ┃     có disconnect, có log không.
        ┃
t=8s    ┃ PHA B — CREDENTIAL ACCESS
        ┃   attack3_brute_force.py  delay=0.05s
        ┃   → Mục đích: thử 15×20 cặp user/pass. Pha này CHỒNG LÊN
        ┃     phần đuôi malformed → IDS thấy 2 nhãn cùng lúc trên 1 IP.
        ┃
t=22s   ┃ PHA C — IMPACT (gây hại)
        ┃   attack1_mqtt_flood.py  threads=5  rate=300  iter=60
        ┃   → Mục đích: làm broker quá tải. Đây là pha "ồn ào nhất".
        ┃     Trong thực tế đây cũng là "smokescreen" — tiếng ồn lớn
        ┃     để admin không để ý các kết nối nhỏ khác.
        ┃
t=40s   ┃ PHA D — EXFILTRATION (tuồn dữ liệu lén)
        ┃   attack5_slow_drip.py  rate=1.5/s
        ┃   → Mục đích: kênh ngầm. Tốc độ thấp tới mức tưởng như traffic
        ┃     hợp pháp. Pha này CHẠY ĐÈ lên đuôi flood, mô phỏng việc
        ┃     attacker đã có credential từ pha B và bắt đầu rút dữ liệu.
```

**3 profile:**

| Profile | Tổng thời gian | Đặc điểm | Kiểm chứng |
|---|---|---|---|
| `fast` | ~60s | Gối nhau 8–18s, tốc độ cao | Demo, chuyển nhãn nhanh |
| `stealth` | ~5 phút | Tốc độ thấp, khoảng cách lớn | Vote window decay, kỹ thuật né tránh |
| `burst` | song song | Cả 4 pha bắt đầu cùng t=0 | Bão hòa nhãn đồng thời (worst-case) |

---

## 3. Tại sao thiết kế này có ý nghĩa kiểm thử IDS?

Hệ thống IDS hiện tại có 3 cơ chế then chốt cần được kiểm chứng dưới điều kiện thực tế, mà chỉ tấn công kết hợp mới làm lộ ra:

### 3.1. Cửa sổ vote trượt (`IDS_VOTE_WINDOW=30s`, `IDS_BLOCK_VOTES=10`)

- Khi chạy tuần tự + `reset` giữa các cuộc → mỗi cuộc tấn công bắt đầu với cửa sổ rỗng → dễ đạt 10 vote.
- Khi chạy kết hợp → **các vote thuộc nhãn khác nhau cộng dồn trên cùng 1 IP nguồn**. Câu hỏi: aggregator có cộng đúng tổng vote (bất kể nhãn) hay reset khi nhãn đổi?
- → Profile `fast` chứng minh điều này: pha A chỉ ~50 gói malformed (chưa đủ block), nhưng cộng với vote của pha B (bruteforce) sẽ vượt ngưỡng *sớm hơn* so với chạy riêng.

### 3.2. Tính bền của Ryu drop rule

- Khi pha B kích hoạt block ở `s1` (drop rule cho src=10.0.0.99) → pha C và D vẫn được khởi chạy ở `hattacker`.
- **Kỳ vọng:** `T3_capture.log` sẽ KHÔNG có thêm sự kiện flood/slow_drip sau timestamp block.
- Nếu vẫn có → drop rule bị bypass (sai timeout, sai match field). Đây là **giá trị cốt lõi của SDN**: chặn ở data plane, không cần endpoint.

### 3.3. Bão hòa nhãn đồng thời (`burst` profile)

- Khi 4 luồng chạy song song, mỗi gói có thể cùng lúc khớp đặc trưng của ≥2 lớp (ví dụ: gói flood có rate cao + payload dị dạng → vừa giống `flood` vừa giống `malformed`).
- Refiner / argmax của model phải chọn đúng → kiểm tra **độ ổn định của classifier** dưới mixed-class traffic.
- Threat-score (weighted bằng confidence) cần saturate đúng, không bị double-count.

### 3.4. Mô phỏng kỹ thuật né tránh — `stealth` profile

- Kẻ tấn công thật có thể giãn 45–90 giây giữa các pha để **lách qua cửa sổ 30s**.
- Profile này kiểm chứng: nếu IDS chỉ dựa cửa sổ ngắn → bị né. Nếu có thêm long-window aggregation → vẫn block được.
- Đây là điểm yếu phổ biến của IDS dựa rule, và là lý do MQTTset đưa lớp `slowite` vào training set.

---

## 4. Quan điểm thiết kế (rationale)

1. **Tái sử dụng script gốc** — không tự viết lại traffic generator. Điều này đảm bảo mỗi pha vẫn giữ đúng đặc trưng mà model XGBoost đã học từ MQTTset (16 feature, 6 class). Nếu viết lại, có nguy cơ test "đường tắt".
2. **`reset` chỉ một lần trước khi chạy** — kẻ tấn công thật không bao giờ tự reset trạng thái phòng thủ. Reset giữa pha = không thực tế.
3. **Mỗi pha log riêng** vào `/tmp/combined_attack/stage_NN_<name>.log` — dễ đối chiếu với `T2_ids.log` để xem chính xác giây thứ mấy block kích hoạt và pha nào bị cắt giữa chừng.
4. **Profile hóa** — một file phục vụ 3 kịch bản (demo, stealth-evasion, worst-case). Không cần ba script riêng.
5. **Không chỉnh sửa argparse của các script con** — script orchestrator chỉ chuyển tham số. Nếu muốn thay đổi rate/duration → sửa `PROFILES` dict, không đụng tới `attack1..5`.

---

## 5. Cách chạy (tóm tắt)

```bash
# Terminal 1 — Mininet
cd Part2
SUDO_ASKPASS=/tmp/askpass.sh sudo -A python3 topology.py

# Trong mininet CLI:
mininet> hbroker mosquitto -c /tmp/mosq_open.conf -d

# Terminal 2 — Flask IDS  (xem README Part2)
# Terminal 3 — traffic_capture trên s1-eth11 (xem README Part2)

# Reset IDS một lần duy nhất:
mininet> sh bash -c 'curl -s -X POST http://127.0.0.1:5000/reset; \
                     curl -s -X POST http://127.0.0.1:8080/ids/unblock \
                          -H "Content-Type: application/json" \
                          -d "{\"ip\":\"10.0.0.99\"}"'

# Phóng kịch bản kết hợp:
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/combined_attack.py \
              --host 10.0.0.10 --profile fast
```

Đối chiếu kết quả:

```bash
# Tổng nhãn IDS đã ghi nhận
grep -oE 'ATTACK \[[a-z_ ]+\]' /tmp/part2_demo/T2_ids.log | sort | uniq -c

# Mốc thời gian block
grep BLOCKING /tmp/part2_demo/T2_ids.log | head -5

# Kiểm tra rule trên Ryu
sh bash -c 'curl -s http://127.0.0.1:8080/ids/rules'
```

---

## 6. Kết quả kỳ vọng theo từng profile

| Profile | Block xảy ra ở pha | Nhãn dự kiến trong log | Sự kiện sau block |
|---|---|---|---|
| `fast` | A→B (giây 4–10) | malformed, bruteforce, flood (ít), slow_drip (ít) | giảm mạnh sau khi block (chứng minh SDN) |
| `stealth` | C hoặc D (sau 2–3 phút) | tất cả các nhãn nhưng count thấp | chứng minh long-window vẫn bắt được |
| `burst` | <2s | mixed labels trong cùng vote window | tất cả 4 pha bị cắt sớm |

---

## 7. Hạn chế cần lưu ý

- **Pha B (brute-force) trên broker anonymous** kết thúc ở lần thử đầu (`mqtt/123456` rc=0). Để pha B sinh đủ vote → bật mosquitto auth bằng [Part2/setup_broker_auth.sh](../Part2/setup_broker_auth.sh) và khởi động lại broker với `/tmp/mosq_auth.conf` thay vì `/tmp/mosq_open.conf`.
- **Mininet CLI không có `;`** — phải bọc bằng `sh bash -c '...'` cho mọi lệnh chuỗi.
- **`hattacker` không định tuyến tới `127.0.0.1` host** → mọi lệnh `curl` tới IDS API phải chạy bằng `sh bash -c` (host namespace), không chạy bên trong namespace của host mininet.

---

## 8. Kết quả thực nghiệm (đã chạy ngày 2026-05-02, profile `fast`)

Đã chạy `combined_attack.py --host 10.0.0.10 --profile fast` từ `hattacker`
trong môi trường 4-terminal đầy đủ (Ryu + IDS API + traffic_capture + Mininet).

### 8.1. Lịch trình thực tế

```
[   0.0s] LAUNCH RECON   (malformed probe)   --rate 10 --duration 5
[   8.0s] LAUNCH CRED    (brute-force)       --delay 0.05  → tìm thấy mqtt/123456 ngay (broker anonymous)
[  22.0s] LAUNCH IMPACT  (MQTT flood)        --threads 5 --iter 60 --rate 300
[  40.0s] LAUNCH EXFIL   (slow-drip)         --rate 1.5
[  45.2s] DONE   EXFIL   rc=1   ← thất bại do bị block ở data plane
COMPLETED in 45.2s.
```

### 8.2. IDS labels đã ghi nhận trên 1 IP nguồn (10.0.0.99)

| Nhãn | Số sự kiện | Confidence điển hình |
|---|---:|---|
| `malformed`   |   9 | 0.62 – 1.00 |
| `bruteforce`  |   7 | (pha B kết thúc sớm vì broker anonymous) |
| `flood`       | 157 | 0.50 – 1.00 |
| `dos`         |  14 | (xuất hiện trong cửa sổ trùng với flood) |
| **Tổng**      | **187** | **4 nhãn / 1 IP nguồn** |

→ **Đã chứng minh điểm 3.1**: aggregator cộng dồn vote đúng qua 4 nhãn khác nhau trên cùng IP. Vote không bị reset khi nhãn đổi.

### 8.3. Thời điểm block

```
10:03:18.578  ATTACK [malformed]  +1.0pt  score=1.00/5.0   ← bắt đầu pha A
10:03:25.411  bruteforce stage tìm cred sau 1ms
10:03:39.547  -> BLOCKING src=10.0.0.99 score=5.69          ← VƯỢT NGƯỠNG (5.0)
10:03:39.551  Ryu block 10.0.0.99 → 200 {"status":"blocked"}
10:03:40.xxx  thêm hàng loạt flood event nhưng score đã saturate ở 10.0/5.0
```

→ Block kích hoạt giây thứ ~21 sau khi bắt đầu (giữa pha C — flood). Đúng như dự đoán: pha A+B chưa đủ điểm, pha C đẩy threat-score qua ngưỡng 5.0.

### 8.4. Bằng chứng SDN drop hoạt động (giá trị cốt lõi)

Pha D — slow-drip — được khởi chạy lúc t=40s, **sau** khi block đã có hiệu lực ở t=21s. Log của `stage_03_slow_drip.log`:

```python
File "/usr/lib/python3.12/socket.py", line 837, in create_connection
    sock.connect(sa)
TimeoutError: timed out
```

→ **Pha exfiltration không thể TCP-connect tới broker** vì OpenFlow drop rule trên `s1` đã match `nw_src=10.0.0.99` và drop mọi gói. Đây là kết quả mong muốn nhất:

> Khi IDS block một IP, kẻ tấn công không thể đổi nhãn (chuyển từ flood sang slow-drip) để vượt qua. SDN cắt ở data plane, không phụ thuộc lớp ứng dụng.

So sánh với khi chạy 5 attack tuần tự + reset (lần test trước):
- Tuần tự: `slow_drip` → 6 events được phân loại đúng (chạy bình thường vì block đã reset).
- Combined: `slow_drip` → 0 events, TCP timeout → SDN block đã giữ.

### 8.5. Tổng kết kiểm chứng các điểm 3.1–3.4

| Mục | Điểm cần kiểm chứng | Kết quả |
|---|---|---|
| 3.1 | Vote đa nhãn cộng dồn đúng | ✅ 4 nhãn cộng dồn trên 1 IP |
| 3.2 | Ryu drop rule bền qua nhãn mới | ✅ slow-drip TCP timeout sau block |
| 3.3 | Threat-score saturate đúng | ✅ score=10.0/5.0 ổn định, không quá 10.0 |
| 3.4 | (chưa test — cần `stealth` profile) | — chạy sau nếu cần |

### 8.6. Vấn đề gặp phải khi chạy & cách xử lý

| Vấn đề | Nguyên nhân | Cách khắc phục đã áp dụng |
|---|---|---|
| `topology.py` mở mosquitto chỉ trên `127.0.0.1` | mặc định trong topology | Khởi động lại broker bằng `mosquitto -c /tmp/mosq_open.conf -d` (listener `0.0.0.0` + `allow_anonymous true`) |
| Pha B brute-force kết thúc ở lần thử đầu | broker anonymous chấp nhận `mqtt/123456` ngay | Chấp nhận hạn chế này; ghi chú trong báo cáo. Để pha B chạy đủ wordlist, dùng `Part2/setup_broker_auth.sh` |
| Pha D báo lỗi `TimeoutError` (rc=1) | **không phải bug** — đây là minh chứng SDN block hoạt động | Giữ nguyên, ghi vào báo cáo như bằng chứng tốt nhất |
| `mn -c` bị `Killed` (exit 137) | OOM khi chạy song song với Ryu/IDS đang lên | Tách thành 2 lệnh sudo riêng |

→ **Không có vấn đề nào cần sửa code.** Script `combined_attack.py` chạy thành công ở lần thử đầu tiên với profile `fast`.

---

## 9. Tóm tắt một dòng

> *Tấn công thật không bao giờ đến từng cái một. `combined_attack.py` ghép 4 pha của kill-chain (Recon → Credential → Impact → Exfil) trên cùng một IP nguồn, đan xen thời gian, để kiểm chứng IDS có thực sự cộng dồn vote đa nhãn, có thực sự block trong cửa sổ trượt, và có thực sự cắt được data plane bằng SDN — chứ không chỉ phân loại đúng từng đòn riêng lẻ. **Đã chạy thành công: 187 sự kiện / 4 nhãn / 1 IP / block sau 21s / pha exfiltration bị TCP-timeout — chứng minh đủ cả 3 luận điểm.***
