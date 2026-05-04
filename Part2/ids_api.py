#!/usr/bin/env python3
"""
ids_api.py — ML IDS REST API  (v5 — 16 features)
=================================================
Wraps best_model.pkl (XGBoost v5, retrained on MQTTset).

Features (16, must match model.metadata order):
  tcp.len, tcp.time_delta, tcp.flags,
  mqtt.msgtype, mqtt.msgid, mqtt.qos, mqtt.dupflag,
  mqtt.len, mqtt.kalive, mqtt.conack.val, mqtt.conflag.passwd,
  mqtt.retain,
  time_delta_mean, time_delta_std, pkt_rate, pub_to_conn_ratio

The last 4 are per-IP aggregate features computed by ids_api from a
sliding time window — NOT raw tshark fields.

Usage:
    python ids_api.py --model best_model.pkl \
                      --scaler scaler.pkl \
                      --encoder label_encoder.pkl \
                      --port 5000

Endpoints:
  POST /predict        — classify one packet's features
  POST /predict/batch  — classify a list of packets
  GET  /stats          — detection statistics
  GET  /health         — liveness check
  GET  /whitelist      — list whitelisted IPs
  POST /whitelist/add  — add IP to whitelist
  POST /whitelist/remove — remove IP from whitelist
  POST /reset          — clear per-IP state
"""

import argparse
import logging
import math
import os
import statistics
import time
from collections import defaultdict, deque, Counter
from datetime import datetime

import joblib
import numpy as np
import requests
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [IDS-API] %(levelname)s %(message)s"
)
LOG = logging.getLogger("ids_api")

app = Flask(__name__)

# ─── Global model objects ─────────────────────────────────────────────────────
MODEL         = None
SCALER        = None
LABEL_ENCODER = None

# ─── 16 features — MUST match model.metadata "features" order exactly ─────────
# 12 per-packet tshark features + 4 aggregate per-IP features.
FEATURE_NAMES = [
    "tcp.len",
    "tcp.time_delta",
    "tcp.flags",
    "mqtt.msgtype",
    "mqtt.msgid",
    "mqtt.qos",
    "mqtt.dupflag",
    "mqtt.len",
    "mqtt.kalive",
    "mqtt.conack.val",
    "mqtt.conflag.passwd",
    "mqtt.retain",
    # ── Per-IP aggregate features (computed here, not from tshark directly) ──
    "time_delta_mean",    # mean inter-packet interval in sliding window
    "time_delta_std",     # std  inter-packet interval in sliding window
    "pkt_rate",           # packets/sec in sliding window
    "pub_to_conn_ratio",  # PUBLISH count / CONNECT count in sliding window
]

# Tshark fields used for aggregate computation (not sent to model directly)
AGGREGATE_TSHARK_FIELDS = {"tcp.time_delta", "mqtt.msgtype"}

MODEL_ATTACK_LABELS   = {"bruteforce", "dos", "flood", "malformed", "slowite"}
REFINED_ATTACK_LABELS = {"flood", "malformed", "brute_force", "port_scan",
                         "slow_drip", "c2_malware", "dos"}
ATTACK_LABELS = MODEL_ATTACK_LABELS | REFINED_ATTACK_LABELS
BENIGN_LABEL  = "legitimate"

IP_WHITELIST = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.5", "10.0.0.6",
    "10.0.0.7", "10.0.0.8", "10.0.0.10",
    "127.0.0.1",
}

TRUSTED_SOURCES = {
    "10.0.0.1", "10.0.0.2", "10.0.0.3",
    "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8",
    "10.0.0.10",  # broker
}
NORMAL_MQTT_MSGTYPES  = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14"}
ENABLE_TRUSTED_PREFILTER = os.environ.get("IDS_TRUSTED_PREFILTER", "1") == "1"
_trusted_prefilter_hits  = 0

BLOCK_CONFIDENCE_THRESHOLD = float(os.environ.get("IDS_BLOCK_CONF",       "0.90"))

# ─── Threat Score system (replaces old count-based vote window) ───────────────
# Mỗi IP có 1 điểm số tổng hợp (0..10). Score tăng khi detect attack,
# tự giảm theo exponential decay khi không có activity.
# Ưu điểm so với deque vote:
#   1. Nhiều loại attack cùng lúc (flood+dos+malformed) đều cộng vào 1 pool
#   2. Conf thấp vẫn được tính (có weight nhỏ hơn) thay vì bị bỏ qua hoàn toàn
#   3. Không "reset cứng" — score giảm dần, tấn công liên tục giữ score cao
#   4. Nghỉ rồi tấn công lại: score còn phần dư từ lần trước → phát hiện nhanh hơn

THREAT_BLOCK_THRESHOLD = float(os.environ.get("IDS_THREAT_THRESHOLD", "5.0"))
THREAT_SCORE_CAP       = float(os.environ.get("IDS_THREAT_CAP",       "10.0"))
THREAT_DECAY_LAMBDA    = float(os.environ.get("IDS_THREAT_DECAY",     "0.15"))
# λ=0.15 → score giảm ~78% sau 10 giây, ~97% sau 20 giây

# Conf weight brackets — conf thấp vẫn cộng điểm nhưng nhẹ hơn
CONF_WEIGHT_BRACKETS = [
    (0.90, 1.0),   # conf >= 0.90 → +1.0 điểm
    (0.80, 0.7),   # conf >= 0.80 → +0.7 điểm
    (0.70, 0.4),   # conf >= 0.70 → +0.4 điểm
    (0.00, 0.1),   # conf <  0.70 → +0.1 điểm (rất thấp nhưng không bỏ qua)
]

# ip_threat_score[ip] = float score hiện tại (sau decay)
# ip_threat_last[ip]  = timestamp lần cập nhật cuối (để tính decay)
ip_threat_score: dict = defaultdict(float)
ip_threat_last:  dict = defaultdict(float)


def _get_conf_weight(conf: float) -> float:
    for threshold, weight in CONF_WEIGHT_BRACKETS:
        if conf >= threshold:
            return weight
    return 0.1


def update_threat_score(src_ip: str, conf: float, is_attack: bool) -> float:
    """
    Cập nhật threat score cho src_ip.
    - Áp dụng exponential decay kể từ lần cập nhật trước.
    - Nếu is_attack=True: cộng thêm weight tương ứng với conf.
    - Trả về score hiện tại (sau decay + update).
    """
    now  = time.time()
    last = ip_threat_last.get(src_ip, now)
    dt   = now - last

    # Exponential decay: score_new = score_old × e^(-λ × dt)
    decayed = ip_threat_score[src_ip] * math.exp(-THREAT_DECAY_LAMBDA * dt)

    if is_attack:
        weight  = _get_conf_weight(conf)
        decayed = min(decayed + weight, THREAT_SCORE_CAP)

    ip_threat_score[src_ip] = decayed
    ip_threat_last[src_ip]  = now
    return decayed


def get_threat_score(src_ip: str) -> float:
    """Trả về score hiện tại (sau decay) mà không cộng thêm điểm mới."""
    now  = time.time()
    last = ip_threat_last.get(src_ip, now)
    dt   = now - last
    return ip_threat_score[src_ip] * math.exp(-THREAT_DECAY_LAMBDA * dt)

# ─── Per-IP sliding window for aggregate features ────────────────────────────
# Stores (timestamp, tcp.time_delta, mqtt.msgtype_int) per packet
AGG_WINDOW_SECS   = int(os.environ.get("IDS_AGG_WINDOW", "10"))  # seconds
# Flood gửi hàng nghìn TCP segment/s → maxlen phải lớn hơn burst rate × window
# Nếu maxlen quá nhỏ, deque bị tràn → mất gói cũ → timestamp[0] dịch gần timestamp[-1]
# → pkt_rate bị undercount → miss attack đầu đợt
# Flood ~2000 seg/s × 10s = 20000; dùng 25000 để có buffer
AGG_MAX_HISTORY   = 25000
ip_agg_window: dict = defaultdict(lambda: deque(maxlen=AGG_MAX_HISTORY))

# ─── Behavior-tracking window for subtype refinement ─────────────────────────
BEHAVIOR_WINDOW_SECS = 10.0
BEHAVIOR_MAX_HISTORY = 25000
ip_behavior: dict = defaultdict(lambda: deque(maxlen=BEHAVIOR_MAX_HISTORY))

# ─── Post-attack idle reset ───────────────────────────────────────────────────
# Nếu IP im lặng >= IDLE_RESET_SECS giây thì xóa sạch window trước khi xử lý
# packet mới. Tránh "ghost features" từ flood cũ làm nhiễu traffic hợp lệ sau đó.
IDLE_RESET_SECS = float(os.environ.get("IDS_IDLE_RESET", "15.0"))
ip_last_seen: dict = defaultdict(float)  # ip → timestamp lần cuối thấy packet

RYU_BLOCK_URL = os.environ.get("RYU_URL", "http://127.0.0.1:8080/ids/block")

stats           = defaultdict(int)
blocked_ips_log = []
start_time      = time.time()

DEBUG_LOG_FIRST_N = int(os.environ.get("IDS_DEBUG_N", "20"))
_dbg_pre_logged   = 0
_dbg_cls_logged   = 0
_dbg_pred_counter = Counter()


# ─── Model loading ────────────────────────────────────────────────────────────

def load_models(model_path, scaler_path, encoder_path):
    global MODEL, SCALER, LABEL_ENCODER
    LOG.info("Loading model   : %s", model_path)
    MODEL = joblib.load(model_path)
    LOG.info("Loading scaler  : %s", scaler_path)
    SCALER = joblib.load(scaler_path)
    LOG.info("Loading encoder : %s", encoder_path)
    LABEL_ENCODER = joblib.load(encoder_path)
    LOG.info("Classes  : %s", list(LABEL_ENCODER.classes_))
    LOG.info("Features (%d): %s", len(FEATURE_NAMES), FEATURE_NAMES)


# ─── Numeric conversion ───────────────────────────────────────────────────────

def to_num(val):
    """Convert any value to float. Supports hex strings, None, NaN, empty."""
    if val is None or (isinstance(val, float) and val != val):
        return 0.0
    s = str(val).strip()
    if not s or s in ("nan", "None", ""):
        return 0.0
    if s.startswith(("0x", "0X")):
        try:
            return float(int(s, 16))
        except ValueError:
            return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


# ─── Aggregate feature computation ───────────────────────────────────────────

def compute_aggregate_features(src_ip: str, raw: dict) -> dict:
    """
    Update the per-IP sliding window with the current packet and compute
    the 4 aggregate features required by model v5.

    Returns dict with keys: time_delta_mean, time_delta_std, pkt_rate,
                             pub_to_conn_ratio
    """
    now      = time.time()
    td       = to_num(raw.get("tcp.time_delta", 0))
    msgtype  = int(to_num(raw.get("mqtt.msgtype", 0)))

    # ── Idle reset: nếu IP im lặng quá lâu, xóa window cũ ───────────────────
    # Tránh ghost features từ đợt flood/attack trước ảnh hưởng traffic mới.
    last_seen = ip_last_seen[src_ip]
    if last_seen > 0 and (now - last_seen) >= IDLE_RESET_SECS:
        ip_agg_window[src_ip].clear()
        ip_behavior[src_ip].clear()
        LOG.info(
            "[AGG-RESET] src=%s idle=%.1fs >= %.1fs → window cleared",
            src_ip, now - last_seen, IDLE_RESET_SECS
        )
    ip_last_seen[src_ip] = now

    # ── tcp.time_delta sanity: giá trị > AGG_WINDOW_SECS là gap giữa 2 burst
    # không nên đưa vào mean/std vì sẽ kéo lệch → cap tại AGG_WINDOW_SECS
    td_capped = min(td, float(AGG_WINDOW_SECS))

    # Append current packet to this IP's window
    ip_agg_window[src_ip].append((now, td_capped, msgtype))

    # Prune entries older than AGG_WINDOW_SECS
    cutoff = now - AGG_WINDOW_SECS
    window = ip_agg_window[src_ip]
    while window and window[0][0] < cutoff:
        window.popleft()

    timestamps  = [e[0] for e in window]
    time_deltas = [e[1] for e in window]
    msgtypes    = [e[2] for e in window]

    n = len(time_deltas)

    # time_delta_mean / time_delta_std
    if n >= 2:
        td_mean = statistics.mean(time_deltas)
        td_std  = statistics.stdev(time_deltas) if n >= 3 else 0.0
    elif n == 1:
        td_mean = time_deltas[0]
        td_std  = 0.0
    else:
        td_mean = 0.0
        td_std  = 0.0

    # pkt_rate = packets in window / window duration (pkts/sec)
    if len(timestamps) >= 2:
        duration = timestamps[-1] - timestamps[0]
        pkt_rate = n / max(duration, 1e-6)
    else:
        pkt_rate = 0.0

    # pub_to_conn_ratio: PUBLISH(3) count / CONNECT(1) count
    pub_count  = msgtypes.count(3)
    conn_count = msgtypes.count(1)
    pub_to_conn_ratio = pub_count / max(conn_count, 1)

    return {
        "time_delta_mean":    td_mean,
        "time_delta_std":     td_std,
        "pkt_rate":           pkt_rate,
        "pub_to_conn_ratio":  pub_to_conn_ratio,
    }


# ─── Preprocessing ────────────────────────────────────────────────────────────

def preprocess_features(raw: dict, agg: dict) -> np.ndarray:
    """Convert tshark feature dict + aggregate dict → scaled numpy array."""
    combined = {**raw, **agg}
    row = [to_num(combined.get(col, 0)) for col in FEATURE_NAMES]
    X   = np.array([row], dtype=np.float32)
    Xs  = SCALER.transform(X)

    global _dbg_pre_logged
    if _dbg_pre_logged < DEBUG_LOG_FIRST_N:
        _dbg_pre_logged += 1
        LOG.info("[DBG-PRE #%d] raw  16feat = %s",
                 _dbg_pre_logged, dict(zip(FEATURE_NAMES, row)))
        LOG.info("[DBG-PRE #%d] scaled      = %s",
                 _dbg_pre_logged,
                 [round(float(v), 4) for v in Xs[0].tolist()])
        if all(v == 0.0 for v in row[:12]):
            LOG.warning("[DBG-PRE #%d]  ⚠ all-zero static features — pure TCP / no MQTT",
                        _dbg_pre_logged)
    return Xs


# ─── Behavior-based attack subtype refinement ─────────────────────────────────

def refine_attack_label(model_label: str, src_ip: str, raw: dict) -> str:
    """Return refined attack subtype based on src_ip's recent behavior.

    Rule priority (first match wins):
      1. flood (raw TCP burst) — tcp.len >> 1000 + very high pkt_rate
         attack1_mqtt_flood.py gửi 32760-byte TCP chunk → tshark thấy tcp.len rất lớn
      2. flood (PUBLISH ratio) — pub_ratio cao + pkt_rate cao
      3. SYN flood            — SYN-only packets
      4. dos                  — high pkt_rate + CONNECT+PUBLISH mix
      5. slow_drip            — low rate + large payload (base64 exfil)
      6. malformed            — CONNECT-only + out-of-spec msgtype
      7. port_scan            — SYN + varied msgtypes
      8. brute_force          — sustained CONNECT-only moderate rate
      9. fallback             — model_label unchanged

    Signature notes per attack script:
      attack1_mqtt_flood.py : gửi raw 32760-byte TCP segment = 1820× PUBLISH ghép lại
                              → tshark thấy tcp.len ≈ 32760, mqtt.len rất lớn,
                                pkt_rate rất cao (burst), pub_to_conn >> 1000
      attack_dos.py         : CONNECT + 50× PUBLISH per connection, pkt_rate cao,
                              pub_to_conn_ratio moderate (không >> như flood)
      attack_malformed.py   : raw TCP CONNECT bytes only, msgtype=1, tcp.len nhỏ
    """
    if model_label == BENIGN_LABEL or not src_ip:
        return model_label

    ts        = time.time()
    msgtype   = int(to_num(raw.get("mqtt.msgtype")))
    tcp_flags = int(to_num(raw.get("tcp.flags")))
    tcp_len   = int(to_num(raw.get("tcp.len")))
    mqtt_len  = int(to_num(raw.get("mqtt.len")))
    mqtt_msgid = to_num(raw.get("mqtt.msgid"))

    ip_behavior[src_ip].append((ts, msgtype, tcp_flags, tcp_len, mqtt_msgid, mqtt_len))

    # Prune stale entries
    cutoff = ts - BEHAVIOR_WINDOW_SECS
    buf    = ip_behavior[src_ip]
    while buf and buf[0][0] < cutoff:
        buf.popleft()

    recent = list(buf)
    if len(recent) < 3:
        return model_label

    msgtypes   = [e[1] for e in recent]
    flags_list = [e[2] for e in recent]
    tcp_lens   = [e[3] for e in recent]
    mqtt_lens  = [e[5] for e in recent]

    # ── Shared: pkt_rate từ agg window ───────────────────────────────────────
    agg_buf  = ip_agg_window.get(src_ip)
    pkt_rate = 0.0
    if agg_buf and len(agg_buf) >= 2:
        ts_list  = [e[0] for e in agg_buf]
        duration = ts_list[-1] - ts_list[0]
        pkt_rate = len(agg_buf) / max(duration, 1e-6)

    pub_ratio    = msgtypes.count(3) / len(msgtypes)
    conn_ratio   = msgtypes.count(1) / len(msgtypes)
    avg_mqtt_len = sum(mqtt_lens) / len(mqtt_lens) if mqtt_lens else 0
    avg_tcp_len  = sum(tcp_lens)  / len(tcp_lens)  if tcp_lens  else 0
    syn_ratio    = sum(1 for f in flags_list if (f & 0x02) and not (f & 0x10)) / len(flags_list)

    buf_pub  = msgtypes.count(3)
    buf_conn = msgtypes.count(1)
    buf_p2c  = buf_pub / max(buf_conn, 1)

    # ── Rule 1: Raw TCP burst flood (attack1_mqtt_flood.py signature) ─────────
    # Script gửi 32760-byte chunk = 1820 PUBLISH ghép lại trong 1 sendall().
    # tshark thấy tcp.len rất lớn (> 1000) hoặc mqtt.len rất lớn.
    # Packet hiện tại hoặc trung bình buffer đều lớn bất thường.
    is_large_tcp = tcp_len > 1000 or avg_tcp_len > 500
    if is_large_tcp and pkt_rate > 5:
        return "flood"

    # ── Rule 2: High-rate PUBLISH flood (pub_ratio cao, rate cao) ────────────
    if pub_ratio > 0.8 and buf_p2c > 3.0 and pkt_rate > 20:
        return "flood"

    # ── Rule 3: SYN flood ────────────────────────────────────────────────────
    if syn_ratio > 0.7:
        return "flood"

    # ── Rule 4: DoS (attack_dos.py) ──────────────────────────────────────────
    # CONNECT + nhiều PUBLISH per session, pkt_rate cao vừa, p2c moderate
    if pkt_rate > 30 and 0.3 <= buf_p2c <= 3.0:
        return "dos"

    # ── Rule 5: Slow drip ─────────────────────────────────────────────────────
    # Low rate + PUBLISH + payload LỚN BẤT THƯỜNG (base64 exfil > 100 bytes)
    # KHÔNG phải legitimate sensor JSON (thường < 80 bytes, td > 1s)
    if pkt_rate < 1.5 and pub_ratio >= 0.5 and avg_mqtt_len > 100:
        return "slow_drip"

    # ── Rule 6: Malformed ─────────────────────────────────────────────────────
    malformed_ratio = sum(1 for m in msgtypes if m == 0 or m > 14) / len(msgtypes)
    if malformed_ratio > 0.3 and pkt_rate >= 2.0:
        return "malformed"
    if conn_ratio > 0.8 and buf_p2c == 0 and avg_tcp_len < 30 and pkt_rate > 2.0:
        return "malformed"

    # ── Rule 7: Port scan ─────────────────────────────────────────────────────
    if syn_ratio > 0.5 and len(set(msgtypes)) > 3:
        return "port_scan"

    # ── Rule 8: Brute force ───────────────────────────────────────────────────
    if conn_ratio > 0.5:
        return "brute_force"

    return model_label


# ─── Behavioral sanity check (false-positive suppressor) ─────────────────────
#
# Model XGBoost được train trên MQTTset có giới hạn: một số feature combination
# của legitimate IoT traffic (pub_to_conn_ratio tăng dần, mqtt.msgid tăng, QoS=1)
# overlap với DoS/slowite pattern trong training data.
#
# Hàm này áp dụng các ràng buộc vật lý / thống kê mà attack thực sự PHẢI thỏa,
# nhưng legitimate traffic KHÔNG thể thỏa đồng thời → override model nếu vi phạm.
#
# Chỉ can thiệp vào 2 label dễ bị false positive nhất: dos, slowite.
# Các label khác (flood, bruteforce, malformed) giữ nguyên model decision.

# Ngưỡng vật lý: pkt_rate tối thiểu để tấn công có tác động thực sự
DOS_MIN_PKT_RATE    = 5.0   # pkts/s — DoS cần ít nhất 5 pkt/s để gây tải
SLOWITE_MAX_PKT_RATE = 2.0  # pkts/s — slowite/slow_drip là LOW-rate by definition
                             # nhưng phải kết hợp payload lớn bất thường
SLOWITE_MIN_MQTT_LEN = 100  # bytes — legitimate sensor JSON thường < 80 bytes

# time_delta giữa các packet của legitimate IoT publisher ≈ PUBLISH_RATE (2-4s)
# DoS/flood thực sự có time_delta << 1s (thường < 0.1s)
LEGITIMATE_MIN_TIME_DELTA_MEAN = 1.0  # giây — dưới ngưỡng này mới có thể là attack

def behavioral_sanity_check(model_label: str, agg: dict, raw: dict) -> str:
    """
    Kiểm tra xem model_label có phù hợp với hành vi thực tế quan sát không.
    Trả về model_label gốc nếu hợp lý, hoặc BENIGN_LABEL nếu phát hiện FP rõ ràng.

    Logic:
      - dos/flood    cần pkt_rate CAO và time_delta_mean THẤP
      - slowite      cần pkt_rate THẤP nhưng payload lớn bất thường
      - bruteforce   cần pkt_rate vừa và CONNECT-only (pub_to_conn thấp)
      - malformed    cần msgtype bất thường hoặc tcp.len rất nhỏ
    """
    if model_label not in MODEL_ATTACK_LABELS:
        return model_label  # không can thiệp vào legitimate

    pkt_rate        = agg.get("pkt_rate", 0.0)
    td_mean         = agg.get("time_delta_mean", 0.0)
    pub_to_conn     = agg.get("pub_to_conn_ratio", 0.0)
    mqtt_len        = to_num(raw.get("mqtt.len", 0))
    mqtt_qos        = to_num(raw.get("mqtt.qos", 0))
    mqtt_kalive     = to_num(raw.get("mqtt.kalive", 0))
    tcp_time_delta  = to_num(raw.get("tcp.time_delta", 0))

    # ── Kiểm tra dos / flood ─────────────────────────────────────────────────
    # Attack thực: pkt_rate cao VÀ time_delta nhỏ
    # False positive: pkt_rate thấp (< DOS_MIN_PKT_RATE) VÀ time_delta lớn (> 1s)
    if model_label in ("dos", "flood"):
        legitimate_rate   = pkt_rate < DOS_MIN_PKT_RATE
        legitimate_timing = td_mean > LEGITIMATE_MIN_TIME_DELTA_MEAN
        legitimate_delta  = tcp_time_delta > LEGITIMATE_MIN_TIME_DELTA_MEAN

        if legitimate_rate and legitimate_timing and legitimate_delta:
            LOG.info(
                "[SANITY] Override %s→legitimate: pkt_rate=%.3f<%.1f "
                "td_mean=%.3f>%.1fs tcp_td=%.3f (legitimate IoT cadence)",
                model_label, pkt_rate, DOS_MIN_PKT_RATE,
                td_mean, LEGITIMATE_MIN_TIME_DELTA_MEAN, tcp_time_delta
            )
            return BENIGN_LABEL

    # ── Kiểm tra slowite ─────────────────────────────────────────────────────
    # Slowite thực: pkt_rate thấp + payload LỚN BẤT THƯỜNG (base64 exfil)
    # False positive: pkt_rate thấp + payload bình thường (sensor JSON < 80 bytes)
    if model_label == "slowite":
        normal_payload = mqtt_len < SLOWITE_MIN_MQTT_LEN
        normal_timing  = tcp_time_delta > LEGITIMATE_MIN_TIME_DELTA_MEAN

        if normal_payload and normal_timing:
            LOG.info(
                "[SANITY] Override slowite→legitimate: mqtt_len=%.0f<%.0f "
                "tcp_td=%.3f (normal sensor payload)",
                mqtt_len, SLOWITE_MIN_MQTT_LEN, tcp_time_delta
            )
            return BENIGN_LABEL

    # ── Kiểm tra bruteforce ──────────────────────────────────────────────────
    # Bruteforce thực: CONNECT liên tục, pub_to_conn gần 0, không có QoS=1 data
    # Nếu có pub_to_conn > 2 và QoS=1 → đây là publisher bình thường
    if model_label == "bruteforce":
        if pub_to_conn > 2.0 and mqtt_qos >= 1 and pkt_rate < DOS_MIN_PKT_RATE:
            LOG.info(
                "[SANITY] Override bruteforce→legitimate: pub_to_conn=%.1f "
                "qos=%.0f pkt_rate=%.3f (normal publisher)",
                pub_to_conn, mqtt_qos, pkt_rate
            )
            return BENIGN_LABEL

    return model_label  # giữ nguyên nếu không có vi phạm


# ─── Block via Ryu ────────────────────────────────────────────────────────────

def block_ip_via_ryu(src_ip: str, label: str):
    try:
        r = requests.post(RYU_BLOCK_URL, json={"ip": src_ip}, timeout=2.0)
        LOG.warning("Ryu block %s → %d %s", src_ip, r.status_code, r.text[:80])
        blocked_ips_log.append({
            "ip": src_ip, "label": label,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        LOG.error("Ryu block request failed for %s: %s", src_ip, e)


# ─── Core classification ──────────────────────────────────────────────────────

def classify(raw_features: dict, src_ip: str = None) -> dict:
    """Classify one packet. Returns prediction result dict."""
    global _trusted_prefilter_hits

    # Trusted-source pre-filter (skip ML for known-good hosts)
    if ENABLE_TRUSTED_PREFILTER and src_ip in TRUSTED_SOURCES:
        msgtype = str(int(to_num(raw_features.get("mqtt.msgtype", 0))))
        if msgtype in NORMAL_MQTT_MSGTYPES:
            _trusted_prefilter_hits += 1
            if _trusted_prefilter_hits <= DEBUG_LOG_FIRST_N:
                LOG.info("[DBG-TRUST] hit #%d src=%s msgtype=%s -> legitimate",
                         _trusted_prefilter_hits, src_ip, msgtype)
            # Still update aggregate window so state stays consistent
            compute_aggregate_features(src_ip, raw_features)
            stats[BENIGN_LABEL] += 1
            return {
                "label":        BENIGN_LABEL,
                "model_label":  BENIGN_LABEL,
                "confidence":   1.0,
                "is_attack":    False,
                "threat_score": round(get_threat_score(src_ip), 3),
                "src_ip":       src_ip,
                "timestamp":    datetime.now().isoformat(),
                "blocked":      False,
                "trusted_prefilter": True,
            }

    # Compute aggregate features for this src_ip
    agg = compute_aggregate_features(src_ip or "__unknown__", raw_features)

    X     = preprocess_features(raw_features, agg)
    proba = MODEL.predict_proba(X)[0]
    idx   = int(np.argmax(proba))
    model_label = LABEL_ENCODER.inverse_transform([idx])[0]
    conf  = float(proba[idx])

    global _dbg_cls_logged, _dbg_pred_counter
    _dbg_pred_counter[model_label] += 1
    if _dbg_cls_logged < DEBUG_LOG_FIRST_N:
        _dbg_cls_logged += 1
        proba_d = {LABEL_ENCODER.inverse_transform([i])[0]: round(float(p), 3)
                   for i, p in enumerate(proba)}
        LOG.info("[DBG-CLS #%d] src=%-15s model_label=%-12s conf=%.3f probas=%s",
                 _dbg_cls_logged, src_ip or "-", model_label, conf, proba_d)
    if sum(_dbg_pred_counter.values()) % 200 == 0:
        LOG.info("[DBG-DIST] cumulative model_label histogram: %s",
                 dict(_dbg_pred_counter.most_common()))

    # ── Behavioral sanity check: override obvious false positives ────────────
    # Chạy TRƯỚC refine_attack_label để tránh refine một FP thành subtype khác.
    # Nếu model predict attack nhưng behavior không khớp signature thực → legitimate.
    sanitized_label = behavioral_sanity_check(model_label, agg, raw_features)
    if sanitized_label != model_label:
        # Model bị FP — override toàn bộ pipeline
        model_label = sanitized_label
        conf        = 1.0   # certainty ta override

    is_attack = model_label in MODEL_ATTACK_LABELS
    label     = refine_attack_label(model_label, src_ip, raw_features) if is_attack else model_label
    stats[label] += 1

    # ── Threat score update ───────────────────────────────────────────────────
    # Cộng điểm vào pool chung của IP (không phân biệt loại attack).
    # Conf thấp vẫn được tính với weight nhỏ hơn.
    # Score tự decay theo thời gian → không "đóng băng" giữa 2 lần test.
    if src_ip:
        threat_score = update_threat_score(src_ip, conf, is_attack)
    else:
        threat_score = 0.0

    result = {
        "label":        label,
        "model_label":  model_label,
        "confidence":   round(conf, 4),
        "is_attack":    is_attack,
        "threat_score": round(threat_score, 3),
        "src_ip":       src_ip or "unknown",
        "timestamp":    datetime.now().isoformat(),
        "blocked":      False,
        "agg_features": {k: round(v, 4) for k, v in agg.items()},
    }

    if is_attack and src_ip:
        weight = _get_conf_weight(conf)
        LOG.warning(
            "ATTACK [%-12s] conf=%.2f +%.1fpt score=%.2f/%.1f src=%s",
            label, conf, weight, threat_score, THREAT_BLOCK_THRESHOLD, src_ip
        )
        if src_ip in IP_WHITELIST:
            LOG.info("  -> Skip block: %s whitelisted", src_ip)
        elif threat_score < THREAT_BLOCK_THRESHOLD:
            LOG.info(
                "  -> Skip block: score %.2f < %.1f (λ-decay active)",
                threat_score, THREAT_BLOCK_THRESHOLD
            )
        elif conf < BLOCK_CONFIDENCE_THRESHOLD:
            LOG.info(
                "  -> Skip block: score %.2f >= %.1f but conf %.2f < %.2f (conf gate)",
                threat_score, THREAT_BLOCK_THRESHOLD, conf, BLOCK_CONFIDENCE_THRESHOLD
            )
        else:
            LOG.warning("  -> BLOCKING src=%s score=%.2f conf=%.2f", src_ip, threat_score, conf)
            block_ip_via_ryu(src_ip, label)
            result["blocked"] = True
    else:
        LOG.debug("OK [%s] conf=%.2f score=%.2f src=%s",
                  label, conf, threat_score, src_ip)

    return result


# ─── Flask endpoints ──────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":   "ok",
        "model":    "XGBoost v5 (MQTTset, 16 features)",
        "features": FEATURE_NAMES,
        "classes":  list(LABEL_ENCODER.classes_) if LABEL_ENCODER else [],
        "uptime_s": round(time.time() - start_time, 1),
        "agg_window_secs": AGG_WINDOW_SECS,
    })


@app.route("/predict", methods=["POST"])
def predict():
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503
    body = request.get_json(silent=True)
    if not body or "features" not in body:
        return jsonify({"error": "Missing 'features' key"}), 400
    try:
        result = classify(body["features"], src_ip=body.get("src_ip"))
    except Exception as e:
        LOG.error("Predict error: %s", e)
        return jsonify({"error": str(e)}), 500
    return jsonify(result)


@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 503
    items = request.get_json(silent=True)
    if not isinstance(items, list):
        return jsonify({"error": "Expected a JSON array"}), 400
    results = []
    for item in items:
        try:
            r = classify(item.get("features", {}), src_ip=item.get("src_ip"))
            results.append(r)
        except Exception as e:
            results.append({"error": str(e)})
    return jsonify(results)


@app.route("/stats", methods=["GET"])
def get_stats():
    total = sum(stats.values())
    now   = time.time()
    return jsonify({
        "total_packets":  total,
        "by_label":       dict(stats),
        "blocked_events": blocked_ips_log[-50:],
        "uptime_s":       round(time.time() - start_time, 1),
        "trusted_prefilter_hits": _trusted_prefilter_hits,
        "config": {
            "features":              FEATURE_NAMES,
            "n_features":            len(FEATURE_NAMES),
            "whitelist":             sorted(IP_WHITELIST),
            "confidence_threshold":  BLOCK_CONFIDENCE_THRESHOLD,
            "threat_block_threshold": THREAT_BLOCK_THRESHOLD,
            "threat_score_cap":      THREAT_SCORE_CAP,
            "threat_decay_lambda":   THREAT_DECAY_LAMBDA,
            "agg_window_secs":       AGG_WINDOW_SECS,
        },
        "ip_threat_scores": {
            ip: {
                "score":        round(score * math.exp(-THREAT_DECAY_LAMBDA * (now - ip_threat_last.get(ip, now))), 3),
                "last_seen_ago": round(now - ip_threat_last.get(ip, now), 1),
                "above_threshold": (score * math.exp(-THREAT_DECAY_LAMBDA * (now - ip_threat_last.get(ip, now)))) >= THREAT_BLOCK_THRESHOLD,
            }
            for ip, score in ip_threat_score.items()
        },
        "ip_agg_windows": {
            ip: {"buffered_pkts": len(buf)}
            for ip, buf in ip_agg_window.items()
        },
    })


@app.route("/whitelist", methods=["GET"])
def get_whitelist():
    return jsonify({"whitelist": sorted(IP_WHITELIST)})


@app.route("/whitelist/add", methods=["POST"])
def add_whitelist():
    body = request.get_json(silent=True)
    ip   = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing 'ip'"}), 400
    IP_WHITELIST.add(ip)
    LOG.info("Whitelist add: %s", ip)
    return jsonify({"status": "added", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    body = request.get_json(silent=True)
    ip   = (body or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "missing 'ip'"}), 400
    IP_WHITELIST.discard(ip)
    LOG.info("Whitelist remove: %s", ip)
    return jsonify({"status": "removed", "ip": ip, "whitelist": sorted(IP_WHITELIST)})


@app.route("/reset", methods=["POST"])
def reset_state():
    """Clear per-IP threat score / behavior / aggregate windows.
    Body: {"ip": "10.0.0.99"} to scope to one IP, omit to clear all.
          {"stats": true}      to also zero the stats counters."""
    body = request.get_json(silent=True) or {}
    ip   = (body.get("ip") or "").strip()
    if ip:
        ip_threat_score.pop(ip, None)
        ip_threat_last.pop(ip, None)
        ip_behavior.pop(ip, None)
        ip_agg_window.pop(ip, None)
        ip_last_seen.pop(ip, None)
        LOG.info("Reset state for %s", ip)
        scope = ip
    else:
        ip_threat_score.clear()
        ip_threat_last.clear()
        ip_behavior.clear()
        ip_agg_window.clear()
        ip_last_seen.clear()
        LOG.info("Reset state for ALL ips")
        scope = "all"
    if body.get("stats"):
        stats.clear()
    return jsonify({"status": "reset", "scope": scope})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MQTT IDS API v5 — 16 features")
    parser.add_argument("--model",   default="best_model.pkl")
    parser.add_argument("--scaler",  default="scaler.pkl")
    parser.add_argument("--encoder", default="label_encoder.pkl")
    parser.add_argument("--port",    type=int, default=5000)
    parser.add_argument("--host",    default="0.0.0.0")
    args = parser.parse_args()

    load_models(args.model, args.scaler, args.encoder)

    LOG.info("IDS API v5 starting on %s:%d", args.host, args.port)
    LOG.info("Ryu block endpoint  : %s", RYU_BLOCK_URL)
    LOG.info("Aggregate window    : %ds", AGG_WINDOW_SECS)
    LOG.info("Threat score config : block=%.1f cap=%.1f decay_λ=%.3f",
             THREAT_BLOCK_THRESHOLD, THREAT_SCORE_CAP, THREAT_DECAY_LAMBDA)
    LOG.info("Conf weight brackets: %s", CONF_WEIGHT_BRACKETS)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)