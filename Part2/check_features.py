#!/usr/bin/env python3
"""
check_features.py — Kiểm tra feature pipeline so với dataset MQTTset
=====================================================================
Không cần Mininet, không cần tshark, không cần model chạy.
Chỉ cần: scaler_v2.pkl, label_encoder_v2.pkl, model_metadata_v2.json

Chạy:
    python3 check_features.py --meta model_metadata_v2.json \
                               --scaler scaler_v2.pkl \
                               --encoder label_encoder_v2.pkl

Kiểm tra:
  1. Số lượng features đúng không (phải là 8)
  2. Tên features khớp với model không
  3. Hex string convert đúng không
  4. Scaler normalize ra giá trị hợp lý không
  5. Giá trị thực tế từ dataset so sánh với giá trị test (có post-process rules)
  6. Xử lý field bị thiếu
"""

import argparse
import json
import sys

import joblib
import numpy as np

# ── Màu terminal ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):  print(f"  {GREEN}✓{RESET} {msg}")
def err(msg): print(f"  {RED}✗ {msg}{RESET}")
def warn(msg):print(f"  {YELLOW}⚠ {msg}{RESET}")
def info(msg):print(f"  {CYAN}→{RESET} {msg}")


# ── to_num (phải giống hệt ids_api.py) ───────────────────────────────────────
def to_num(val):
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


# ── TCP flag constants ─────────────────────────────────────────────────────────
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10

ATTACK_LABELS = {"bruteforce", "dos", "flood", "malformed", "slowite"}
POSTPROCESS_CONF_THRESHOLD = 0.65


# ── Post-processing rules (mirror của ids_api.py) ─────────────────────────────
def apply_postprocess_rules(label, conf, raw_features):
    """
    Trả về (new_label, new_conf, rule_name) sau khi áp dụng rules.
    Nếu không có rule nào kích hoạt, trả về (label, conf, None).
    """
    if conf >= POSTPROCESS_CONF_THRESHOLD:
        return label, conf, None

    tcp_flags  = int(to_num(raw_features.get("tcp.flags", 0)))
    tcp_len    = to_num(raw_features.get("tcp.len", 0))
    mqtt_type  = to_num(raw_features.get("mqtt.msgtype", 0))
    mqtt_flags = to_num(raw_features.get("mqtt.hdrflags", 0))

    is_pure_ack = (tcp_flags == TCP_FLAG_ACK) and tcp_len == 0 and mqtt_type == 0 and mqtt_flags == 0
    is_syn      = bool(tcp_flags & TCP_FLAG_SYN) and not bool(tcp_flags & TCP_FLAG_ACK) and tcp_len == 0
    is_fin      = bool(tcp_flags & TCP_FLAG_FIN) and tcp_len == 0 and mqtt_type == 0

    # R1: Pure ACK bị pred=slowite → legitimate
    if label == "slowite" and is_pure_ack:
        return "legitimate", 0.55, "R1:pure_ack→legitimate"

    # R2: SYN packet bị pred=malformed → dos
    if label == "malformed" and is_syn:
        return "dos", 0.60, "R2:syn→dos"

    # R3: FIN packet bị pred=attack → legitimate
    if label in ATTACK_LABELS and is_fin:
        return "legitimate", 0.52, "R3:fin→legitimate"

    return label, conf, None


# ── Các mẫu thực tế lấy từ dataset (observed values) ─────────────────────────
REAL_SAMPLES = {
    "legitimate_PUBLISH": {
        "raw": {
            "mqtt.msgid":      "0",
            "tcp.len":         "10",
            "mqtt.msgtype":    "3",
            "mqtt.hdrflags":   "0x00000030",
            "mqtt.qos":        "0",
            "tcp.flags":       "0x00000018",
            "tcp.time_delta":  "0.998867",
            "mqtt.retain":     "0",
        },
        "expected_label": "legitimate",
    },
    "legitimate_ACK_only": {
        "raw": {
            "mqtt.msgid":      "0",
            "tcp.len":         "0",
            "mqtt.msgtype":    "0",
            "mqtt.hdrflags":   "0",
            "mqtt.qos":        "0",
            "tcp.flags":       "0x00000010",  # ACK only → R1 sẽ fix
            "tcp.time_delta":  "0.000009",
            "mqtt.retain":     "0",
        },
        "expected_label": "legitimate",
    },
    "malformed_RST": {
        "raw": {
            "mqtt.msgid":      "0",
            "tcp.len":         "0",
            "mqtt.msgtype":    "0",
            "mqtt.hdrflags":   "0",
            "mqtt.qos":        "0",
            "tcp.flags":       "0x00000004",  # RST
            "tcp.time_delta":  "0.000001",
            "mqtt.retain":     "0",
        },
        "expected_label": "malformed",
    },
    "dos_SYN_flood": {
        "raw": {
            "mqtt.msgid":      "0",
            "tcp.len":         "0",
            "mqtt.msgtype":    "0",
            "mqtt.hdrflags":   "0",
            "mqtt.qos":        "0",
            "tcp.flags":       "0x00000002",  # SYN → R2 sẽ fix
            "tcp.time_delta":  "0.000001",
            "mqtt.retain":     "0",
        },
        "expected_label": "dos",
    },
}


def check_1_feature_count(meta_features):
    print(f"\n{BOLD}=== CHECK 1: Số lượng features ==={RESET}")
    n = len(meta_features)
    if n == 8:
        ok(f"Đúng 8 features")
    else:
        err(f"Sai số lượng: {n} (cần 8)")
    return n == 8


def check_2_feature_names(meta_features):
    print(f"\n{BOLD}=== CHECK 2: Tên features ==={RESET}")
    EXPECTED = [
        "mqtt.qos", "mqtt.hdrflags", "tcp.len", "mqtt.msgtype",
        "mqtt.retain", "tcp.flags", "mqtt.msgid", "tcp.time_delta"
    ]
    all_ok = True
    for i, (exp, got) in enumerate(zip(EXPECTED, meta_features)):
        if exp == got:
            ok(f"[{i}] {got}")
        else:
            err(f"[{i}] Cần '{exp}' — got '{got}'")
            all_ok = False
    if len(meta_features) != len(EXPECTED):
        err(f"Số lượng khác nhau: {len(meta_features)} vs {len(EXPECTED)}")
        all_ok = False
    return all_ok


def check_3_hex_conversion(meta_features):
    print(f"\n{BOLD}=== CHECK 3: Hex string conversion ==={RESET}")
    cases = [
        ("tcp.flags",     "0x00000018", 24.0),
        ("tcp.flags",     "0x00000002",  2.0),
        ("tcp.flags",     "0x00000004",  4.0),
        ("tcp.flags",     "0x00000010", 16.0),
        ("mqtt.hdrflags", "0x00000030", 48.0),
        ("mqtt.hdrflags", "0x00000020", 32.0),
        ("mqtt.hdrflags", "0",           0.0),
    ]
    all_ok = True
    for feat, inp, expected in cases:
        got = to_num(inp)
        if abs(got - expected) < 1e-6:
            ok(f"to_num({inp!r}) = {got} ✓")
        else:
            err(f"to_num({inp!r}) = {got}, cần {expected}")
            all_ok = False
    return all_ok


def check_4_scaler(scaler, meta_features):
    print(f"\n{BOLD}=== CHECK 4: Scaler — normalize giá trị ==={RESET}")
    means  = scaler.mean_
    scales = scaler.scale_
    info(f"Scaler fitted trên {scaler.n_samples_seen_} samples")
    print(f"\n  {'Feature':<20} {'mean':>10} {'std':>10}  {'range_check'}")
    print(f"  {'-'*20} {'-'*10} {'-'*10}  {'-'*20}")
    all_ok = True
    for i, feat in enumerate(meta_features):
        m, s = means[i], scales[i]
        if s < 1e-9:
            print(f"  {feat:<20} {m:>10.4f} {s:>10.6f}  {RED}⚠ std≈0 (constant feature!){RESET}")
            warn(f"{feat} có std≈0 — feature này không có giá trị phân biệt")
            all_ok = False
        else:
            print(f"  {feat:<20} {m:>10.4f} {s:>10.4f}  {GREEN}OK{RESET}")
    return all_ok


def check_5_real_samples(scaler, model, le, meta_features):
    print(f"\n{BOLD}=== CHECK 5: Predict + post-process rules ==={RESET}")
    info("Rules đang active: R1 (pure ACK→legit), R2 (SYN→dos), R3 (FIN→legit)")
    all_ok = True

    for name, sample in REAL_SAMPLES.items():
        raw      = sample["raw"]
        expected = sample.get("expected_label", "?")

        # Build feature vector
        row  = [to_num(raw.get(f, "0")) for f in meta_features]
        X    = np.array([row], dtype=np.float32)
        Xs   = scaler.transform(X)

        raw_str    = "  ".join(f"{meta_features[i]}={row[i]:.1f}" for i in range(len(row)))
        scaled_str = "  ".join(f"{Xs[0][i]:+.2f}" for i in range(len(row)))

        if model is not None:
            proba      = model.predict_proba(Xs)[0]
            idx        = int(np.argmax(proba))
            raw_label  = le.inverse_transform([idx])[0]
            raw_conf   = float(proba[idx])

            # Áp dụng post-process rules
            final_label, final_conf, rule = apply_postprocess_rules(raw_label, raw_conf, raw)

            match  = final_label == expected
            if not match:
                all_ok = False
            status = f"{GREEN}✓{RESET}" if match else f"{RED}✗{RESET}"

            # Hiển thị raw model output
            if rule:
                raw_info  = f"model={raw_label} conf={raw_conf:.3f}"
                rule_info = f"{CYAN}[{rule}]{RESET}"
                pred_str  = f"pred={final_label} conf={final_conf:.3f} {rule_info} {status}"
            else:
                raw_info = ""
                pred_str = f"pred={final_label} conf={final_conf:.3f} {status}"
        else:
            raw_info = ""
            pred_str = "(model không load)"

        print(f"\n  [{name}]")
        print(f"    raw   : {raw_str}")
        print(f"    scaled: {scaled_str}")
        if raw_info:
            print(f"    model : {raw_info}")
        print(f"    expect: {expected}  {pred_str}")

    return all_ok


def check_6_missing_fields(meta_features):
    print(f"\n{BOLD}=== CHECK 6: Xử lý field bị thiếu (missing/None/nan) ==={RESET}")
    test_cases = [None, "", "nan", "None", float("nan")]
    all_ok = True
    for v in test_cases:
        got = to_num(v)
        if got == 0.0:
            ok(f"to_num({v!r}) = 0.0 (đúng — fallback 0)")
        else:
            err(f"to_num({v!r}) = {got} (cần 0.0)")
            all_ok = False
    return all_ok


def main():
    ap = argparse.ArgumentParser(description="Feature pipeline validator cho MQTT IDS")
    ap.add_argument("--meta",    default="model_metadata_v2.json")
    ap.add_argument("--scaler",  default="scaler_v2.pkl")
    ap.add_argument("--encoder", default="label_encoder_v2.pkl")
    ap.add_argument("--model",   default="best_model_xgb_v2.pkl")
    args = ap.parse_args()

    print(f"\n{BOLD}{'='*55}")
    print("MQTT IDS — Feature Pipeline Validator")
    print(f"{'='*55}{RESET}")

    # Load artifacts
    try:
        with open(args.meta) as f:
            meta = json.load(f)
        meta_features = meta["feature_names"]
        info(f"Loaded metadata : {args.meta}")
        info(f"Classes         : {meta['classes']}")
        info(f"Train accuracy  : {meta['results']['XGBoost']['accuracy']}")
    except FileNotFoundError:
        err(f"Không tìm thấy {args.meta}")
        sys.exit(1)

    try:
        scaler = joblib.load(args.scaler)
        info(f"Loaded scaler   : {args.scaler}")
    except FileNotFoundError:
        err(f"Không tìm thấy {args.scaler}")
        sys.exit(1)

    try:
        le = joblib.load(args.encoder)
        info(f"Loaded encoder  : {args.encoder}  classes={list(le.classes_)}")
    except FileNotFoundError:
        err(f"Không tìm thấy {args.encoder}")
        sys.exit(1)

    model = None
    try:
        model = joblib.load(args.model)
        info(f"Loaded model    : {args.model}")
    except FileNotFoundError:
        warn(f"Không tìm thấy {args.model} — bỏ qua predict check")

    # Chạy checks
    results = {
        "1_feature_count":   check_1_feature_count(meta_features),
        "2_feature_names":   check_2_feature_names(meta_features),
        "3_hex_conversion":  check_3_hex_conversion(meta_features),
        "4_scaler":          check_4_scaler(scaler, meta_features),
        "5_real_samples":    check_5_real_samples(scaler, model, le, meta_features),
        "6_missing_fields":  check_6_missing_fields(meta_features),
    }

    # Summary
    print(f"\n{BOLD}=== SUMMARY ==={RESET}")
    all_pass = True
    for name, passed in results.items():
        if passed:
            ok(name)
        else:
            err(name)
            all_pass = False

    print()
    if all_pass:
        print(f"{GREEN}{BOLD}✓ Tất cả checks PASS — pipeline sẵn sàng cho production{RESET}")
    else:
        print(f"{RED}{BOLD}✗ Có lỗi — xem chi tiết ở trên{RESET}")
    print()
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
