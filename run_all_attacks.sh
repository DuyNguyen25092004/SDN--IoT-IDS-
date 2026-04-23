#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  run_all_attacks.sh — Chạy toàn bộ kịch bản tấn công       ║
# ║  Người 3 — Security Tester                                   ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Sử dụng:
#   chmod +x run_all_attacks.sh
#   ./run_all_attacks.sh <BROKER_IP> [BROKER_PORT]
#
# Ví dụ trong Mininet (chạy từ host h1):
#   ./run_all_attacks.sh 10.0.0.100 1883

BROKER_IP="${1:-10.0.0.100}"
BROKER_PORT="${2:-1883}"
LOG_DIR="attack_logs_$(date +%Y%m%d_%H%M%S)"

echo "======================================================"
echo "  IoT IDS — ATTACK TEST SUITE"
echo "  Broker : $BROKER_IP:$BROKER_PORT"
echo "  Logs   : $LOG_DIR/"
echo "======================================================"

mkdir -p "$LOG_DIR"

# ── Kiểm tra dependency ────────────────────────────────────────
echo "[*] Kiểm tra dependencies..."
python3 -c "import paho.mqtt.client" 2>/dev/null || {
    echo "[!] paho-mqtt chưa cài. Đang cài..."
    pip3 install paho-mqtt --quiet
}

# ── Hàm tiện ích ──────────────────────────────────────────────
run_attack() {
    local name="$1"
    local cmd="$2"
    echo ""
    echo "------------------------------------------------------"
    echo "  CHẠY: $name"
    echo "  CMD : $cmd"
    echo "------------------------------------------------------"
    eval "$cmd" 2>&1 | tee "$LOG_DIR/${name}.log"
    echo "  [OK] $name xong → $LOG_DIR/${name}.log"
}

# ══════════════════════════════════════════════════════════════
# PHASE 0: Thu thập traffic BÌNH THƯỜNG (baseline)
# ══════════════════════════════════════════════════════════════
echo ""
echo "[Phase 0] Thu thập normal traffic baseline (30 giây)..."
python3 normal_traffic.py \
    --host "$BROKER_IP" --port "$BROKER_PORT" \
    --duration 30 --devices 5 \
    2>&1 | tee "$LOG_DIR/phase0_normal.log"
echo "  [OK] Normal traffic xong"

sleep 2

# ══════════════════════════════════════════════════════════════
# PHASE 1: Attack 1 — MQTT Flood
# ══════════════════════════════════════════════════════════════
run_attack "attack1_flood" \
    "python3 attack1_mqtt_flood.py \
        --host $BROKER_IP --port $BROKER_PORT \
        --threads 5 --count 1000 --qos 0"
cp -f attack1_flood_log.csv "$LOG_DIR/" 2>/dev/null

sleep 3

# ══════════════════════════════════════════════════════════════
# PHASE 2: Attack 2 — C2 Malware (chạy bot trước, server sau)
# ══════════════════════════════════════════════════════════════
echo ""
echo "------------------------------------------------------"
echo "  CHẠY: attack2_c2_malware (bot + server)"
echo "------------------------------------------------------"
# Chạy bot ngầm
python3 attack2_c2_malware.py --mode bot --host "$BROKER_IP" --port "$BROKER_PORT" \
    > "$LOG_DIR/attack2_bot.log" 2>&1 &
BOT_PID=$!
sleep 1
# Chạy C2 server
python3 attack2_c2_malware.py --mode server --host "$BROKER_IP" --port "$BROKER_PORT" \
    2>&1 | tee "$LOG_DIR/attack2_server.log"
kill $BOT_PID 2>/dev/null
cp -f attack2_c2_server_log.json "$LOG_DIR/" 2>/dev/null
echo "  [OK] Attack 2 xong"

sleep 3

# ══════════════════════════════════════════════════════════════
# PHASE 3: Attack 3 — Brute Force CONNECT
# ══════════════════════════════════════════════════════════════
run_attack "attack3_bruteforce" \
    "python3 attack3_brute_force.py \
        --host $BROKER_IP --port $BROKER_PORT \
        --delay 0.1 --max 50"
cp -f attack3_bruteforce_log.csv "$LOG_DIR/" 2>/dev/null

sleep 3

# ══════════════════════════════════════════════════════════════
# PHASE 4: Attack 4 — Port Scan
# ══════════════════════════════════════════════════════════════
# Lấy subnet từ IP broker
SUBNET=$(echo "$BROKER_IP" | cut -d'.' -f1-3)
run_attack "attack4_port_scan" \
    "python3 attack4_port_scan.py \
        --subnet $SUBNET --start 1 --end 10 \
        --threads 15 --timeout 0.3 \
        --mqtt-broker $BROKER_IP"
cp -f attack4_scan_results.json "$LOG_DIR/" 2>/dev/null

sleep 3

# ══════════════════════════════════════════════════════════════
# PHASE 5: Attack 5 — Slow Drip Exfiltration
# ══════════════════════════════════════════════════════════════
run_attack "attack5_slow_drip" \
    "python3 attack5_slow_drip.py \
        --host $BROKER_IP --port $BROKER_PORT \
        --topic home/sensor/temp \
        --rate 0.3 --chunk-size 32"
cp -f attack5_slowdrip_log.json "$LOG_DIR/" 2>/dev/null

sleep 2

# ══════════════════════════════════════════════════════════════
# PHASE 6: Evaluation
# ══════════════════════════════════════════════════════════════
echo ""
echo "------------------------------------------------------"
echo "  CHẠY: Evaluation (demo mode)"
echo "------------------------------------------------------"
python3 evaluation.py --demo --outdir "$LOG_DIR/eval"
echo "  [OK] Evaluation xong → $LOG_DIR/eval/"

# ══════════════════════════════════════════════════════════════
# TỔNG KẾT
# ══════════════════════════════════════════════════════════════
echo ""
echo "======================================================"
echo "  TẤT CẢ ATTACK ĐÃ CHẠY XONG"
echo "======================================================"
echo "  Logs:"
ls -lh "$LOG_DIR/"
echo ""
echo "  Để xem evaluation:"
echo "  ls $LOG_DIR/eval/"
echo "======================================================"
