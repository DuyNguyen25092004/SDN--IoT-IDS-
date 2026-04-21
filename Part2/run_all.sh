#!/usr/bin/env bash
# run_all.sh — Master Launch Script for SDN IoT IDS
# ==================================================

set -e

# ─── Configuration ────────────────────────────────────────────────────────────
RYU_ENV="$HOME/ryu-env-py39"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="${1:-$SCRIPT_DIR}"           # default: same dir as scripts
LOG_DIR="/tmp/sdn-iot-ids-logs"
BROKER_IP="10.0.0.10"
RYU_PORT=6633
RYU_REST_PORT=8080
IDS_API_PORT=5000
CAPTURE_IFACE="s1"                      # OVS bridge name = capture interface

# ─── Colors for output ────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; }
section() { echo -e "\n${BLUE}══ $* ══${NC}"; }

# ─── Cleanup on exit ─────────────────────────────────────────────────────────
cleanup() {
    section "Cleanup"
    warn "Stopping all components..."

    [ -f /tmp/ryu.pid ]     && kill "$(cat /tmp/ryu.pid)"     2>/dev/null; rm -f /tmp/ryu.pid
    [ -f /tmp/ids_api.pid ] && kill "$(cat /tmp/ids_api.pid)" 2>/dev/null; rm -f /tmp/ids_api.pid
    [ -f /tmp/capture.pid ] && kill "$(cat /tmp/capture.pid)" 2>/dev/null; rm -f /tmp/capture.pid

    sudo mn -c 2>/dev/null || true
    sudo pkill -f mosquitto 2>/dev/null || true

    info "Cleanup complete"
}
trap cleanup EXIT INT TERM

# ─── Pre-flight checks ────────────────────────────────────────────────────────
section "Pre-flight checks"

if [ ! -f "$RYU_ENV/bin/activate" ]; then
    error "Ryu venv not found at $RYU_ENV"
    exit 1
fi
source "$RYU_ENV/bin/activate"
info "Activated Python: $(python --version)"

mkdir -p "$LOG_DIR"
info "Logs → $LOG_DIR"

# ─── Clean up any previous run ────────────────────────────────────────────────
section "Cleaning previous state"
sudo mn -c 2>/dev/null || true
sudo pkill -f "ryu-manager" 2>/dev/null || true
sudo pkill -f "ids_api.py"  2>/dev/null || true
sudo pkill -f "traffic_capture.py" 2>/dev/null || true
sleep 1
info "Previous state cleared"

# ─── Step 1: Start Ryu controller ─────────────────────────────────────────────
section "Step 1: Starting Ryu Controller"
ryu-manager "$SCRIPT_DIR/ryu_controller.py" \
    --ofp-tcp-listen-port "$RYU_PORT" \
    --wsapi-port "$RYU_REST_PORT" \
    --observe-links \
    > "$LOG_DIR/ryu.log" 2>&1 &

echo $! > /tmp/ryu.pid
sleep 2
info "Ryu controller started (PID=$(cat /tmp/ryu.pid))"

# ─── Step 2: Start IDS API ────────────────────────────────────────────────────
section "Step 2: Starting IDS API (ML Model Server)"
python "$SCRIPT_DIR/ids_api.py" \
    --model    "$MODEL_DIR/best_model_xgb.pkl" \
    --scaler   "$MODEL_DIR/scaler.pkl" \
    --encoder  "$MODEL_DIR/label_encoder.pkl" \
    --feat-encoder "$MODEL_DIR/feature_encoders.pkl" \
    --port "$IDS_API_PORT" \
    > "$LOG_DIR/ids_api.log" 2>&1 &

echo $! > /tmp/ids_api.pid
sleep 3
info "IDS API running at http://127.0.0.1:$IDS_API_PORT"

# ─── Step 3: Start Traffic Capture (Delayed background job) ───────────────────
section "Step 3: Queuing Traffic Capture"
CAPTURE_ARGS="--iface $CAPTURE_IFACE --api http://127.0.0.1:$IDS_API_PORT"
CAPTURE_ARGS="$CAPTURE_ARGS --csv $LOG_DIR/capture_$(date +%Y%m%d_%H%M%S).csv"
CAPTURE_ARGS="$CAPTURE_ARGS --pcap $LOG_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap"

(
    # Wait until Mininet creates the s1 interface
    while ! ip link show "$CAPTURE_IFACE" >/dev/null 2>&1; do
        sleep 1
    done
    sudo ip link set "$CAPTURE_IFACE" up
    sleep 5 # Give it time to settle
    sudo "$RYU_ENV/bin/python" "$SCRIPT_DIR/traffic_capture.py" $CAPTURE_ARGS > "$LOG_DIR/capture.log" 2>&1 &
    echo $! > /tmp/capture.pid
    echo -e "\n${GREEN}[✓]${NC} Traffic capture automatically started on $CAPTURE_IFACE"
) &
info "Traffic capture is waiting for Mininet network to spin up..."

# ─── Step 4: Start Mininet topology ───────────────────────────────────────────
section "Step 4: Starting Mininet Topology"
info "Using topology.py directly (This will automatically start Mosquitto!)"
echo ""
info "Once the mininet> prompt appears, you can run:"
echo "  h1 $RYU_ENV/bin/python $SCRIPT_DIR/normal_traffic.py publisher --broker $BROKER_IP --id h1 --topic sensors/h1 &"
echo "  h7 $RYU_ENV/bin/python $SCRIPT_DIR/normal_traffic.py subscriber --broker $BROKER_IP --id h7 --topic sensors/# &"
echo "  sh curl -s http://127.0.0.1:5000/stats | python3 -m json.tool"
echo ""

# We run topology.py directly which contains the custom run() method!
sudo python3 "$SCRIPT_DIR/topology.py"