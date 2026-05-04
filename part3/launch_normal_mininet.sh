#!/usr/bin/env bash
# launch_normal_mininet.sh — paste-helper for normal_traffic.py
# Outputs the 8 mininet CLI commands to launch each client from its OWN host
# namespace, so each gets its own source IP (10.0.0.1 .. 10.0.0.8) and the
# IDS sees realistic per-IP rates.
#
# Usage:
#   ./launch_normal_mininet.sh > /tmp/normal_cmds.txt
# then in mininet CLI: paste each line one at a time.

P3=/home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3
SCRIPT="$P3/normal_traffic.py"

cat <<EOF
# Paste each line below into mininet CLI (one at a time, & runs in background):
h1 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h1 --topic sensors/h1 --duration 120 &
h2 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h2 --topic sensors/h2 --duration 120 &
h3 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h3 --topic sensors/h3 --duration 120 &
h4 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h4 --topic sensors/h4 --duration 120 &
h5 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h5 --topic sensors/h5 --duration 120 &
h6 python3 ${SCRIPT} publisher  --broker 10.0.0.10 --id h6 --topic sensors/h6 --duration 120 &
h7 python3 ${SCRIPT} subscriber --broker 10.0.0.10 --id h7 --topic 'sensors/#' --duration 120 &
h8 python3 ${SCRIPT} subscriber --broker 10.0.0.10 --id h8 --topic 'sensors/#' --duration 120 &
# To stop early:
#   sh pkill -f normal_traffic.py
EOF
