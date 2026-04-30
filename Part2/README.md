# SDN IoT IDS — Run Guide

Verified 4-terminal demo procedure for Mininet + Ryu + XGBoost IDS.

---

## Prerequisites

System-wide dependencies (needed inside Mininet hosts):

```bash
sudo pip3 install paho-mqtt --break-system-packages
```

Venv dependencies (for IDS API and capture):

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate
pip install flask joblib numpy requests xgboost scikit-learn
```

The model artifacts (`best_model_xgb_v2.pkl`, `scaler_v2.pkl`, `label_encoder_v2.pkl`) live in `Part2/` and are auto-loaded by `ids_api.py` from its CWD.

---

## Terminal Layout

| Terminal | Role |
|----------|------|
| **T1** | Ryu SDN Controller |
| **T2** | IDS API (XGBoost classifier) |
| **T3** | Traffic Capture (tshark → API) — start **after** T4 |
| **T4** | Mininet topology + attack scripts |
| **T5** *(optional)* | Helper terminal for `curl` unblock/whitelist between attacks |

> **Critical order:** T1 → T2 → T4 → T3. T3 attaches to switch `s1`, which only exists after T4 starts the topology.

---

## T0 — Clean slate (run before each fresh demo)

In any terminal:

```bash
sudo -v   # cache sudo password once
sudo sh -c '
  mn -c >/dev/null 2>&1
  killall -9 mosquitto 2>/dev/null
  pkill -9 -f "ryu-manager"        2>/dev/null
  pkill -9 -f "ids_api.py"         2>/dev/null
  pkill -9 -f "traffic_capture.py" 2>/dev/null
  pkill -9 -f "topology.py"        2>/dev/null
  pkill -9 -f "ovs-testcontroller" 2>/dev/null
  ip link show s1 >/dev/null 2>&1 && ovs-vsctl del-br s1 2>/dev/null
  ip link del s1-eth1 2>/dev/null
  ip link del s1-eth2 2>/dev/null
  rm -f /tmp/capture.csv /tmp/mosquitto.conf
  sleep 1
  echo CLEAN
'
mkdir -p /tmp/part2_demo
```

> ⚠ **Never use `pkill -f mosquitto`** — that pattern matches any shell whose argv contains the word `mosquitto` (e.g. the very shell that runs the command), and it will kill your terminal. Use `killall -9 mosquitto` instead, which matches process **name** only.

---

## T1 — Ryu Controller

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source ~/ryu-env-py39/bin/activate
ryu-manager ryu_controller.py --observe-links --wsapi-port 8080 \
    2>&1 | tee /tmp/part2_demo/T1_ryu.log
```

Wait for:
```
WSGIServer: starting up on http://0.0.0.0:8080
```
(`Switch connected: dpid=0000000000000001` will appear once T4 starts the topology.)

---

## T2 — IDS API

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate
IDS_BLOCK_VOTES=10 IDS_BLOCK_CONF=0.30 IDS_VOTE_WINDOW=30 \
RYU_URL=http://127.0.0.1:8080/ids/block \
python3 ids_api.py \
    2>&1 | tee /tmp/part2_demo/T2_ids.log
```

> Use the `venv` virtualenv (NOT `ryu-env-py39`). The `*_v2.pkl` artifacts auto-load from CWD.

Wait for:
```
* Running on http://127.0.0.1:5000
```

Tunable env vars:
- `IDS_BLOCK_VOTES` — attack votes within the window required to block (default 10).
- `IDS_BLOCK_CONF`  — minimum classifier confidence required to block (default 0.30).
- `IDS_VOTE_WINDOW` — vote window size, in classifications (default 30).
- `RYU_URL`         — Ryu block endpoint.

---

## T4 — Mininet (start before T3)

> ⚠ **Do NOT pipe the sudo password into `topology.py`.** A command like
> `echo 250704 | sudo -S python3 topology.py` leaves stdin attached to the pipe; the leftover bytes are read by Mininet's CLI as `*** Unknown command: 250704` and the topology immediately tears itself down.
>
> Cache sudo first, then launch with a real TTY.

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
sudo -v                       # cache credential once (~15 min)
sudo python3 topology.py      # NO pipe, NO -S
```

You should land at the `mininet>` prompt with hosts `h1–h8`, `hbroker`, `hattacker`.

### Restart the broker on 0.0.0.0

`topology.py` auto-starts mosquitto bound to `127.0.0.1` only — attackers can't reach it. Replace it with a 0.0.0.0 listener:

```
mininet> hbroker killall -9 mosquitto
mininet> hbroker bash -c "echo -e 'listener 1883 0.0.0.0\nallow_anonymous true' > /tmp/mosquitto.conf && mosquitto -d -c /tmp/mosquitto.conf"
mininet> hbroker netstat -tlnp | grep 1883
```

The last line should show `0.0.0.0:1883`. Sanity test:

```
mininet> hattacker mosquitto_pub -h 10.0.0.10 -t test -m hello
```

---

## T3 — Traffic Capture (start AFTER T4 reaches `mininet>`)

```bash
cd ~/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/Part2
source venv/bin/activate

# Bring up the OVS internal port (s1 only exists once T4 is running)
sudo ip link set s1 up

# Set up OVS mirror — copies all switch traffic to s1 for tshark
sudo ovs-vsctl -- set Bridge s1 mirrors=@m \
    -- --id=@s1 get Port s1 \
    -- --id=@m create Mirror name=ids-mirror \
        select-all=true \
        output-port=@s1 \
    || true   # OK if mirror already exists

# Start capture
sudo -E python3 traffic_capture.py \
    --iface s1 \
    --api http://127.0.0.1:5000 \
    --csv capture.csv \
    2>&1 | tee /tmp/part2_demo/T3_capture.log
```

You should soon see `[DBG-VEC #N]` and `[DBG-API #N]` lines as packets flow.

---

## T5 — Optional helper terminal

Open a 5th terminal and define a quick unblock helper:

```bash
unblock99() {
  curl -s -X POST http://127.0.0.1:8080/ids/unblock \
       -H 'Content-Type: application/json' \
       -d '{"ip":"10.0.0.99"}'  ; echo
  curl -s -X POST http://127.0.0.1:5000/whitelist/remove \
       -H 'Content-Type: application/json' \
       -d '{"ip":"10.0.0.99"}'  ; echo
}
```

Run `unblock99` between attacks to clear both the OVS flow rule AND any leftover whitelist entry.

---

## Running the Attacks (issue at the `mininet>` prompt)

> Project base path inside commands: `/home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-`

### Attack 1 — MQTT Flood (DoS)

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack1_mqtt_flood.py --host 10.0.0.10 --port 1883 --threads 10 --iter 5000
```

Expected: `flood` / `malformed` at 93–100% confidence → BLOCKED.
Then in T5: `unblock99`.

> The flag is `--iter`, not `--count`.

---

### Attack 2 — C2 Malware

```
mininet> hattacker bash -c "python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack2_c2_malware.py --mode server --host 10.0.0.10 &"
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack2_c2_malware.py --mode bot --host 10.0.0.10
```

Expected: `malformed` / `c2_malware` / `dos` → BLOCKED.
Then in T5: `unblock99`.

---

### Attack 3 — Brute Force

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack3_brute_force.py --host 10.0.0.10 --delay 0.1 --force
```

Expected: refined `brute_force` at 67–84% confidence → BLOCKED.
Then in T5: `unblock99`.

> `--force` skips the anonymous-broker pre-check, which would otherwise abort the attack against an open broker.

---

### Attack 4 — Port Scan

```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack4_port_scan.py --subnet 10.0.0 --start 1 --end 10 --mqtt-broker 10.0.0.10
```

Expected: `port_scan` / `malformed` at ~100% confidence → BLOCKED.
Then in T5: `unblock99`.

---

### Attack 5 — Slow Drip Exfiltration

Slow drip mimics legitimate sensor traffic. Choose ONE of two modes:

#### (a) Demo mode — show full slow_drip detection (whitelisted, NOT blocked)

The model often misclassifies the very first connect/publish bursts as `flood`/`malformed`, which would block `10.0.0.99` before the slow_drip pattern can build up. Whitelisting lets the IDS keep classifying every packet (so you'll see `slow_drip` accumulating in `/stats`) while suppressing the Ryu block.

In **T5**, before the attack:
```bash
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}' ; echo
curl -s -X POST http://127.0.0.1:5000/whitelist/add \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}' ; echo
```

In **T4**:
```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack5_slow_drip.py --host 10.0.0.10 --port 1883 --topic sensor/data --rate 0.5 --chunk-size 50
```

After it finishes, in **T5**:
```bash
curl -s -X POST http://127.0.0.1:5000/whitelist/remove \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}' ; echo
```

Expected: `by_label.slow_drip` increases in `/stats`. T2 logs show
`ATTACK [slow_drip] … src=10.0.0.99` followed by
`-> Skip block: 10.0.0.99 whitelisted` (no Ryu block — by design).

#### (b) Production mode — actually block slow_drip (no whitelist)

In **T5**:
```bash
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}' ; echo
```

In **T4**:
```
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack5_slow_drip.py --host 10.0.0.10 --port 1883 --topic sensor/data --rate 0.5 --chunk-size 50
```

T3 will log `⚠ ATTACK BLOCKED [slow_drip] …` and T2 will log `BLOCKED src=10.0.0.99 label=slow_drip`. The attack will terminate early once Ryu installs the drop rule.

---

## Unblocking Between Attacks

After each attack, hattacker (`10.0.0.99`) is blocked at the SDN layer. Clear it before the next run:

```bash
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
     -H 'Content-Type: application/json' \
     -d '{"ip":"10.0.0.99"}'
```

Verify no flow rule remains:
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 10.0.0.99
# (no output expected)
```

If you ran Attack 5 mode (a), also remove from the whitelist:
```bash
curl -s -X POST http://127.0.0.1:5000/whitelist/remove \
     -H 'Content-Type: application/json' \
     -d '{"ip":"10.0.0.99"}'
```

---

## Broker Restart (if connection refused)

If attacks fail with `Connection refused` / `TimeoutError`, the broker probably died:

```
mininet> hbroker killall -9 mosquitto
mininet> hbroker bash -c "echo -e 'listener 1883 0.0.0.0\nallow_anonymous true' > /tmp/mosquitto.conf && mosquitto -d -c /tmp/mosquitto.conf"
mininet> hbroker netstat -tlnp | grep 1883
```

> Again: do **not** use `pkill -f mosquitto` from within Mininet either — `killall -9 mosquitto` only.

---

## Monitoring & Verification

```bash
# Detection statistics (per-label counters)
curl -s http://127.0.0.1:5000/stats     | python3 -m json.tool

# Health + loaded model info
curl -s http://127.0.0.1:5000/health    | python3 -m json.tool

# Current whitelist
curl -s http://127.0.0.1:5000/whitelist | python3 -m json.tool

# Active Ryu block rules
curl -s http://127.0.0.1:8080/ids/rules | python3 -m json.tool

# Live OpenFlow drop rules on s1
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep -E "drop|10.0.0.99"

# Quick log scan
grep -E "BLOCKED|ATTACK \[" /tmp/part2_demo/T2_ids.log | tail -30
```

---

## Tear down

```
mininet> exit
```

Then in any terminal:

```bash
sudo sh -c '
  mn -c >/dev/null 2>&1
  killall -9 mosquitto 2>/dev/null
  pkill -9 -f "ryu-manager|ids_api.py|traffic_capture.py" 2>/dev/null
  ovs-vsctl del-br s1 2>/dev/null
  echo DONE
'
```

---

## Common Gotchas (verified)

| Symptom | Cause | Fix |
|---|---|---|
| `*** Unknown command: 250704` then immediate Mininet shutdown | `echo PASS \| sudo -S python3 topology.py` leaves stdin tied to the pipe → Mininet CLI reads leftover bytes. | `sudo -v` first, then `sudo python3 topology.py` (no pipe). |
| Attacker can't reach broker | `topology.py` starts mosquitto on `127.0.0.1` only. | `hbroker killall -9 mosquitto` then re-launch with `listener 1883 0.0.0.0`. |
| Terminal dies when restarting broker | `pkill -f mosquitto` matches the shell argv that contains the word "mosquitto". | Use `killall -9 mosquitto`. |
| T3 capture says `Cannot find device s1` | Capture started before T4 created the bridge. | Always start T4 (Mininet) before T3 (capture). |
| Attack 3 exits without sending anything | Brute-force script's pre-check rejects anonymous brokers. | Add `--force`. |
| Attack 5 blocked before any slow_drip pattern shows | Early packets misclassified as `flood`/`malformed`, IDS blocks. | Whitelist `10.0.0.99` for the demo, OR accept that "production mode" terminates the attack early (which is correct behaviour). |
| Repeated attacks blocked instantly | Previous run's drop rule still installed. | `unblock99` between every attack. |

---

## Host IP Reference

| Host | IP |
|------|----|
| h1–h8 | 10.0.0.1 – 10.0.0.8 |
| hbroker | 10.0.0.10 |
| hattacker | 10.0.0.99 |
