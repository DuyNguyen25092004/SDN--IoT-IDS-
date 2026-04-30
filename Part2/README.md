# SDN IoT IDS — Run Guide

4-terminal demo. The exact commands below are the ones that worked in
the last successful end-to-end run. Use them in order.

---

## 0. Prerequisites

- Linux + sudo (password cached once with `sudo -v` **per terminal** — Ryu calls `ovs-vsctl` synchronously and will block on a password prompt)
- Python 3.9 venv for **Ryu** at `~/ryu-env-py39/`
- Python 3.12 venv for **IDS** at `Part2/venv/`
- `mininet`, `openvswitch`, `mosquitto`, `tshark`

### Optional: passwordless sudo helper for unattended runs

Mininet's CLI dies if you pipe a password into `sudo -S` (the password
becomes Mininet's first command). The cleanest workaround is a tiny
askpass helper:

```bash
cat >/tmp/askpass.sh <<'EOF'
#!/bin/sh
echo YOUR_SUDO_PASSWORD
EOF
chmod +x /tmp/askpass.sh
```

Then each terminal that needs sudo (T1 Ryu, T3 capture, T4 Mininet)
caches credentials with:

```bash
SUDO_ASKPASS=/tmp/askpass.sh sudo -A -v
```

---

## 1. Clean slate (run once before each demo)

Any shell:

```bash
sudo -v
sudo sh -c 'mn -c >/dev/null 2>&1; killall -9 mosquitto ryu-manager 2>/dev/null; \
            pkill -9 -f "ids_api.py|traffic_capture.py|topology.py" 2>/dev/null; \
            ovs-vsctl --if-exists del-br s1; echo CLEAN'
mkdir -p /tmp/part2_demo
```

---

## 2. Terminal layout

| # | Terminal      | What it runs                       |
|---|---------------|------------------------------------|
| 1 | T1 — Ryu      | SDN controller (port 8080)         |
| 2 | T2 — IDS      | Flask ML API   (port 5000)         |
| 3 | T3 — Capture  | tshark → IDS API (after T4 is up)  |
| 4 | T4 — Mininet  | topology + mosquitto broker        |

Use any spare shell for `curl` (`/ids/unblock`, `/reset`, …).

---

## 3. T1 — Ryu controller

```bash
source ~/ryu-env-py39/bin/activate
cd Part2          # skip if already in Part2
# IMPORTANT: cache sudo in *this* shell first — _install_mirror_rule()
# in ryu_controller.py calls `sudo ovs-vsctl` synchronously, and a
# password prompt blocks the eventlet greenthread → no flows installed.
SUDO_ASKPASS=/tmp/askpass.sh sudo -A -v
ryu-manager ryu_controller.py --observe-links --wsapi-port 8080 \
    2>&1 | tee /tmp/part2_demo/T1_ryu.log
```

Wait for: `dpid=0000000000000001`. The line `ovs-vsctl: '11' is not a
valid UUID` / `OVS mirror setup failed` printed by the controller is
harmless — the real mirror is created from T3.

---

## 4. T2 — IDS API

```bash
cd Part2
IDS_BLOCK_VOTES=10 IDS_BLOCK_CONF=0.30 IDS_VOTE_WINDOW=30 \
RYU_URL=http://127.0.0.1:8080/ids/block \
./venv/bin/python3 ids_api.py 2>&1 | tee /tmp/part2_demo/T2_ids.log
```

Health check (any spare shell):
```bash
curl -s http://127.0.0.1:5000/health
```

---

## 5. T4 — Mininet (start before T3)

From the repo root (or `Part2/`):

```bash
cd Part2          # skip if already in Part2
SUDO_ASKPASS=/tmp/askpass.sh sudo -A -v   # cache creds *without* poisoning stdin
SUDO_ASKPASS=/tmp/askpass.sh sudo -A python3 topology.py
```

> Do NOT use `echo PASS | sudo -S python3 topology.py` — `sudo`
> consumes stdin and Mininet's CLI immediately exits.

Wait until the prompt becomes `mininet>`. The default `mosquitto`
started by `topology.py` binds to `127.0.0.1` only, so attackers from
`10.0.0.99` get TCP `RST`. Drop a tiny config that listens on
`0.0.0.0`, restart the broker inside `hbroker`'s netns, and sanity-
check connectivity:

From any spare shell (once, before this section):
```bash
cat >/tmp/mosq_open.conf <<'EOF'
listener 1883 0.0.0.0
allow_anonymous true
EOF
```

Then at the `mininet>` prompt:
```text
mininet> hbroker pkill -f mosquitto; sleep 0.5
mininet> hbroker mosquitto -c /tmp/mosq_open.conf -d
mininet> hattacker ping -c1 10.0.0.10
```

Leave this terminal at the `mininet>` prompt — you will run all
attacks from here.

---

## 6. T3 — Traffic capture

**Important:** open this in a NEW shell (not the Mininet one). The OVS
mirror has to be wired up before tshark can see anything; without it,
tshark exits with `Captured: 0 packets`.

```bash
cd Part2          # skip if already in Part2
SUDO_ASKPASS=/tmp/askpass.sh sudo -A -v   # cache creds for this terminal

# 1) Bring s1 up and create the mirror that copies every packet to s1 itself
sudo ip link set s1 up
sudo ovs-vsctl -- set Bridge s1 mirrors=@m \
               -- --id=@s1 get Port s1 \
               -- --id=@m create Mirror name=ids-mirror \
                  select-all=true output-port=@s1

# 2) Start the capture (uses the IDS venv so paho/etc. are present)
sudo -E ./venv/bin/python3 traffic_capture.py \
    --iface s1 --api http://127.0.0.1:5000 \
    --csv /tmp/part2_demo/capture.csv 2>&1 | tee /tmp/part2_demo/T3_capture.log
```

What you will see (only two kinds of lines):

```
Stats: captured=… sent=… errors=… rate=… pkt/s
⚠ ATTACK BLOCKED [<label>] conf=0.xx src=10.0.0.99
```

All `[DBG-*]` debug lines are commented out; uncomment them in
`traffic_capture.py` only when troubleshooting.

> If `tshark` exits immediately with 0 packets, the mirror isn't set
> up. Re-run the two `ovs-vsctl` lines above.

---

## 7. Attacks (run from T4 / Mininet CLI)

> **Note:** the Mininet CLI does **not** expand shell variables — you
> must paste the full literal path. The path used below is:
> `/home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3`
> (note the escaped space in `Final\ Term`). Adjust if your repo lives
> elsewhere.

Between attacks, clear state from any spare shell:
```bash
curl -s -X POST http://127.0.0.1:8080/ids/unblock \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99"}'
curl -s -X POST http://127.0.0.1:5000/reset \
     -H 'Content-Type: application/json' -d '{"ip":"10.0.0.99","stats":true}'
```

### Attack 1 — Flood
```text
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack1_mqtt_flood.py --host 10.0.0.10 --iter 5000 --threads 10
```
Expected: `⚠ ATTACK BLOCKED [flood] conf≈1.00`

> Note: `attack1_mqtt_flood.py` uses `--host` (not `--target`).
> `attack_dos.py` and `attack_malformed.py` use `--target`.

> The flood is intentionally heavy — kill it after detection if needed:
> `sudo pkill -9 -f attack1_mqtt_flood.py`

### Attack 3 — Brute force CONNECT
```text
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack3_brute_force.py --host 10.0.0.10 --port 1883 --delay 0.5 --max 25 --force
```
Expected: `⚠ ATTACK BLOCKED [brute_force] conf≈0.94`

### Attack 5 — Slow drip exfiltration
```text
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack5_slow_drip.py --host 10.0.0.10 --port 1883 --topic sensor/data --rate 0.5 --chunk-size 8
```
Expected: `⚠ ATTACK BLOCKED [slow_drip] conf≈0.98`
(Use `--chunk-size 8`. Larger chunk sizes generate fewer publishes and
fail to reach the 10-vote threshold inside the 30 s window.)

> **Important:** Attack 5 keeps publishing for ~90 s (50 chunks). Kill
> it before issuing the next attack, otherwise its log spam corrupts
> the next Mininet command line:
> `mininet> hattacker pkill -9 -f attack5_slow_drip`

### Attack 6 — DoS flood
```text
mininet> hattacker timeout 12 python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack_dos.py --target 10.0.0.10 --rate 200 --threads 8
```
Expected: `⚠ ATTACK BLOCKED [brute_force] conf≈0.98`
(`attack_dos.py` opens many short TCP CONNECTs in parallel without
ever publishing, so the refinement rule rewrites the model's prediction
to `brute_force`. The block itself fires correctly; the label is just
the closest behavioural match.)

### Attack 7 — Malformed packets
```text
mininet> hattacker python3 /home/thevien257/Desktop/term/SDN/Final\ Term/Project/SDN--IoT-IDS-/part3/attack_malformed.py --target 10.0.0.10 --port 1883 --rate 50 --duration 15
```
Expected: `⚠ ATTACK BLOCKED [brute_force] conf≈0.98`
(Same caveat as Attack 6 — malformed packets establish the TCP
connection but never produce a valid PUBLISH, so the refiner labels
the burst `brute_force`. The block itself triggers as expected.)

> **Skipped:** Attack 2 (C2 malware) and Attack 4 (port scan) — labels
> are not reliable on this stack (per-packet model can't see C2 timing,
> port scan is filtered out by the MQTT capture).

---

## 8. Useful REST endpoints

| Method | URL                                  | Purpose                                  |
|--------|--------------------------------------|------------------------------------------|
| GET    | `http://127.0.0.1:5000/health`       | model + uptime                           |
| GET    | `http://127.0.0.1:5000/stats`        | counters, config, blocked events         |
| POST   | `http://127.0.0.1:5000/reset`        | clear vote-window + behavior history     |
| GET    | `http://127.0.0.1:5000/whitelist`    | list whitelisted IPs                     |
| GET    | `http://127.0.0.1:8080/ids/rules`    | active OF block rules                    |
| POST   | `http://127.0.0.1:8080/ids/unblock`  | remove OF block for an IP                |

---

## 9. Tear down

In T4:
```text
mininet> exit
```

Then any shell:
```bash
sudo sh -c 'mn -c >/dev/null 2>&1; killall -9 mosquitto; \
            pkill -9 -f "ryu-manager|ids_api.py|traffic_capture.py"; \
            ovs-vsctl --if-exists del-br s1; echo DONE'
```

The OVS mirror disappears with the bridge — no separate cleanup
needed. If you keep the bridge around for some reason, drop just the
mirror with:
```bash
sudo ovs-vsctl clear Bridge s1 mirrors
```

---

## 10. Common gotchas

- **Don't pipe `sudo -S` into `topology.py`** — it poisons Mininet's
  stdin and produces `*** Unknown command: <password>`. Use `sudo -v`
  (or `SUDO_ASKPASS=… sudo -A …`) first, then `sudo python3 topology.py`.
- **Cache sudo in T1 (Ryu) too.** `_install_mirror_rule()` runs
  `sudo ovs-vsctl` synchronously; an unprimed sudo prompt freezes the
  greenthread and the table-miss flow is never installed → `pingall`
  is all `X` and `dump-flows s1` is empty.
- **Default `mosquitto` binds to `127.0.0.1`.** From inside `hbroker`
  this means attackers in another netns get TCP RST. Always start the
  broker with `mosquitto -c /tmp/mosq_open.conf -d`.
- **Don't `pkill -f mosquitto`** from inside the same shell that ran
  it — `pkill` matches its own argv. Use `killall -9 mosquitto`.
- **Vote-window persists per-IP.** Hit `/reset` between attacks if you
  want a clean label trace, otherwise residue from the previous attack
  can trigger an early block.
- **Kill long-running attacks before starting the next one.** Attack 5
  prints chunk progress for ~90 s; if it's still running when you type
  the next `mininet>` command, the log output mangles your input
  (e.g. `hattacker` becomes `attacker` or `hpython3`).

---

## Host IP reference

| Host       | IP          | Role        |
|------------|-------------|-------------|
| h1–h8      | 10.0.0.1–8  | sensors     |
| hbroker    | 10.0.0.10   | MQTT broker |
| hattacker  | 10.0.0.99   | attacker    |
