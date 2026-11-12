# Dynamic Host Blocking System (TCP + SDN + Mininet + OS-Ken)

Detects abnormal TCP connection rates per source IP and dynamically blocks the host with an OpenFlow drop rule.

```
h1,h2 (normal) \
h3 (attacker)   -- s1 (OVS, OpenFlow 1.3) -- h4 (TCP server 10.0.0.4:5000)
                        |
                 OS-Ken controller: counts SYNs per IP -> threshold -> blocklist -> drop flow -> logs
```

## How it works
1. Every new TCP connection's first packet (SYN) has no matching flow, so it reaches the controller (forwarding flows are per-connection: 5-tuple, 5 s idle timeout).
2. The controller keeps a sliding 10 s window of SYNs per source IP (`detection_engine.py`).
3. More than 20 SYNs in 10 s -> host is flagged, added to `blocklist.py`, and a priority-100 drop rule (`ipv4_src=<ip>, tcp`) is pushed to the switch with a 60 s hard timeout (auto-unblock).
4. Events go to `logs/events.csv`; flow stats (dropped packet counts) every 5 s to `logs/flow_stats.csv`; blocklist to `logs/blocklist.json`.

Thresholds are experimental values. Change with env vars: `DHB_THRESHOLD`, `DHB_WINDOW`, `DHB_BLOCK_TIMEOUT`, `DHB_ENABLED=0` (baseline, detect only).

## Setup (Ubuntu VM)
```bash
sudo apt update && sudo apt install -y mininet openvswitch-switch python3-pip
pip3 install -r requirements.txt     # if osken-manager errors: pip3 install setuptools==58.2.0
```

## Run (from repo root)
```bash
# Terminal 1 - controller
osken-manager controller/sdn_controller.py

# Terminal 2 - interactive demo
sudo -E python3 network/topology.py
mininet> h1 python3 socket_app/traffic_generator.py --mode normal
mininet> h3 python3 socket_app/traffic_generator.py --mode abnormal     # gets blocked
mininet> h3 python3 socket_app/client.py                                # fails
mininet> h1 python3 socket_app/client.py                                # still works
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1                      # shows drop rule
```

## Automated tests + performance
```bash
osken-manager controller/sdn_controller.py                 # terminal 1
sudo -E python3 evaluation/test_cases.py --mode blocking --recovery   # terminal 2
# stop controller, restart with baseline:
DHB_ENABLED=0 osken-manager controller/sdn_controller.py
sudo -E python3 evaluation/test_cases.py --mode baseline
python3 evaluation/performance.py     # -> evaluation/results/comparison.png, summary.md
```
Test cases: TC1 normal traffic, TC2 abnormal h3, TC3 blocking verification + flow table, TC4 legit client under attack (baseline vs blocking), TC5 server failure/recovery, TC6 auto-unblock after timeout.

## Team split
| Member | Module |
|---|---|
| 1 | `socket_app/` TCP server, client, traffic generator |
| 2 | `controller/` OS-Ken app, detection, blocklist, flow stats |
| 3 | `network/` topology, `evaluation/` tests and performance |
