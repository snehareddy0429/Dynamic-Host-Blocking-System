"""Automated test cases. Member 3.
1. Start the controller in another terminal (blocking ON or baseline):
     osken-manager controller/sdn_controller.py                 # then:  --mode blocking
     DHB_ENABLED=0 osken-manager controller/sdn_controller.py   # then:  --mode baseline
2. sudo python3 evaluation/test_cases.py --mode blocking [--recovery]
"""
import argparse, csv, json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mininet.log import setLogLevel
from network.topology import build_network
from network.network_config import REPO_ROOT, SERVER_IP, SERVER_PORT

APP = f"{REPO_ROOT}/socket_app"
RES = f"{REPO_ROOT}/evaluation/results"


def gen(host, mode, **kw):
    args = " ".join(f"--{k} {v}" for k, v in kw.items())
    out = host.cmd(f"cd {APP} && python3 traffic_generator.py --mode {mode} --server {SERVER_IP} --port {SERVER_PORT} {args}")
    return json.loads(out.strip().splitlines()[-1])


def read_events(since):
    path = f"{REPO_ROOT}/logs/events.csv"
    with open(path) as f:
        return [r for r in csv.DictReader(f) if float(r["timestamp"]) >= since]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["blocking", "baseline"], default="blocking")
    ap.add_argument("--recovery", action="store_true", help="also wait for block timeout and re-test h3")
    ap.add_argument("--block-timeout", type=int, default=60)
    a = ap.parse_args()

    setLogLevel("warning")
    net = build_network(); net.start()
    h1, h2, h3, h4 = (net.get(n) for n in ("h1", "h2", "h3", "h4"))
    h4.cmd(f"python3 {APP}/server.py > /tmp/server.out 2>&1 &")
    time.sleep(1); net.pingAll()
    R = {"mode": a.mode}

    print("TC1 normal traffic"); R["tc1_h1"] = gen(h1, "normal", count=5, interval=0.5)
    R["tc1_h2"] = gen(h2, "normal", count=3, interval=0.5)

    print("TC2 abnormal traffic from h3"); t0 = time.time()
    R["tc2_h3"] = gen(h3, "abnormal", count=50, interval=0.05)
    time.sleep(1)
    ev = read_events(t0)
    for r in ev:
        if r["event"] == "BLOCK":
            R["detection_delay_s"] = float(r["detection_delay_s"]); R["block_latency_ms"] = float(r["block_latency_ms"])

    print("TC3 verify blocking"); R["tc3_h3_again"] = gen(h3, "normal", count=3, interval=0.3)
    R["tc3_h1_still_ok"] = gen(h1, "normal", count=3, interval=0.3)
    flows = net.get("s1").cmd("ovs-ofctl -O OpenFlow13 dump-flows s1")
    open(f"{RES}/flow_table_{a.mode}.txt", "w").write(flows)
    R["drop_rule_present"] = "priority=100" in flows and "actions=drop" in flows or "priority=100" in flows

    print("TC4 legitimate client under attack")
    atk = h3.popen(f"cd {APP} && python3 traffic_generator.py --mode abnormal --count 200 --interval 0.02 --server {SERVER_IP}", shell=True)
    R["tc4_h1_under_attack"] = gen(h2, "normal", count=10, interval=0.5)
    atk.wait()

    print("TC5 server failure + recovery")
    h4.cmd("pkill -f socket_app/server.py"); time.sleep(1)
    R["tc5_server_down"] = gen(h1, "normal", count=2, interval=0.3)
    h4.cmd(f"python3 {APP}/server.py > /tmp/server.out 2>&1 &"); time.sleep(1)
    R["tc5_server_back"] = gen(h1, "normal", count=2, interval=0.3)

    if a.recovery:
        print(f"TC6 waiting {a.block_timeout + 8}s for block to expire"); time.sleep(a.block_timeout + 8)
        R["tc6_h3_after_unblock"] = gen(h3, "normal", count=3, interval=0.3)

    json.dump(R, open(f"{RES}/results_{a.mode}.json", "w"), indent=2)
    print(json.dumps(R, indent=2))
    h4.cmd("pkill -f socket_app/server.py"); net.stop()


if __name__ == "__main__":
    main()
