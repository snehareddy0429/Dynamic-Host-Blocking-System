"""Normal / abnormal TCP traffic generator. Member 1.
Prints one JSON summary line at the end."""
import argparse, json, time
from client import connect_once

PROFILES = {            # defaults: connections, seconds between connections
    "normal":   {"count": 5,  "interval": 1.0},
    "abnormal": {"count": 50, "interval": 0.05},
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=PROFILES, default="normal")
    ap.add_argument("--server", default="10.0.0.4")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--count", type=int)
    ap.add_argument("--interval", type=float)
    ap.add_argument("--timeout", type=float, default=1.0)
    a = ap.parse_args()
    count = a.count if a.count is not None else PROFILES[a.mode]["count"]
    interval = a.interval if a.interval is not None else PROFILES[a.mode]["interval"]

    ok_n, lat = 0, []
    t0 = time.time()
    for _ in range(count):
        ok, ms = connect_once(a.server, a.port, a.timeout)
        if ok:
            ok_n += 1
            lat.append(ms)
        time.sleep(interval)
    print(json.dumps({
        "mode": a.mode, "attempts": count, "success": ok_n, "failed": count - ok_n,
        "avg_latency_ms": round(sum(lat) / len(lat), 2) if lat else None,
        "duration_s": round(time.time() - t0, 2),
    }))
