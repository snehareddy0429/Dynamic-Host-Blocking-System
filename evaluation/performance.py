"""Compare baseline vs blocking results and draw graphs. Member 3.
Run after both:  python3 evaluation/performance.py
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
load = lambda m: json.load(open(f"{RES}/results_{m}.json"))
b, d = load("baseline"), load("blocking")

fig, ax = plt.subplots(1, 3, figsize=(13, 4))
ax[0].bar(["No blocking", "Dynamic blocking"],
          [b["tc4_h1_under_attack"]["avg_latency_ms"] or 0, d["tc4_h1_under_attack"]["avg_latency_ms"] or 0],
          color=["tab:red", "tab:green"]); ax[0].set_title("Legit client latency under attack (ms)")
ax[1].bar(["No blocking", "Dynamic blocking"],
          [b["tc2_h3"]["success"], d["tc2_h3"]["success"]],
          color=["tab:red", "tab:green"]); ax[1].set_title("Attacker successful connections (of 50)")
ax[2].bar(["Detection delay (s)", "Block latency (ms)"],
          [d.get("detection_delay_s", 0), d.get("block_latency_ms", 0)], color="tab:blue")
ax[2].set_title("Detection / blocking time")
plt.tight_layout(); plt.savefig(f"{RES}/comparison.png", dpi=150)

with open(f"{RES}/summary.md", "w") as f:
    f.write("| Metric | Baseline | Dynamic blocking |\n|---|---|---|\n")
    f.write(f"| Attacker successful conns (of 50) | {b['tc2_h3']['success']} | {d['tc2_h3']['success']} |\n")
    f.write(f"| Attacker conns after block (TC3, of 3) | {b['tc3_h3_again']['success']} | {d['tc3_h3_again']['success']} |\n")
    f.write(f"| Legit client avg latency under attack (ms) | {b['tc4_h1_under_attack']['avg_latency_ms']} | {d['tc4_h1_under_attack']['avg_latency_ms']} |\n")
    f.write(f"| Legit client failed conns under attack | {b['tc4_h1_under_attack']['failed']} | {d['tc4_h1_under_attack']['failed']} |\n")
    f.write(f"| Detection delay (s) | n/a | {d.get('detection_delay_s')} |\n| Block latency (ms) | n/a | {d.get('block_latency_ms')} |\n")
print(open(f"{RES}/summary.md").read())
