"""CSV event log for detection and response events. Member 2."""
import csv, os, time

FIELDS = ["timestamp", "event", "ip", "syn_count", "detection_delay_s", "block_latency_ms", "details"]


class EventLog:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(FIELDS)

    def log(self, event, ip="", syn_count="", detection_delay_s="", block_latency_ms="", details=""):
        with open(self.path, "a", newline="") as f:
            csv.writer(f).writerow([f"{time.time():.3f}", event, ip, syn_count,
                                    detection_delay_s, block_latency_ms, details])
