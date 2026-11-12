"""Dynamic blocklist with timestamps, reasons and auto-expiry. Member 2."""
import json, os, time


class Blocklist:
    def __init__(self, path, ttl=60):
        self.path, self.ttl, self.entries = path, ttl, {}

    def add(self, ip, reason, syn_count):
        self.entries[ip] = {"blocked_at": time.time(), "reason": reason,
                            "syn_count": syn_count, "expires_at": time.time() + self.ttl if self.ttl else None,
                            "dropped_packets": 0}
        self._save()

    def remove(self, ip):
        self.entries.pop(ip, None)
        self._save()

    def is_blocked(self, ip):
        return ip in self.entries

    def expired(self):
        now = time.time()
        return [ip for ip, e in self.entries.items() if e["expires_at"] and now >= e["expires_at"]]

    def set_dropped(self, ip, n):
        if ip in self.entries:
            self.entries[ip]["dropped_packets"] = n
            self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=2)
