"""Sliding-window SYN-rate detector. Member 2."""
import time
from collections import defaultdict, deque


class DetectionEngine:
    def __init__(self, threshold=20, window=10.0):
        self.threshold = threshold      # more than this many SYNs ...
        self.window = window            # ... within this many seconds = abnormal
        self._syns = defaultdict(deque)

    def record_syn(self, ip, now=None):
        """Record a SYN; return (count_in_window, first_syn_timestamp)."""
        now = time.time() if now is None else now
        q = self._syns[ip]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        return len(q), q[0]

    def is_suspicious(self, count):
        return count > self.threshold

    def reset(self, ip):
        self._syns.pop(ip, None)
