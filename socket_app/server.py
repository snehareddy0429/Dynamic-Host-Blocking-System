"""Multi-threaded TCP server (runs on h4, 10.0.0.4:5000). Member 1."""
import argparse, csv, os, socketserver, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "server_connections.csv")
lock = threading.Lock()


def log_conn(ip, port):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    new = not os.path.exists(LOG)
    with lock, open(LOG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp", "client_ip", "client_port"])
        w.writerow([f"{time.time():.3f}", ip, port])


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        ip, port = self.client_address
        log_conn(ip, port)
        try:
            self.request.settimeout(5)
            data = self.request.recv(1024)
            self.request.sendall(b"ACK: " + data)
        except (OSError, TimeoutError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    with Server((a.host, a.port), Handler) as s:
        print(f"[server] listening on {a.host}:{a.port}", flush=True)
        s.serve_forever()
