"""TCP client helper. Member 1."""
import argparse, socket, time


def connect_once(server, port, timeout=2.0, message="hello"):
    """Open one TCP connection, send a message, read the reply.
    Returns (success, latency_ms)."""
    t0 = time.time()
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(message.encode())
            s.settimeout(timeout)
            s.recv(1024)
        return True, (time.time() - t0) * 1000
    except OSError:
        return False, (time.time() - t0) * 1000


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="10.0.0.4")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()
    ok, ms = connect_once(a.server, a.port, a.timeout)
    print("OK" if ok else "FAILED", f"{ms:.1f} ms")
