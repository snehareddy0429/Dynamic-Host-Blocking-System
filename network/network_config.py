"""Shared constants. Member 3."""
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTROLLER_IP, CONTROLLER_PORT = "127.0.0.1", 6653
SERVER_IP, SERVER_PORT = "10.0.0.4", 5000
HOSTS = {"h1": "10.0.0.1/24", "h2": "10.0.0.2/24", "h3": "10.0.0.3/24", "h4": "10.0.0.4/24"}
