"""Mininet topology: h1-h4 on one OVS switch (OpenFlow 1.3) + remote OS-Ken controller. Member 3.
Run:  sudo python3 network/topology.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from network.network_config import *


def build_network():
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for name, ip in HOSTS.items():
        net.addLink(net.addHost(name, ip=ip), s1)
    return net


if __name__ == "__main__":
    setLogLevel("info")
    net = build_network()
    net.start()
    net.get("h4").cmd(f"python3 {REPO_ROOT}/socket_app/server.py > /tmp/server.out 2>&1 &")
    print("Server running on h4. Try: h1 python3 socket_app/client.py ; h3 python3 socket_app/traffic_generator.py --mode abnormal")
    CLI(net)
    net.get("h4").cmd("pkill -f socket_app/server.py")
    net.stop()
