"""OS-Ken OpenFlow 1.3 controller: learning switch + SYN-rate detection + dynamic blocking.

Run from repo root:   osken-manager controller/sdn_controller.py
Env vars: DHB_THRESHOLD (20) DHB_WINDOW (10) DHB_BLOCK_TIMEOUT (60, 0=permanent) DHB_ENABLED (1/0)
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from os_ken.ofproto import ofproto_v1_3

from controller.detection_engine import DetectionEngine
from controller.blocklist import Blocklist
from controller.event_log import EventLog
from controller.traffic_monitor import request_flow_stats, parse_flow_stats, DROP_PRIORITY

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")
THRESHOLD = int(os.environ.get("DHB_THRESHOLD", 20))
WINDOW = float(os.environ.get("DHB_WINDOW", 10))
BLOCK_TIMEOUT = int(os.environ.get("DHB_BLOCK_TIMEOUT", 60))
ENABLED = os.environ.get("DHB_ENABLED", "1") == "1"
FLOW_PRIORITY = 10


class DynamicHostBlocker(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port, self.datapaths, self.flagged = {}, {}, {}
        self.engine = DetectionEngine(THRESHOLD, WINDOW)
        self.blocklist = Blocklist(os.path.join(LOGS, "blocklist.json"), BLOCK_TIMEOUT)
        self.event_log = EventLog(os.path.join(LOGS, "events.csv"))
        self.event_log.log("START", details=f"threshold={THRESHOLD} window={WINDOW}s "
                                         f"block_timeout={BLOCK_TIMEOUT}s blocking={'ON' if ENABLED else 'OFF (baseline)'}")
        hub.spawn(self._monitor)

    # ---------- switch setup ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        p, o = dp.ofproto_parser, dp.ofproto
        self.datapaths[dp.id] = dp
        # table-miss: send unknown packets to controller
        self._flow(dp, 0, p.OFPMatch(), [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])
        self.event_log.log("SWITCH_CONNECTED", details=f"dpid={dp.id}")

    def _flow(self, dp, priority, match, actions, idle=0, hard=0):
        p, o = dp.ofproto_parser, dp.ofproto
        inst = [p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst,
                                 idle_timeout=idle, hard_timeout=hard))

    # ---------- packet handling ----------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp, o, p = msg.datapath, msg.datapath.ofproto, msg.datapath.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, o.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]

        ip4, t = pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(tcp.tcp)
        if ip4 and t:
            if self.blocklist.is_blocked(ip4.src):
                return                                   # belt and braces: drop
            if t.has_flags(tcp.TCP_SYN) and not t.has_flags(tcp.TCP_ACK):
                if self._inspect_syn(dp, ip4.src):
                    return                               # host just blocked; drop this SYN
            if out_port != o.OFPP_FLOOD:                 # per-connection forwarding flow
                match = p.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6,
                                   ipv4_src=ip4.src, ipv4_dst=ip4.dst,
                                   tcp_src=t.src_port, tcp_dst=t.dst_port)
                self._flow(dp, FLOW_PRIORITY, match, actions, idle=5)

        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=o.OFP_NO_BUFFER, in_port=in_port,
                                   actions=actions, data=msg.data))

    # ---------- detection and response ----------
    def _inspect_syn(self, dp, src_ip):
        count, first = self.engine.record_syn(src_ip)
        if not self.engine.is_suspicious(count):
            return False
        now = time.time()
        if now - self.flagged.get(src_ip, 0) > WINDOW:   # log DETECT once per window
            self.flagged[src_ip] = now
            self.event_log.log("DETECT", src_ip, count, f"{now - first:.3f}", "",
                            f"{count} SYNs in {WINDOW}s > threshold {THRESHOLD}")
            self.logger.warning("DETECTED suspicious host %s (%d SYNs)", src_ip, count)
            if ENABLED:
                self._block(dp, src_ip, count, now, now - first)
                return True
        return ENABLED

    def _block(self, dp, ip, count, detect_ts, delay):
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip)
        self._flow(dp, DROP_PRIORITY, match, [], hard=BLOCK_TIMEOUT)   # no actions = DROP
        latency_ms = (time.time() - detect_ts) * 1000
        self.blocklist.add(ip, f"{count} SYNs in {WINDOW}s", count)
        self.event_log.log("BLOCK", ip, count, f"{delay:.3f}", f"{latency_ms:.2f}",
                        f"drop rule installed, timeout={BLOCK_TIMEOUT}s")
        self.logger.warning("BLOCKED %s - drop rule installed", ip)

    # ---------- periodic stats + expiry ----------
    def _monitor(self):
        while True:
            hub.sleep(5)
            for dp in list(self.datapaths.values()):
                request_flow_stats(dp)
            for ip in self.blocklist.expired():
                self.blocklist.remove(ip)
                self.engine.reset(ip)
                self.flagged.pop(ip, None)
                self.event_log.log("UNBLOCK", ip, details="block timeout expired")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        dropped = parse_flow_stats(ev.msg.body, os.path.join(LOGS, "flow_stats.csv"))
        for ip, n in dropped.items():
            self.blocklist.set_dropped(ip, n)
