"""OpenFlow flow-statistics collection. Member 2."""
import csv, os, time

DROP_PRIORITY = 100


def request_flow_stats(datapath):
    parser = datapath.ofproto_parser
    datapath.send_msg(parser.OFPFlowStatsRequest(datapath))


def parse_flow_stats(body, log_path):
    """Return {blocked_ip: dropped_packet_count}; append a snapshot row to CSV."""
    dropped, total_flows, total_pkts = {}, len(body), 0
    for st in body:
        total_pkts += st.packet_count
        if st.priority == DROP_PRIORITY:
            ip = st.match.get("ipv4_src")
            if ip:
                dropped[ip] = st.packet_count
    new = not os.path.exists(log_path)
    with open(log_path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp", "total_flows", "total_packets", "drop_rules", "dropped_packets"])
        w.writerow([f"{time.time():.3f}", total_flows, total_pkts, len(dropped), sum(dropped.values())])
    return dropped
