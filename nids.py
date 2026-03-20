# The detection engine - the heart of the NIDS
# Captures all the packets on a network and analyzes it
# Detects four attacks:
# 1. Port scans
# 2. SYN floods
# 3. Ping sweeps
# 4. ARP sweeps

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list, get_if_addr
from collections import defaultdict
import time

from config import (
    PORT_SCAN_THRESHOLD,
    TIME_WINDOW,
    SYN_FLOOD_THRESHOLD,
    PING_SWEEP_THRESHOLD,
    INTERFACE
)

from logger import log_info, log_alert

# Tracking Dictionaries

port_scan_tracker  = defaultdict(list)
syn_flood_tracker  = defaultdict(list)
ping_sweep_tracker = defaultdict(list)

# Detection Functions

def check_port_scan(src_ip, dst_port):
    """Detects port scanning behaviour"""
    current_time = time.time()

    port_scan_tracker[src_ip].append((dst_port, current_time))

    port_scan_tracker[src_ip] = [
        (port, t) for port, t in port_scan_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    unique_ports = set(port for port, t in port_scan_tracker[src_ip])

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        log_alert(
            f"Port scan detected | Source: {src_ip} | "
            f"Unique ports hit: {len(unique_ports)} in {TIME_WINDOW}s | "
            f"Ports: {sorted(unique_ports)}"
        )
        port_scan_tracker[src_ip] = []


def check_syn_flood(src_ip, dst_ip):
    """Detects SYN flooding behaviour"""
    current_time = time.time()

    syn_flood_tracker[src_ip].append(current_time)

    syn_flood_tracker[src_ip] = [
        t for t in syn_flood_tracker[src_ip]
        if current_time - t <= 1
    ]

    if len(syn_flood_tracker[src_ip]) >= SYN_FLOOD_THRESHOLD:
        log_alert(
            f"SYN flood detected | Source: {src_ip} | "
            f"{len(syn_flood_tracker[src_ip])} SYN packets in 1 second"
        )
        syn_flood_tracker[src_ip] = []


def check_ping_sweep(src_ip, dst_ip):
    """Detects ping sweep reconnaissance"""
    current_time = time.time()

    ping_sweep_tracker[src_ip].append((dst_ip, current_time))

    ping_sweep_tracker[src_ip] = [
        (ip, t) for ip, t in ping_sweep_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    unique_ips = set(ip for ip, t in ping_sweep_tracker[src_ip])

    if len(unique_ips) >= PING_SWEEP_THRESHOLD:
        log_alert(
            f"Ping sweep detected | Source: {src_ip} | "
            f"Unique IPs hit: {len(unique_ips)} in {TIME_WINDOW}s | "
            f"IPs: {sorted(unique_ips)}"
        )
        ping_sweep_tracker[src_ip] = []


def check_arp_sweep(src_ip, dst_ip):
    """Detects ARP sweep reconnaissance"""
    current_time = time.time()

    ping_sweep_tracker[src_ip].append((dst_ip, current_time))

    ping_sweep_tracker[src_ip] = [
        (ip, t) for ip, t in ping_sweep_tracker[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    unique_ips = set(ip for ip, t in ping_sweep_tracker[src_ip])

    if len(unique_ips) >= PING_SWEEP_THRESHOLD:
        log_alert(
            f"ARP sweep detected | Source: {src_ip} | "
            f"Unique IPs probed: {len(unique_ips)} in {TIME_WINDOW}s | "
            f"IPs: {sorted(unique_ips)}"
        )
        ping_sweep_tracker[src_ip] = []


# Interface Detection

def find_interface():
    """
    Automatically finds the best network interface to listen on.
    Skips loopback and interfaces with no valid IP address.
    Returns the first valid interface found.
    """
    for iface in get_if_list():
        if "Loopback" in iface or iface == "lo":
            continue
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                log_info(f"Auto-detected interface: {iface} | IP: {ip}")
                return iface
        except:
            continue

    log_info("Could not auto-detect interface — using system default")
    return None


# Packet Handler

def packet_handler(packet):
    """Called for every captured packet. Routes to detection functions"""

    # Handle ARP packets separately — they have no IP layer
    if ARP in packet:
        if packet[ARP].op == 1:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            check_arp_sweep(src_ip, dst_ip)
        return

    # All other packets need an IP layer
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        if flags == 0x02:
            check_syn_flood(src_ip, dst_ip)
        check_port_scan(src_ip, dst_port)

    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        if icmp_type == 8:
            check_ping_sweep(src_ip, dst_ip)


# Entry Point

if __name__ == "__main__":
    log_info("NIDS started - monitoring all network traffic")
    log_info(
        f"Thresholds - port scan: {PORT_SCAN_THRESHOLD} ports/{TIME_WINDOW}s | "
        f"SYN flood: {SYN_FLOOD_THRESHOLD} SYNs/s | "
        f"ping sweep: {PING_SWEEP_THRESHOLD} IPs/{TIME_WINDOW}s"
    )

    # Use manual interface from config if set, otherwise auto-detect
    iface = INTERFACE if INTERFACE else find_interface()
    log_info(f"Listening on: {iface}")

    try:
        sniff(prn=packet_handler, store=0, iface=iface)
    except KeyboardInterrupt:
        log_info("NIDS stopped by user")