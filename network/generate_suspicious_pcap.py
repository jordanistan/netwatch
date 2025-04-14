#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import *
from collections import defaultdict
from datetime import datetime, timedelta
import random
import time
import os

def create_suspicious_traffic():
    """Generate a PCAP file with suspicious traffic from birdy.lan"""
    packets = []
    timestamp = datetime.now()
    
    # Malicious actor details
    attacker_ip = "192.168.86.42"  # birdy.lan
    attacker_mac = "b8:27:eb:13:19:3b"
    
    # Target IPs (other devices in network)
    target_ips = [
        "192.168.1.100",  # My Laptop
        "192.168.1.101",  # Smartphone
        "192.168.1.102"   # Smart TV
    ]
    
    # 1. Port Scanning Activity
    print("Generating port scan traffic...")
    for target in target_ips:
        for port in [21, 22, 23, 80, 443, 445, 3389, 8080]:
            # TCP SYN scan
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            packets.append(pkt)
    
    # 2. Brute Force SSH Attempts
    print("Generating SSH brute force attempts...")
    target = random.choice(target_ips)
    for _ in range(50):
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
              IP(src=attacker_ip, dst=target)/\
              TCP(sport=random.randint(49152, 65535), dport=22)/\
              Raw(load=b"SSH-2.0-OpenSSH_8.2p1")
        packets.append(pkt)
    
    # 3. Data Exfiltration (Large uploads to suspicious IPs)
    print("Generating data exfiltration traffic...")
    suspicious_ips = ["45.77.65.211", "198.51.100.123", "203.0.113.42"]
    for dst_ip in suspicious_ips:
        # Simulate large data transfers
        for _ in range(20):
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=dst_ip)/\
                  TCP(sport=random.randint(49152, 65535), dport=443)/\
                  Raw(load=RandString(size=1400))
            packets.append(pkt)
    
    # 4. DNS Tunneling Attempts
    print("Generating DNS tunneling traffic...")
    suspicious_domains = [
        "exfil.evil.com",
        "c2.malware.net",
        "data.badactor.org"
    ]
    for domain in suspicious_domains:
        for _ in range(10):
            # Encode fake data in subdomain
            encoded_data = RandString(size=30)
            query = f"{encoded_data}.{domain}"
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst="8.8.8.8")/\
                  UDP(sport=53, dport=53)/\
                  DNS(rd=1, qd=DNSQR(qname=query))
            packets.append(pkt)
    
    # 5. HTTP Attacks
    print("Generating web attack traffic...")
    target = random.choice(target_ips)
    attack_paths = [
        "/wp-admin/",
        "/phpmyadmin/",
        "/admin/login.php",
        "/?page=../../../../etc/passwd",
        "/search.php?q=1' OR '1'='1"
    ]
    for path in attack_paths:
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
              IP(src=attacker_ip, dst=target)/\
              TCP(sport=random.randint(49152, 65535), dport=80)/\
              Raw(load=f"GET {path} HTTP/1.1\r\nHost: {target}\r\n\r\n")
        packets.append(pkt)
    
    # Add some normal traffic to mix
    print("Adding normal traffic...")
    for _ in range(20):
        src = random.choice(target_ips)
        pkt = Ether(src=random.choice(["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]))/\
              IP(src=src, dst="8.8.8.8")/\
              UDP(sport=random.randint(49152, 65535), dport=53)/\
              DNS(rd=1, qd=DNSQR(qname="www.google.com"))
        packets.append(pkt)
    
    # Create captures directory if it doesn't exist
    os.makedirs("captures", exist_ok=True)
    
    # Write packets to PCAP
    pcap_file = "captures/suspicious_traffic.pcap"
    wrpcap(pcap_file, packets)
    print(f"\nCreated PCAP file with {len(packets)} packets of suspicious traffic")
    print(f"PCAP file location: {os.path.abspath(pcap_file)}")
    return pcap_file

if __name__ == "__main__":
    create_suspicious_traffic()
