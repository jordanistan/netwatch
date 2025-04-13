#!/usr/bin/env python3
from scapy.all import *
import ipaddress
from collections import defaultdict
import time
import json
import os
from datetime import datetime

class SecurityAnalyzer:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "threats": [],
            "suspicious_activities": [],
            "vulnerabilities": [],
            "statistics": {},
            "scan_results": {}
        }
        
        # Initialize threat detection parameters
        self.port_scan_threshold = 10  # ports/second
        self.syn_flood_threshold = 50  # SYNs/second
        self.failed_conn_threshold = 0.3  # 30% of total
        self.blacklist_ports = {
            21: "FTP", 23: "Telnet", 445: "SMB",
            135: "RPC", 137: "NetBIOS", 139: "NetBIOS",
            3389: "RDP", 5900: "VNC"
        }
        
    def detect_port_scans(self, packets):
        """Detect potential port scanning activities"""
        port_attempts = defaultdict(lambda: defaultdict(set))
        scan_window = defaultdict(lambda: defaultdict(float))
        
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport
                timestamp = pkt.time
                
                # Track unique ports per source
                port_attempts[src][dst].add(dport)
                
                # Check rate of port attempts
                if len(port_attempts[src][dst]) > self.port_scan_threshold:
                    if timestamp - scan_window[src][dst] <= 1.0:  # within 1 second
                        self.results["threats"].append({
                            "type": "Port Scan Detected",
                            "severity": "High",
                            "details": {
                                "source_ip": src,
                                "target_ip": dst,
                                "ports_attempted": len(port_attempts[src][dst]),
                                "timestamp": timestamp
                            }
                        })
                    scan_window[src][dst] = timestamp

    def detect_syn_flood(self, packets):
        """Detect potential SYN flood attacks"""
        syn_counts = defaultdict(lambda: defaultdict(int))
        time_windows = defaultdict(lambda: defaultdict(list))
        
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    timestamp = pkt.time
                    
                    # Maintain a sliding window of SYN packets
                    time_windows[src][dst].append(timestamp)
                    time_windows[src][dst] = [t for t in time_windows[src][dst] 
                                           if timestamp - t <= 1.0]
                    
                    if len(time_windows[src][dst]) > self.syn_flood_threshold:
                        self.results["threats"].append({
                            "type": "SYN Flood Attack",
                            "severity": "Critical",
                            "details": {
                                "source_ip": src,
                                "target_ip": dst,
                                "syn_rate": len(time_windows[src][dst]),
                                "timestamp": timestamp
                            }
                        })

    def detect_suspicious_ports(self, packets):
        """Detect connections to potentially dangerous ports"""
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                dport = pkt[TCP].dport
                if dport in self.blacklist_ports:
                    self.results["suspicious_activities"].append({
                        "type": "Suspicious Port Access",
                        "severity": "Medium",
                        "details": {
                            "source_ip": pkt[IP].src,
                            "target_ip": pkt[IP].dst,
                            "port": dport,
                            "service": self.blacklist_ports[dport],
                            "timestamp": pkt.time
                        }
                    })

    def analyze_failed_connections(self, packets):
        """Analyze failed connection attempts"""
        connections = defaultdict(lambda: {
            "syn": 0, "syn_ack": 0, "rst": 0, "fin": 0
        })
        
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                stream_id = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                flags = pkt[TCP].flags
                
                if flags & 0x02:  # SYN
                    connections[stream_id]["syn"] += 1
                elif flags & 0x12:  # SYN-ACK
                    connections[stream_id]["syn_ack"] += 1
                elif flags & 0x04:  # RST
                    connections[stream_id]["rst"] += 1
                elif flags & 0x01:  # FIN
                    connections[stream_id]["fin"] += 1
        
        # Analyze connection patterns
        total_conns = len(connections)
        failed_conns = sum(1 for c in connections.values() 
                         if c["syn"] > 0 and (c["rst"] > 0 or c["syn_ack"] == 0))
        
        if total_conns > 0:
            failure_rate = failed_conns / total_conns
            if failure_rate > self.failed_conn_threshold:
                self.results["suspicious_activities"].append({
                    "type": "High Connection Failure Rate",
                    "severity": "Medium",
                    "details": {
                        "failure_rate": f"{failure_rate:.2%}",
                        "failed_connections": failed_conns,
                        "total_connections": total_conns
                    }
                })

    def detect_data_exfiltration(self, packets):
        """Detect potential data exfiltration patterns"""
        outbound_data = defaultdict(lambda: defaultdict(int))
        
        for pkt in packets:
            if IP in pkt:
                if TCP in pkt or UDP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    size = len(pkt)
                    outbound_data[src][dst] += size
        
        # Check for large data transfers
        for src, destinations in outbound_data.items():
            for dst, total_bytes in destinations.items():
                if total_bytes > 1000000:  # 1MB threshold
                    self.results["suspicious_activities"].append({
                        "type": "Large Data Transfer",
                        "severity": "Medium",
                        "details": {
                            "source_ip": src,
                            "destination_ip": dst,
                            "bytes_transferred": total_bytes,
                            "mb_transferred": f"{total_bytes/1000000:.2f}MB"
                        }
                    })

    def check_encryption(self, packets):
        """Analyze unencrypted sensitive protocols"""
        sensitive_ports = {
            80: "HTTP",
            143: "IMAP",
            25: "SMTP",
            110: "POP3"
        }
        
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                dport = pkt[TCP].dport
                if dport in sensitive_ports:
                    self.results["vulnerabilities"].append({
                        "type": "Unencrypted Protocol",
                        "severity": "High",
                        "details": {
                            "protocol": sensitive_ports[dport],
                            "source_ip": pkt[IP].src,
                            "destination_ip": pkt[IP].dst,
                            "port": dport
                        }
                    })

    def analyze_network_security(self, duration=30):
        """Run comprehensive security analysis"""
        print(f"\n🔍 Starting {duration}-second security analysis...")
        print("Capturing packets for analysis...")
        
        packets = sniff(iface="eth0", timeout=duration)
        total_packets = len(packets)
        
        print(f"\nAnalyzing {total_packets} packets for security threats...")
        
        # Run all security checks
        self.detect_port_scans(packets)
        self.detect_syn_flood(packets)
        self.detect_suspicious_ports(packets)
        self.analyze_failed_connections(packets)
        self.detect_data_exfiltration(packets)
        self.check_encryption(packets)
        
        # Compile statistics
        self.results["statistics"] = {
            "total_packets": total_packets,
            "duration": duration,
            "packet_rate": total_packets/duration,
            "unique_ips": len(set(pkt[IP].src for pkt in packets if IP in pkt)),
            "threats_detected": len(self.results["threats"]),
            "suspicious_activities": len(self.results["suspicious_activities"]),
            "vulnerabilities": len(self.results["vulnerabilities"])
        }
        
        # Save results
        report_path = "/app/reports/security_scan_{}.json".format(
            int(time.time()))
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        print("\n📊 Security Analysis Summary:")
        print("=" * 50)
        print(f"Duration: {duration} seconds")
        print(f"Total Packets: {total_packets}")
        print(f"Packet Rate: {total_packets/duration:.2f} packets/second")
        print(f"Threats Detected: {len(self.results['threats'])}")
        print(f"Suspicious Activities: {len(self.results['suspicious_activities'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"\nDetailed report saved to: {report_path}")
        
        return self.results

if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    analyzer.analyze_network_security()
