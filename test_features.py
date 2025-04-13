#!/usr/bin/env python3
from scapy.all import *
import ipaddress
import json
import os
import time
from datetime import datetime
import socket
from collections import defaultdict

class NetworkTest:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "interface_info": {},
            "network_scan": {},
            "packet_capture": {},
            "traffic_analysis": {},
            "errors": []
        }
        self.capture_dir = "/app/captures"
        self.report_dir = "/app/reports"
        
        # Create directories if they don't exist
        os.makedirs(self.capture_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

    def test_interface_detection(self):
        """Test network interface detection and configuration"""
        try:
            print("\n🔍 Testing interface detection...")
            interfaces = get_working_ifaces()
            
            for iface in interfaces:
                if 'lo' in iface.name:  # Skip loopback
                    continue
                    
                ip = get_if_addr(iface.name)
                mac = get_if_hwaddr(iface.name)
                
                self.results["interface_info"][iface.name] = {
                    "ip": ip,
                    "mac": mac,
                    "status": "UP" if "UP" in iface.flags else "DOWN",
                    "flags": str(iface.flags)
                }
                
            print(f"Found {len(self.results['interface_info'])} interfaces")
            
        except Exception as e:
            self.results["errors"].append(f"Interface detection error: {str(e)}")
            print(f"❌ Error in interface detection: {e}")

    def test_network_scan(self):
        """Test ARP-based network scanning"""
        try:
            print("\n🔍 Testing network scanning...")
            # Use the first non-loopback interface
            iface = next(i.name for i in get_working_ifaces() 
                        if 'lo' not in i.name and 'UP' in i.flags)
            
            ip = get_if_addr(iface)
            network = str(ipaddress.IPv4Network(f'{ip}/24', strict=False))
            
            print(f"Scanning network: {network} on interface {iface}")
            start_time = time.time()
            
            ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=network),
                            timeout=3, verbose=False, iface=iface)
            
            devices = []
            for sent, received in ans:
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Unknown"
                    
                devices.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": hostname
                })
            
            self.results["network_scan"] = {
                "interface": iface,
                "network": network,
                "scan_time": time.time() - start_time,
                "devices_found": len(devices),
                "devices": devices
            }
            
            print(f"Found {len(devices)} devices")
            
        except Exception as e:
            self.results["errors"].append(f"Network scan error: {str(e)}")
            print(f"❌ Error in network scan: {e}")

    def test_packet_capture(self):
        """Test packet capture and analysis"""
        try:
            print("\n🔍 Testing packet capture and advanced analysis...")
            iface = next(i.name for i in get_working_ifaces() 
                        if 'lo' not in i.name and 'UP' in i.flags)
            
            capture_file = os.path.join(self.capture_dir, 
                                      f"test_capture_{int(time.time())}.pcap")
            
            print(f"Starting 20-second capture on {iface}...")
            packets = sniff(iface=iface, timeout=20)
            wrpcap(capture_file, packets)
            
            # Initialize analysis dictionaries
            analysis = {
                "total_packets": len(packets),
                "protocols": defaultdict(int),
                "packet_sizes": defaultdict(int),
                "top_talkers": defaultdict(int),
                "tcp_services": defaultdict(set),
                "udp_services": defaultdict(set),
                "tcp_flags": defaultdict(int),
                "tcp_connections": defaultdict(lambda: {
                    "syn": 0, "syn_ack": 0, "fin": 0, "rst": 0,
                    "bytes_sent": 0, "bytes_received": 0
                }),
                "dns_queries": [],
                "http_methods": defaultdict(int),
                "ip_ttl_distribution": defaultdict(int),
                "packet_rate": defaultdict(int),
                "retransmissions": 0
            }
            
            # Track TCP sequence numbers for retransmission detection
            seq_tracker = {}
            start_time = time.time()
            
            for pkt in packets:
                # Basic protocol analysis
                if IP in pkt:
                    # TTL distribution
                    analysis["ip_ttl_distribution"][pkt[IP].ttl] += 1
                    
                    # Packet rate (per second)
                    pkt_time = int(pkt.time - start_time)
                    analysis["packet_rate"][pkt_time] += 1
                    
                    if TCP in pkt:
                        analysis["protocols"]["TCP"] += 1
                        
                        # TCP flags analysis
                        flags = pkt[TCP].flags
                        analysis["tcp_flags"][str(flags)] += 1
                        
                        # Service discovery
                        port = pkt[TCP].dport
                        if port < 1024 or port in [1433, 3306, 5432, 8080, 8443]:
                            analysis["tcp_services"][str(port)].add(pkt[IP].dst)
                        
                        # TCP connection tracking
                        stream_id = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
                        if flags & 0x02:  # SYN
                            analysis["tcp_connections"][stream_id]["syn"] += 1
                        elif flags & 0x12:  # SYN-ACK
                            analysis["tcp_connections"][stream_id]["syn_ack"] += 1
                        elif flags & 0x01:  # FIN
                            analysis["tcp_connections"][stream_id]["fin"] += 1
                        elif flags & 0x04:  # RST
                            analysis["tcp_connections"][stream_id]["rst"] += 1
                        
                        # Retransmission detection
                        seq = pkt[TCP].seq
                        if stream_id in seq_tracker and seq in seq_tracker[stream_id]:
                            analysis["retransmissions"] += 1
                        if stream_id not in seq_tracker:
                            seq_tracker[stream_id] = set()
                        seq_tracker[stream_id].add(seq)
                        
                        # HTTP method detection
                        if Raw in pkt and pkt[TCP].dport in [80, 8080]:
                            payload = pkt[Raw].load.decode('utf-8', 'ignore')
                            for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
                                if payload.startswith(method):
                                    analysis["http_methods"][method] += 1
                    
                    elif UDP in pkt:
                        analysis["protocols"]["UDP"] += 1
                        
                        # UDP service discovery
                        port = pkt[UDP].dport
                        if port < 1024 or port in [53, 67, 68, 123, 161, 162]:
                            analysis["udp_services"][str(port)].add(pkt[IP].dst)
                        
                        # DNS analysis
                        if port == 53 and DNS in pkt:
                            if pkt[DNS].qr == 0:  # Query
                                for i in range(pkt[DNS].qdcount):
                                    name = pkt[DNS].qd[i].qname.decode('utf-8')
                                    analysis["dns_queries"].append({
                                        "query": name,
                                        "type": pkt[DNS].qd[i].qtype
                                    })
                    
                    elif ICMP in pkt:
                        analysis["protocols"]["ICMP"] += 1
                    else:
                        analysis["protocols"]["Other"] += 1
                    
                    # Packet size distribution
                    size = len(pkt)
                    if size <= 64:
                        analysis["packet_sizes"]["0-64"] += 1
                    elif size <= 512:
                        analysis["packet_sizes"]["65-512"] += 1
                    elif size <= 1500:
                        analysis["packet_sizes"]["513-1500"] += 1
                    else:
                        analysis["packet_sizes"][">1500"] += 1
                    
                    # Top talkers
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    analysis["top_talkers"][src] += 1
                    analysis["top_talkers"][dst] += 1
            
            # Post-processing for JSON serialization
            analysis["protocols"] = dict(analysis["protocols"])
            analysis["packet_sizes"] = dict(analysis["packet_sizes"])
            analysis["top_talkers"] = dict(sorted(
                analysis["top_talkers"].items(), 
                key=lambda x: x[1], 
                reverse=True)[:5])
            analysis["tcp_services"] = {k: list(v) for k, v in analysis["tcp_services"].items()}
            analysis["udp_services"] = {k: list(v) for k, v in analysis["udp_services"].items()}
            analysis["ip_ttl_distribution"] = dict(analysis["ip_ttl_distribution"])
            analysis["packet_rate"] = dict(analysis["packet_rate"])
            
            # Calculate additional metrics
            analysis["average_packet_rate"] = len(packets) / 20  # packets per second
            analysis["tcp_completion_rate"] = sum(
                1 for conn in analysis["tcp_connections"].values()
                if conn["syn"] > 0 and conn["fin"] > 0
            ) / len(analysis["tcp_connections"]) if analysis["tcp_connections"] else 0
            
            self.results["packet_capture"] = {
                "interface": iface,
                "duration": 20,
                "capture_file": capture_file,
                "analysis": analysis
            }
            
            print(f"Captured and analyzed {len(packets)} packets")
            
        except Exception as e:
            self.results["errors"].append(f"Packet capture error: {str(e)}")
            print(f"❌ Error in packet capture: {e}")

    def save_report(self):
        """Save test results to a report file"""
        report_file = os.path.join(self.report_dir, 
                                 f"test_report_{int(time.time())}.json")
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📝 Report saved to {report_file}")
        return report_file

    def run_all_tests(self):
        """Run all tests and generate report"""
        print("🚀 Starting comprehensive network tests...")
        
        self.test_interface_detection()
        self.test_network_scan()
        self.test_packet_capture()
        
        report_file = self.save_report()
        
        # Print summary
        print("\n📊 Test Summary:")
        print(f"{'='*50}")
        print(f"Interfaces detected: {len(self.results['interface_info'])}")
        print(f"Devices discovered: {self.results['network_scan'].get('devices_found', 0)}")
        if 'packet_capture' in self.results:
            analysis = self.results['packet_capture']['analysis']
            print(f"Packets captured: {analysis['total_packets']}")
            print("\nProtocol distribution:")
            for proto, count in analysis['protocols'].items():
                print(f"  - {proto}: {count}")
        print(f"{'='*50}")
        
        if self.results['errors']:
            print("\n⚠️ Errors encountered:")
            for error in self.results['errors']:
                print(f"  - {error}")
        
        return report_file

if __name__ == "__main__":
    tester = NetworkTest()
    tester.run_all_tests()
