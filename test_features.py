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
            print("\n🔍 Testing packet capture...")
            iface = next(i.name for i in get_working_ifaces() 
                        if 'lo' not in i.name and 'UP' in i.flags)
            
            capture_file = os.path.join(self.capture_dir, 
                                      f"test_capture_{int(time.time())}.pcap")
            
            print(f"Starting 10-second capture on {iface}...")
            packets = sniff(iface=iface, timeout=10)
            wrpcap(capture_file, packets)
            
            # Analyze captured packets
            analysis = {
                "total_packets": len(packets),
                "protocols": defaultdict(int),
                "packet_sizes": defaultdict(int),
                "top_talkers": defaultdict(int)
            }
            
            for pkt in packets:
                # Protocol analysis
                if IP in pkt:
                    if TCP in pkt:
                        analysis["protocols"]["TCP"] += 1
                    elif UDP in pkt:
                        analysis["protocols"]["UDP"] += 1
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
            
            # Convert defaultdict to regular dict for JSON serialization
            analysis["protocols"] = dict(analysis["protocols"])
            analysis["packet_sizes"] = dict(analysis["packet_sizes"])
            analysis["top_talkers"] = dict(sorted(
                analysis["top_talkers"].items(), 
                key=lambda x: x[1], 
                reverse=True)[:5])
            
            self.results["packet_capture"] = {
                "interface": iface,
                "duration": 10,
                "capture_file": capture_file,
                "analysis": analysis
            }
            
            print(f"Captured {len(packets)} packets")
            
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
