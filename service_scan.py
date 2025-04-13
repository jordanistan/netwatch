#!/usr/bin/env python3
from scapy.all import *
import socket
import ssl
from collections import defaultdict
import json
from datetime import datetime

class ServiceAnalyzer:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "services": [],
            "vulnerabilities": [],
            "certificates": [],
            "protocols": defaultdict(int)
        }
        
        self.sensitive_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB"
        }
    
    def analyze_service(self, ip, port):
        """Attempt to identify service and check for common vulnerabilities"""
        try:
            # Try TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = {
                    "ip": ip,
                    "port": port,
                    "protocol": "TCP",
                    "state": "open",
                    "service": self.sensitive_ports.get(port, "unknown"),
                    "banner": None
                }
                
                # Try to get service banner
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                    service["banner"] = banner.decode('utf-8', 'ignore').strip()
                except:
                    pass
                
                # Check for SSL/TLS
                if port == 443 or service["banner"] and "HTTPS" in service["banner"]:
                    try:
                        ssl_sock = ssl.wrap_socket(sock)
                        cert = ssl_sock.getpeercert()
                        if cert:
                            self.results["certificates"].append({
                                "ip": ip,
                                "port": port,
                                "subject": str(cert.get("subject")),
                                "issuer": str(cert.get("issuer")),
                                "version": cert.get("version"),
                                "expires": str(cert.get("notAfter"))
                            })
                    except:
                        # SSL errors might indicate misconfiguration
                        self.results["vulnerabilities"].append({
                            "type": "SSL Configuration Issue",
                            "severity": "Medium",
                            "target": f"{ip}:{port}",
                            "details": "SSL/TLS handshake failed"
                        })
                
                self.results["services"].append(service)
                
                # Check for common vulnerabilities
                self.check_vulnerabilities(ip, port, service)
            
            sock.close()
            
        except Exception as e:
            print(f"Error analyzing {ip}:{port} - {str(e)}")
    
    def check_vulnerabilities(self, ip, port, service):
        """Check for common security issues"""
        # Check for dangerous services
        if port in [21, 23]:  # FTP, Telnet
            self.results["vulnerabilities"].append({
                "type": "Insecure Protocol",
                "severity": "High",
                "target": f"{ip}:{port}",
                "details": f"Unencrypted {service['service']} service detected"
            })
        
        # Check for database ports exposed
        if port in [3306, 5432, 6379, 27017]:
            self.results["vulnerabilities"].append({
                "type": "Exposed Database",
                "severity": "High",
                "target": f"{ip}:{port}",
                "details": f"Database port ({service['service']}) exposed to network"
            })
        
        # Check for weak HTTP security
        if port == 80 and service.get("banner"):
            if "Server:" in service["banner"]:
                self.results["vulnerabilities"].append({
                    "type": "Information Disclosure",
                    "severity": "Low",
                    "target": f"{ip}:{port}",
                    "details": "Server header reveals version information"
                })
    
    def analyze_packet(self, pkt):
        """Analyze individual packets for protocol statistics"""
        if IP in pkt:
            if TCP in pkt:
                self.results["protocols"]["TCP"] += 1
            elif UDP in pkt:
                self.results["protocols"]["UDP"] += 1
            elif ICMP in pkt:
                self.results["protocols"]["ICMP"] += 1
    
    def run_analysis(self, target_ip, port_range=(1, 1024)):
        """Run full service analysis"""
        print(f"\n🔍 Starting service analysis on {target_ip}")
        print(f"Scanning ports {port_range[0]}-{port_range[1]}...")
        
        # First pass: quick port scan
        for port in range(port_range[0], port_range[1] + 1):
            self.analyze_service(target_ip, port)
        
        # Second pass: packet analysis
        print("\nAnalyzing network protocols...")
        packets = sniff(filter=f"host {target_ip}", timeout=10)
        for pkt in packets:
            self.analyze_packet(pkt)
        
        # Save results
        report_path = "/app/reports/service_scan_{}.json".format(
            int(time.time()))
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Print summary
        print("\n📊 Service Analysis Summary:")
        print("=" * 50)
        print(f"Open Services: {len(self.results['services'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print(f"SSL Certificates: {len(self.results['certificates'])}")
        print("\nProtocol Distribution:")
        for proto, count in self.results["protocols"].items():
            print(f"  {proto}: {count} packets")
        print(f"\nDetailed report saved to: {report_path}")

if __name__ == "__main__":
    analyzer = ServiceAnalyzer()
    analyzer.run_analysis("192.168.65.1")
