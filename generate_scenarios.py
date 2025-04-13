import json
from datetime import datetime, timedelta
import os

def generate_ddos_scenario():
    """Generate data for a DDoS attack scenario"""
    return {
        "incident_type": "ddos_attack",
        "timestamp": datetime.now().isoformat(),
        "duration": 1800,  # 30 minutes
        "source_ips": [f"192.168.1.{i}" for i in range(100, 200)],
        "target_ip": "192.168.1.10",
        "traffic_pattern": {
            "packets_per_second": 50000,
            "bandwidth_usage": "95%",
            "protocol": "UDP",
            "port": 80
        },
        "impact": {
            "server_status": "degraded",
            "response_time": "5000ms",
            "dropped_packets": "75%"
        }
    }

def generate_data_exfiltration():
    """Generate data for a data exfiltration scenario"""
    return {
        "incident_type": "data_exfiltration",
        "timestamp": datetime.now().isoformat(),
        "source_ip": "192.168.1.50",
        "destination_ip": "203.0.113.100",
        "data_transferred": {
            "size": "2.5GB",
            "file_types": ["pdf", "doc", "xls"],
            "sensitive_patterns": ["credit_card", "ssn", "password"]
        },
        "transfer_method": {
            "protocol": "HTTPS",
            "encryption": "TLS 1.3",
            "destination": "unknown_cloud_storage"
        },
        "timeline": [
            {"time": (datetime.now() - timedelta(minutes=30)).isoformat(), "event": "Initial connection"},
            {"time": (datetime.now() - timedelta(minutes=20)).isoformat(), "event": "Data transfer start"},
            {"time": (datetime.now() - timedelta(minutes=5)).isoformat(), "event": "Data transfer complete"}
        ]
    }

def generate_malware_infection():
    """Generate data for a malware infection scenario"""
    return {
        "incident_type": "malware_infection",
        "timestamp": datetime.now().isoformat(),
        "infected_host": "192.168.1.75",
        "malware_type": "ransomware",
        "infection_vector": "phishing_email",
        "behavior": {
            "file_encryption": True,
            "network_scanning": True,
            "c2_communication": {
                "destination": "185.193.127.100",
                "protocol": "HTTPS",
                "frequency": "every 5 minutes"
            }
        },
        "affected_systems": [
            {"ip": "192.168.1.75", "hostname": "DESKTOP-001", "encrypted_files": 1500},
            {"ip": "192.168.1.76", "hostname": "DESKTOP-002", "encrypted_files": 750}
        ],
        "indicators": {
            "file_hashes": ["8a9f8d3e7c6b5a4d2c1e9f8a7b4c5d6e", "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"],
            "network_iocs": ["185.193.127.100", "91.234.56.78"],
            "file_extensions": [".encrypted", ".locked", ".ransom"]
        }
    }

def main():
    # Create scenarios directory
    scenarios_dir = "examples/scenarios"
    os.makedirs(scenarios_dir, exist_ok=True)
    
    # Generate and save scenarios
    scenarios = {
        "ddos_attack": generate_ddos_scenario(),
        "data_exfiltration": generate_data_exfiltration(),
        "malware_infection": generate_malware_infection()
    }
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for name, data in scenarios.items():
        filename = os.path.join(scenarios_dir, f"{name}_{timestamp}.json")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"Generated {filename}")

if __name__ == "__main__":
    main()
