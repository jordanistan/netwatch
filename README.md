# NetWatch 🕵️‍♂️

## Educational Notice

**EDUCATIONAL PURPOSES ONLY**

NetWatch is a network monitoring and traffic analysis tool with an interactive Streamlit dashboard, created for educational purposes to help students and security researchers understand network monitoring concepts, traffic analysis, and basic intrusion detection principles.

## ⚠️ Disclaimer

This tool is designed and intended **STRICTLY FOR EDUCATIONAL PURPOSES**. It should only be used in controlled environments where you have explicit permission to monitor the network traffic. Using this tool to monitor networks or devices without authorization may be illegal and unethical.

## 🎯 Features

### Core Features

- Network device discovery using ARP scanning
- Real-time traffic capture and analysis
- Device presence logging
- Traffic threshold monitoring
- Alert system (Email and Slack integration)
- Interactive menu-driven interface

### Analysis Features

- PCAP file analysis with detailed reports
- Interactive web dashboard
- Traffic visualization and charts
- Protocol distribution analysis
- Media stream detection
- File transfer monitoring

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

- Linux/Unix-based system
- Root/sudo privileges
- Required packages:
  - tcpdump
  - arp-scan
  - whiptail
  - mailutils (for email alerts)
  - curl (for Slack integration)
  - tshark (for PCAP analysis)
  - jq (for JSON processing)
  - modern web browser (for dashboard)

### Installation

```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install tcpdump arp-scan whiptail mailutils curl tshark jq

# On macOS with Homebrew
brew install tcpdump arp-scan whiptail mailutils curl wireshark jq
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
   - Click 'Scan Network' to discover devices
   - View device IP and MAC addresses

2. **Traffic Capture**:
   - Enter target IP address
   - Set capture duration
   - Start capture and monitor progress

3. **PCAP Analysis**:
   - Select captured PCAP file
   - View interactive visualizations
   - Analyze protocol distribution
   - Monitor packet sizes over time

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

## 📊 Output Files

### Capture Files

- `captures/`: PCAP format traffic captures
- `logs/`: Text-based device presence logs
- `alerts/`: Threshold violation records

### Analysis Files

- `reports/`: Individual analysis reports
  - `analysis.json`: Detailed packet analysis
  - `analysis.csv`: Tabular data export
  - `analysis.html`: Interactive visualizations
- `dashboard/`: Web dashboard files
  - `index.html`: Main dashboard interface
  - `captures.json`: Capture history

### Data Analysis

The analysis reports include:

- HTTP traffic patterns
- Media stream detection
- File transfer monitoring
- Protocol distribution
- Traffic volume over time

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
