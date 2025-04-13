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

- Docker installed on your system ([Get Docker](https://docs.docker.com/get-docker/))
- Network access to the host machine

No other dependencies are required as everything runs inside the container!

## 🚀 Quick Start

### 1. Clone and Build

```bash
# Clone the repository
git clone https://github.com/yourusername/netwatch.git
cd netwatch

# Build the Docker image
docker build -t netwatch .
```

### 2. Run the Container

```bash
docker run -d \
  --name netwatch \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v $(pwd)/captures:/app/captures \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  netwatch
```

### 3. Access the Dashboard

1. From the host machine:
   - Open `http://localhost:8501`

2. From other devices on the LAN:
   - Open `http://<host-ip>:8501`
   - Replace `<host-ip>` with your host machine's IP address

## 🎯 Features

### Network Discovery
- Automatic LAN interface detection
- ARP-based device scanning
- MAC address resolution
- Hostname detection (when available)

### Traffic Analysis
- Real-time packet capture
- Protocol distribution visualization
- Traffic volume monitoring
- Interactive time-series graphs

### PCAP Management
- Save captures for later analysis
- Import existing PCAP files
- Generate detailed traffic reports
- Export data in multiple formats

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
