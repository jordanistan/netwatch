<div align="center" id="top"> 
  <img src="https://media.tenor.com/images/af715c0a6016e077e27d332bb9858966/tenor.gif" alt="NetWatch" />

  &#xa0;
</div>

<h1 align="center">NetWatch 🕵️‍♂️</h1>

<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/jordanistan/netwatch?color=56BEB8">

  <img alt="Github language count" src="https://img.shields.io/github/languages/count/jordanistan/netwatch?color=56BEB8">

  <img alt="Repository size" src="https://img.shields.io/github/repo-size/jordanistan/netwatch?color=56BEB8">

  <img alt="License" src="https://img.shields.io/github/license/jordanistan/netwatch?color=56BEB8">
</p>

<p align="center">
  <a href="#dart-about">About</a> &#xa0; | &#xa0; 
  <a href="#sparkles-features">Features</a> &#xa0; | &#xa0;
  <a href="#white_check_mark-requirements">Requirements</a> &#xa0; | &#xa0;
  <a href="#checkered_flag-starting">Starting</a> &#xa0; | &#xa0;
  <a href="#memo-license">License</a> &#xa0; | &#xa0;
  <a href="https://github.com/jordanistan" target="_blank">Author</a>
</p>

<br>

## :dart: About

**EDUCATIONAL PURPOSES ONLY**

NetWatch is a network monitoring and traffic analysis tool with an interactive Streamlit dashboard, created for educational purposes to help students and security researchers understand network monitoring concepts, traffic analysis, and basic intrusion detection principles.

## ⚠️ Disclaimer

This tool is designed and intended **STRICTLY FOR EDUCATIONAL PURPOSES**. It should only be used in controlled environments where you have explicit permission to monitor the network traffic. Using this tool to monitor networks or devices without authorization may be illegal and unethical.

## :sparkles: Features

:heavy_check_mark: Core Features

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

## :white_check_mark: Requirements

Before starting :checkered_flag:, you need to have:
- [Docker](https://docs.docker.com/get-docker/) installed on your system
- Network access to the host machine

### Docker Security Setup (Recommended)

For enhanced security, it's recommended to run Docker in rootless mode:

```bash
# Install Docker rootless mode
dockerd-rootless-setuptool.sh install

# Start the rootless Docker daemon
systemctl --user start docker

# Enable auto-start of rootless Docker daemon
systemctl --user enable docker

# Add environment variables to your shell configuration (~/.bashrc or ~/.zshrc)
echo 'export PATH=/usr/bin:$PATH' >> ~/.bashrc
echo 'export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock' >> ~/.bashrc
```

Refer to the [Docker Rootless Mode documentation](https://docs.docker.com/engine/security/rootless/) for more details.

No other dependencies are required as everything runs inside the container!

## :checkered_flag: Starting ##

### 1. Initial Setup

```bash
# Clone the repository
git clone https://github.com/jordanistan/netwatch.git
cd netwatch

# Create necessary directories
mkdir -p captures logs reports

# Build the Docker image
docker build -t netwatch .
```

### 2. Choose Your Running Mode

NetWatch supports two running modes:

### Option A: Rootless Mode (Recommended for Learning)

```bash
# Start in rootless mode
docker run -d \
  --name netwatch \
  --network host \
  -v $(pwd)/captures:/app/captures \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  netwatch
```

### Option B: Privileged Mode (Full Features)

```bash
# Start with full network capabilities
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

### 3. Verify Installation

```bash
# Check if container is running
docker ps | grep netwatch

# Should see output like:
# CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS   PORTS   NAMES
# abc123...      netwatch  "..."     1m ago    Up 1m           netwatch

# View container logs
docker logs netwatch
```

```bash

> **Note**: In rootless mode, some network capabilities might be limited. If you need full network scanning capabilities, you may need to run in privileged mode with the appropriate security considerations.

#### Access Methods

1. From the host machine:

   - Open `http://localhost:8501`

2. From other devices on the LAN:

   - Open `http://<host-ip>:8501`
   - Replace `<host-ip>` with your host machine's IP address

## 🧪 Testing Features

### 1. Basic Network Tests

```bash
# Copy and run the test script
docker cp test_features.py netwatch:/app/
docker exec netwatch python3 test_features.py

# Expected output:
# 🚀 Starting comprehensive network tests...
# 🔍 Testing interface detection...
# 🔍 Testing network scanning...
# 🔍 Testing packet capture...
```

### 2. Security Analysis

```bash
# Run security scan
docker cp security_scan.py netwatch:/app/
docker exec netwatch python3 security_scan.py

# Expected output:
# 🔍 Starting security analysis...
# 📊 Security Analysis Summary
# - Threats Detected
# - Suspicious Activities
# - Vulnerabilities
```

### 3. Service Detection

```bash
# Run service analysis
docker cp service_scan.py netwatch:/app/
docker exec netwatch python3 service_scan.py

# Expected output:
# 🔍 Starting service analysis...
# 📊 Service Analysis Summary
# - Open Services
# - Protocol Distribution
```

### 4. View Test Results

```bash
# Check test reports
docker exec netwatch ls -l /app/reports/

# View latest report
docker exec netwatch cat /app/reports/test_report_<timestamp>.json
```

## 🎯 Dashboard Features

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

### Security Features

- Port scan detection
- Service fingerprinting
- Vulnerability assessment
- Traffic pattern analysis

## 🍓 Raspberry Pi Deployment

### Setting up Raspberry Pi

1. Install Docker on Raspberry Pi:

   ```bash
   curl -sSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```

2. Clone and deploy NetWatch:

   ```bash
   git clone https://github.com/jordanistan/netwatch.git
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

## 📊 Understanding Output Files

### Directory Structure

```plaintext
netwatch/
├── captures/           # Network capture files
│   └── *.pcap         # Raw packet captures
├── logs/              # Application logs
│   ├── app.log        # General application logs
│   └── alerts.log     # Security alerts
└── reports/           # Analysis reports
    ├── test_*.json    # Feature test results
    ├── security_*.json # Security scan results
    └── service_*.json  # Service analysis results
```

### Report Types

#### 1. Test Reports (`test_report_*.json`)

- Interface information
- Network scan results
- Packet capture statistics
- Traffic analysis

#### 2. Security Reports (`security_scan_*.json`)

- Detected threats
- Suspicious activities
- Vulnerabilities
- Protocol statistics

#### 3. Service Reports (`service_scan_*.json`)

- Open services
- SSL certificates
- Service vulnerabilities
- Protocol distribution

### Reading Reports

```bash
# View latest test report
docker exec netwatch cat /app/reports/test_report_*.json

# View security scan
docker exec netwatch cat /app/reports/security_scan_*.json

# View service analysis
docker exec netwatch cat /app/reports/service_scan_*.json
```

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

## Support me with Coffee

<a href="https://www.buymeacoffee.com/jordanistan" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/L4L4G6GQP)

## :memo: License

This project is released under the MIT License and is intended for educational purposes only.

Made with :heart: by <a href="https://github.com/jordanistan" target="_blank">Jordan Robison</a>

&#xa0;

<a href="#top">Back to top</a>
