# Getting Started with NetWatch

This guide will help you get NetWatch up and running on your system.

## Prerequisites

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

## Installation

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

## Quick Start

1. Start the NetWatch dashboard:
```bash
sudo streamlit run netwatch.py
```

2. Open your web browser and navigate to:
```
http://localhost:8501
```

## Basic Usage

### Network Scanning
```bash
# Start NetWatch with network scanning
sudo streamlit run netwatch.py -- --scan
```

### Traffic Capture
```bash
# Start capture for specific device
sudo streamlit run netwatch.py -- --capture --target 192.168.1.100
```

### PCAP Analysis
```bash
# Analyze existing PCAP file
streamlit run ui/pcap_analyzer.py -- --pcap captures/traffic.pcap
```

## Directory Structure

```
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
├── captures/               # PCAP files
├── config/                 # Configuration
└── reports/                # Analysis output
```

## Next Steps

- Read the [Technical Documentation](technical.md) for detailed information about NetWatch's architecture
- Check the [Configuration Guide](configuration.md) to customize NetWatch for your needs
- Review the [Security Guide](security.md) for best practices and safety considerations
