# NetWatch Technical Documentation

This document provides technical details about NetWatch's architecture, components, and implementation.

## Architecture Overview

NetWatch follows a modular architecture with three main components:

1. Network Operations
2. Data Processing
3. User Interface

### System Architecture Diagram

```
[Network Interface]
       ↓
[Network Scanner] → [Device History]
       ↓
[Traffic Monitor] → [PCAP Files]
       ↓
[PCAP Analyzer]  → [Analysis Reports]
       ↓
[Streamlit UI] ← [Visualization Engine]
```

## Components

### 1. Network Scanner (`network/scanner.py`)

The network scanner uses ARP requests to discover devices on the network.

Key Features:
- ARP-based device discovery
- MAC address resolution
- Hostname lookup
- Device history tracking
- Activity status monitoring

Example Usage:
```python
from network.scanner import NetworkScanner

scanner = NetworkScanner()
devices = scanner.scan_devices(interface="eth0", network_range="192.168.1.0/24")
```

### 2. Traffic Monitor (`network/monitor.py`)

Monitors network traffic and captures packets based on configured filters.

Key Features:
- Real-time packet capture
- Traffic filtering
- Packet analysis
- Data usage tracking
- Alert generation

Example Usage:
```python
from network.monitor import DeviceMonitor

monitor = DeviceMonitor()
monitor.start_monitoring(target_ip="192.168.1.100", duration=3600)
```

### 3. PCAP Analyzer (`network/pcap_analyzer.py`)

Analyzes captured PCAP files for suspicious patterns and network behavior.

Key Features:
- Protocol analysis
- Port scanning detection
- Data exfiltration detection
- Attack pattern recognition
- Traffic visualization

Example Usage:
```python
from network.pcap_analyzer import PcapAnalyzer

analyzer = PcapAnalyzer("captures/traffic.pcap")
stats = analyzer.analyze()
```

### 4. UI Components (`ui/components.py`)

Streamlit-based user interface components for data visualization and interaction.

Key Features:
- Real-time updates
- Interactive charts
- Device management
- Capture controls
- Analysis reports

Example Usage:
```python
from ui.components import show_network_info, show_scan_results

show_network_info(interface="eth0", ip="192.168.1.10")
show_scan_results(devices=devices, netwatch=netwatch)
```

## Data Flow

1. **Device Discovery**
   ```
   ARP Request → Response → Device Info → History DB
   ```

2. **Traffic Capture**
   ```
   Network Packets → Filter → Buffer → PCAP File
   ```

3. **Analysis Pipeline**
   ```
   PCAP File → Parser → Analyzer → Reports → Visualization
   ```

## Dependencies

### Core Dependencies
- `streamlit`: Web interface framework
- `scapy`: Network packet manipulation
- `pandas`: Data analysis and manipulation
- `plotly`: Interactive visualizations

### System Dependencies
- `tcpdump`: Packet capture
- `tshark`: Packet analysis
- `netifaces`: Network interface detection

## Performance Considerations

1. **Memory Usage**
   - PCAP files are read in chunks
   - Large datasets use pandas optimization
   - Visualization data is cached

2. **CPU Usage**
   - Packet capture is multi-threaded
   - Analysis tasks are batched
   - UI updates are optimized

3. **Network Impact**
   - ARP scanning is rate-limited
   - Capture filters reduce overhead
   - Data is compressed when stored

## Security Implementation

1. **Access Control**
   - Root privileges only for capture
   - Restricted file permissions
   - Configurable interface access

2. **Data Protection**
   - PCAP file encryption
   - Secure temporary storage
   - Configurable data retention

3. **Network Safety**
   - Rate limiting
   - Blacklist support
   - Alert thresholds

## Error Handling

1. **Network Errors**
   ```python
   try:
       scanner.scan_devices()
   except NetworkError as e:
       logger.error(f"Scan failed: {e}")
   ```

2. **File Operations**
   ```python
   try:
       with open(pcap_file, 'rb') as f:
           packets = rdpcap(f)
   except FileNotFoundError:
       logger.error("PCAP file not found")
   ```

3. **Permission Errors**
   ```python
   if not os.access(capture_dir, os.W_OK):
       raise PermissionError("Cannot write to capture directory")
   ```

## Logging and Monitoring

1. **Application Logs**
   ```python
   logger.info("Starting network scan")
   logger.debug(f"Found {len(devices)} devices")
   logger.warning("High traffic detected")
   logger.error("Capture failed")
   ```

2. **Performance Metrics**
   - Scan duration
   - Capture statistics
   - Analysis timing
   - Memory usage

3. **Health Checks**
   - Interface status
   - Disk space
   - Memory availability
   - Process status

## Configuration Management

Configuration is managed through JSON files in the `config/` directory:

```json
{
  "network": {
    "interface": "auto",
    "scan_interval": 300
  },
  "capture": {
    "max_size": "1GB",
    "rotation": true
  },
  "analysis": {
    "threshold": 1000,
    "alert": true
  }
}
```

## Further Reading

- [API Reference](api-reference.md) for detailed function documentation
- [Configuration Guide](configuration.md) for setup options
- [Security Guide](security.md) for security best practices
