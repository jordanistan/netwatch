# NetWatch API Reference

This document provides detailed information about NetWatch's API classes and functions.

## Network Scanner

### NetworkScanner Class

```python
class NetworkScanner:
    """Network device discovery and tracking."""
    
    def __init__(self, history_file=None):
        """Initialize scanner with optional history file."""
        
    def scan_devices(self, interface, network_range):
        """
        Scan network for devices using ARP.
        
        Args:
            interface (str): Network interface to use
            network_range (str): CIDR range to scan
            
        Returns:
            list: List of discovered devices
        """
        
    def get_device_history(self, ip=None, mac=None):
        """
        Get device history from database.
        
        Args:
            ip (str, optional): IP address to lookup
            mac (str, optional): MAC address to lookup
            
        Returns:
            dict: Device history data
        """
        
    def get_new_devices(self, limit=10):
        """
        Get recently discovered devices.
        
        Args:
            limit (int): Maximum number of devices to return
            
        Returns:
            list: List of new devices
        """
```

## Traffic Monitor

### DeviceMonitor Class

```python
class DeviceMonitor:
    """Network traffic monitoring and capture."""
    
    def __init__(self, capture_dir="captures"):
        """Initialize monitor with capture directory."""
        
    def start_monitoring(self, target_ip=None, duration=None):
        """
        Start monitoring network traffic.
        
        Args:
            target_ip (str, optional): IP to monitor
            duration (int, optional): Capture duration in seconds
        """
        
    def stop_monitoring(self):
        """Stop active monitoring session."""
        
    def get_traffic_stats(self):
        """
        Get current traffic statistics.
        
        Returns:
            dict: Traffic statistics
        """
```

## PCAP Analyzer

### PcapAnalyzer Class

```python
class PcapAnalyzer:
    """PCAP file analysis and reporting."""
    
    def __init__(self, pcap_file):
        """Initialize analyzer with PCAP file."""
        
    def analyze(self):
        """
        Analyze PCAP file contents.
        
        Returns:
            dict: Analysis results
        """
        
    def detect_anomalies(self):
        """
        Detect suspicious patterns.
        
        Returns:
            list: Detected anomalies
        """
        
    def generate_report(self, output_format="json"):
        """
        Generate analysis report.
        
        Args:
            output_format (str): Report format
            
        Returns:
            str: Report path
        """
```

## UI Components

### Page Setup

```python
def setup_page():
    """Setup the main page configuration."""
```

### Network Information

```python
def show_network_info(interface, ip):
    """
    Display network information in sidebar.
    
    Args:
        interface (str): Network interface
        ip (str): IP address
    """
```

### Scan Results

```python
def show_scan_results(devices, netwatch):
    """
    Display network scan results.
    
    Args:
        devices (list): List of discovered devices
        netwatch (NetWatch): NetWatch instance
    """
```

### Traffic Capture UI

```python
def show_traffic_capture_ui(netwatch, devices):
    """
    Display traffic capture interface.
    
    Args:
        netwatch (NetWatch): NetWatch instance
        devices (list): List of devices
    """
```

### PCAP Analysis

```python
def show_pcap_analysis(stats):
    """
    Display PCAP analysis results.
    
    Args:
        stats (dict): Analysis statistics
    """
```

## Utility Functions

### Duration Formatting

```python
def format_duration(value):
    """
    Format duration for display.
    
    Args:
        value (int): Duration in seconds
            
    Returns:
        str: Formatted duration string
    """
```

### Byte Formatting

```python
def format_bytes(size):
    """
    Format bytes to human readable format.
    
    Args:
        size (int): Size in bytes
            
    Returns:
        str: Formatted size string
    """
```

## Event Handlers

### Device Events

```python
def on_device_found(device):
    """
    Handle new device discovery.
    
    Args:
        device (dict): Device information
    """
```

### Alert Events

```python
def on_alert(alert_type, details):
    """
    Handle alert generation.
    
    Args:
        alert_type (str): Type of alert
        details (dict): Alert details
    """
```

## Configuration Functions

### Load Configuration

```python
def load_config(config_file):
    """
    Load configuration from file.
    
    Args:
        config_file (str): Path to config file
            
    Returns:
        dict: Configuration data
    """
```

### Save Configuration

```python
def save_config(config_data, config_file):
    """
    Save configuration to file.
    
    Args:
        config_data (dict): Configuration to save
        config_file (str): Path to config file
    """
```

## Error Handling

### Custom Exceptions

```python
class NetworkError(Exception):
    """Network operation error."""
    pass

class CaptureError(Exception):
    """Packet capture error."""
    pass

class AnalysisError(Exception):
    """PCAP analysis error."""
    pass
```

## Return Types

### Device Information

```python
{
    "ip": "192.168.1.100",
    "mac": "00:11:22:33:44:55",
    "hostname": "device.local",
    "first_seen": "2025-04-14T04:20:48",
    "last_seen": "2025-04-14T04:35:35",
    "status": "active"
}
```

### Traffic Statistics

```python
{
    "packets": 1000,
    "bytes": 1048576,
    "protocols": {
        "TCP": 750,
        "UDP": 200,
        "ICMP": 50
    },
    "ports": {
        "80": 500,
        "443": 250
    }
}
```

### Analysis Results

```python
{
    "summary": {
        "duration": 3600,
        "total_packets": 1000
    },
    "anomalies": [
        {
            "type": "port_scan",
            "source": "192.168.1.42",
            "time": "2025-04-14T04:30:00"
        }
    ]
}
```
