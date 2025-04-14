# NetWatch Troubleshooting Guide

This guide helps you diagnose and resolve common issues with NetWatch.

## Common Issues

### Installation Problems

1. **Missing Dependencies**
   ```bash
   Error: No module named 'scapy'
   ```
   
   Solution:
   ```bash
   pip install -r requirements.txt
   ```

2. **Permission Errors**
   ```bash
   Error: Permission denied (PCAP)
   ```
   
   Solution:
   ```bash
   sudo setcap cap_net_raw=eip /usr/bin/python3
   # or run with sudo
   sudo streamlit run netwatch.py
   ```

### Network Issues

1. **Interface Not Found**
   ```bash
   Error: Interface eth0 not found
   ```
   
   Solution:
   - Check available interfaces:
     ```bash
     ip link show
     # or
     ifconfig -a
     ```
   - Update configuration with correct interface

2. **No Devices Found**
   ```
   Warning: No devices discovered
   ```
   
   Troubleshooting:
   - Verify network connection
   - Check interface configuration
   - Confirm network range setting
   - Review firewall rules

### Capture Problems

1. **Cannot Create PCAP**
   ```
   Error: Cannot create capture file
   ```
   
   Check:
   - Directory permissions
   - Disk space
   - File system permissions

2. **Capture Not Starting**
   ```
   Error: Failed to start capture
   ```
   
   Verify:
   - Root/sudo privileges
   - Interface availability
   - Capture directory exists

## Error Messages

### Network Scanner

```python
# Error: Network unreachable
def troubleshoot_network():
    # Check network connection
    if not check_connectivity():
        print("Network connection issue")
    # Verify interface
    if not check_interface():
        print("Interface problem")
    # Test permissions
    if not check_permissions():
        print("Permission error")
```

### Traffic Monitor

```python
# Error: Cannot monitor traffic
def troubleshoot_monitor():
    # Check PCAP access
    if not check_pcap_access():
        print("PCAP access denied")
    # Verify storage
    if not check_storage():
        print("Insufficient storage")
    # Test filters
    if not check_filters():
        print("Invalid filter configuration")
```

## Performance Issues

### High CPU Usage

1. **Cause**: Excessive packet capture
   
   Solution:
   ```python
   # Adjust capture filters
   capture_settings = {
       "snapshot_len": 96,
       "buffer_size": 1024 * 1024
   }
   ```

2. **Cause**: Large PCAP analysis
   
   Solution:
   ```python
   # Enable chunked processing
   analysis_settings = {
       "chunk_size": 1000,
       "parallel": True
   }
   ```

### Memory Problems

1. **Cause**: Large device list
   
   Solution:
   ```python
   # Enable pagination
   ui_settings = {
       "page_size": 50,
       "cache": True
   }
   ```

2. **Cause**: PCAP buffer overflow
   
   Solution:
   ```python
   # Adjust buffer settings
   buffer_settings = {
       "max_size": "512MB",
       "flush_interval": 60
   }
   ```

## Configuration Issues

### Invalid Settings

1. **Syntax Errors**
   ```json
   {
     "network": {
       "interface": "eth0"
       "scan_interval": 300  // Missing comma
     }
   }
   ```
   
   Solution:
   - Validate JSON syntax
   - Use configuration validator

2. **Invalid Values**
   ```python
   # Check configuration values
   def validate_config():
       if config["scan_interval"] < 60:
           raise ValueError("Scan interval too short")
   ```

## UI Problems

### Dashboard Not Loading

1. **Streamlit Issues**
   ```bash
   # Clear cache
   rm -rf ~/.streamlit/
   
   # Restart server
   pkill streamlit
   streamlit run netwatch.py
   ```

2. **Browser Problems**
   - Clear browser cache
   - Try different browser
   - Check JavaScript console

### Chart Display Issues

1. **No Data Shown**
   ```python
   # Verify data format
   def check_chart_data():
       if df.empty:
           print("No data available")
       if not correct_columns():
           print("Invalid data format")
   ```

2. **Performance Issues**
   ```python
   # Optimize chart rendering
   chart_settings = {
       "max_points": 1000,
       "aggregation": True
   }
   ```

## System Requirements

### Minimum Requirements

- Python 3.9+
- 2GB RAM
- 1GB free disk space
- Network interface
- Root/sudo access

### Recommended Setup

- Python 3.11+
- 4GB RAM
- 10GB free disk space
- Dedicated network interface
- SSD storage

## Diagnostic Tools

### Network Diagnostics

```python
def run_diagnostics():
    """Run network diagnostic tests."""
    # Check connectivity
    if not ping_test():
        return "Network connectivity issue"
    
    # Test interface
    if not interface_test():
        return "Interface problem"
    
    # Verify permissions
    if not permission_test():
        return "Permission error"
    
    return "All tests passed"
```

### System Checks

```python
def system_check():
    """Check system requirements."""
    # Check Python version
    if sys.version_info < (3, 9):
        print("Python version too old")
    
    # Check memory
    if available_memory() < 2 * 1024 * 1024 * 1024:
        print("Insufficient memory")
    
    # Check disk space
    if free_disk_space() < 1024 * 1024 * 1024:
        print("Low disk space")
```

## FAQ

1. **Q: Why is the scan taking too long?**
   
   A: Check:
   - Network range size
   - Scan interval setting
   - Network congestion
   - System resources

2. **Q: Why are some devices not showing up?**
   
   A: Verify:
   - Device is active
   - Within network range
   - Not in exclusion list
   - Firewall settings

3. **Q: How do I reduce resource usage?**
   
   A: Try:
   - Adjust scan interval
   - Limit capture size
   - Enable data rotation
   - Use efficient filters

## Support

### Getting Help

1. **Documentation**
   - [Technical Guide](technical.md)
   - [API Reference](api-reference.md)
   - [Configuration Guide](configuration.md)

2. **Issue Reporting**
   - Include error messages
   - Provide system info
   - Share configuration
   - Describe steps to reproduce

### Debug Mode

```bash
# Enable debug logging
export NETWATCH_DEBUG=1
streamlit run netwatch.py -- --debug

# Check logs
tail -f logs/netwatch.log
```
