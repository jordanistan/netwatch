# NetWatch Configuration Guide

This guide explains how to configure NetWatch for your specific needs.

## Configuration File

NetWatch uses a JSON configuration file located at `config/netwatch.json`:

```json
{
  "network": {
    "interface": "auto",
    "scan_interval": 300,
    "network_range": "192.168.1.0/24",
    "exclude_ips": [
      "192.168.1.1",
      "192.168.1.254"
    ]
  },
  "capture": {
    "max_file_size": "1GB",
    "rotation_count": 5,
    "capture_dir": "captures",
    "file_prefix": "netwatch",
    "filters": {
      "ports": [80, 443, 53],
      "protocols": ["tcp", "udp", "icmp"]
    }
  },
  "analysis": {
    "alert_threshold": 1000,
    "suspicious_ports": [22, 3389],
    "scan_detection": true,
    "data_retention_days": 30
  },
  "ui": {
    "refresh_interval": 5,
    "dark_mode": true,
    "chart_theme": "viridis",
    "max_devices_display": 50
  },
  "logging": {
    "level": "INFO",
    "file": "logs/netwatch.log",
    "max_size": "10MB",
    "backup_count": 3
  }
}
```

## Network Settings

### Interface Configuration
```json
"interface": {
  "auto": true,          // Auto-select interface
  "preferred": "eth0",   // Preferred interface
  "exclude": ["lo"]      // Excluded interfaces
}
```

### Scan Settings
```json
"scan": {
  "interval": 300,       // Scan interval in seconds
  "timeout": 2,         // ARP timeout in seconds
  "retry": 3,           // Retry attempts
  "parallel": 50        // Parallel scan limit
}
```

## Capture Settings

### File Management
```json
"capture": {
  "max_file_size": "1GB",
  "rotation_count": 5,
  "compression": true,
  "format": "pcap"
}
```

### Filters
```json
"filters": {
  "ports": [80, 443, 53],
  "protocols": ["tcp", "udp"],
  "exclude_ips": [
    "192.168.1.1",
    "192.168.1.254"
  ]
}
```

## Analysis Settings

### Detection Thresholds
```json
"thresholds": {
  "port_scan": 100,     // Connections per minute
  "bandwidth": "10MB",   // Per device
  "connections": 1000    // Per device
}
```

### Alert Configuration
```json
"alerts": {
  "email": {
    "enabled": true,
    "smtp_server": "smtp.example.com",
    "port": 587,
    "username": "alerts@example.com"
  },
  "webhook": {
    "enabled": false,
    "url": "https://hooks.example.com/netwatch"
  }
}
```

## UI Settings

### Display Options
```json
"ui": {
  "theme": "dark",
  "refresh_rate": 5,
  "max_items": 50,
  "charts": {
    "color_scheme": "viridis",
    "animation": true
  }
}
```

### Dashboard Layout
```json
"dashboard": {
  "default_view": "overview",
  "panels": [
    "network_map",
    "traffic_stats",
    "alerts"
  ]
}
```

## Environment Variables

NetWatch supports configuration via environment variables:

```bash
# Network Settings
NETWATCH_INTERFACE=eth0
NETWATCH_SCAN_INTERVAL=300

# Capture Settings
NETWATCH_CAPTURE_DIR=/path/to/captures
NETWATCH_MAX_FILESIZE=1GB

# Analysis Settings
NETWATCH_ALERT_THRESHOLD=1000
NETWATCH_RETENTION_DAYS=30

# UI Settings
NETWATCH_REFRESH_RATE=5
NETWATCH_DARK_MODE=true

# Security Settings
NETWATCH_ENCRYPTION_KEY=your-secret-key
```

## Command Line Arguments

Override configuration via command line:

```bash
# Network interface
streamlit run netwatch.py -- --interface eth0

# Capture duration
streamlit run netwatch.py -- --duration 3600

# PCAP analysis
streamlit run netwatch.py -- --pcap captures/traffic.pcap

# Debug mode
streamlit run netwatch.py -- --debug
```

## Configuration Profiles

Save different configurations for various use cases:

```json
"profiles": {
  "development": {
    "network": {
      "interface": "eth0",
      "scan_interval": 60
    }
  },
  "production": {
    "network": {
      "interface": "eth1",
      "scan_interval": 300
    }
  }
}
```

## Logging Configuration

### File Logging
```json
"logging": {
  "file": {
    "enabled": true,
    "path": "logs/netwatch.log",
    "level": "INFO",
    "rotation": {
      "max_size": "10MB",
      "backup_count": 3
    }
  }
}
```

### Syslog Integration
```json
"syslog": {
  "enabled": false,
  "host": "localhost",
  "port": 514,
  "facility": "local0"
}
```

## Security Settings

### Access Control
```json
"security": {
  "require_sudo": true,
  "allowed_users": [
    "admin",
    "netadmin"
  ]
}
```

### Data Protection
```json
"encryption": {
  "enabled": true,
  "algorithm": "AES-256",
  "key_file": "config/encryption.key"
}
```

## Best Practices

1. **Network Settings**
   - Use specific interfaces when possible
   - Set reasonable scan intervals
   - Exclude sensitive IPs

2. **Capture Settings**
   - Enable file rotation
   - Use compression
   - Set appropriate filters

3. **Security**
   - Use environment variables for secrets
   - Enable encryption
   - Restrict access appropriately

4. **Performance**
   - Adjust thresholds based on network size
   - Enable caching for better UI performance
   - Use appropriate logging levels
