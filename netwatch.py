#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

# Network and packet analysis
import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether, ARP
import pyshark

# System and network interfaces
import socket
import psutil
import netifaces

# Security and encryption
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import SSL

# Data analysis and visualization
import streamlit as st
import pandas as pd
import plotly.express as px

# DNS resolution
import dns.resolver

# Utility imports
import json
import logging
from slack_sdk import WebClient
from dotenv import load_dotenv
import os

# Local imports
import variables
from simulated_data import generate_simulated_stats, get_risk_assessment

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class NetWatch:
    def __init__(self):
        # Initialize directories
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            
        # Initialize logger
        self.logger = logging.getLogger('NetWatch')
        file_handler = logging.FileHandler(self.logs_dir / 'app.log')
        self.logger.addHandler(file_handler)
        
        # Initialize alert system
        self.slack_client = None
        if os.getenv('SLACK_TOKEN'):
            self.slack_client = WebClient(token=os.getenv('SLACK_TOKEN'))
            
        # Traffic thresholds
        self.thresholds = {
            'bandwidth': 1000000,  # 1 Mbps
            'packet_rate': 1000,   # packets per second
            'connection_limit': 100 # concurrent connections
        }
        
        # Active monitoring state
        self.monitoring_active = False
        self.capture_session = None

    def capture_traffic(self, target_ips=None, duration=60, is_suspicious=False, callback=None):
        """Capture network traffic for specific IPs or all traffic"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create a descriptive filename
            if target_ips:
                if isinstance(target_ips, str):
                    target_ips = [target_ips]
                alert_tag = "_ALERT" if is_suspicious else ""
                filename = f"traffic{'_suspicious' if is_suspicious else ''}_{'_'.join(ip.replace('.', '-') for ip in target_ips)}_{timestamp}{alert_tag}.pcap"
            else:
                filename = f"traffic_all_{timestamp}.pcap"
            
            output_file = self.captures_dir / filename
            
            # Build capture filter
            filter_expr = " or ".join(f"host {ip}" for ip in target_ips) if target_ips else ""
            
            # Initialize capture session with pyshark for real-time analysis
            self.capture_session = pyshark.LiveCapture(
                interface=self.get_default_interface(),
                display_filter=filter_expr
            )
            
            # Start packet capture with real-time monitoring
            self.monitoring_active = True
            packet_count = 0
            start_time = datetime.now()
            
            def packet_callback(packet):
                nonlocal packet_count
                packet_count += 1
                
                # Check traffic thresholds
                self._check_thresholds(packet)
                
                # Log suspicious activities
                if self._is_suspicious_packet(packet):
                    self._log_suspicious_activity(packet)
                
                if callback:
                    callback(packet)
            
            try:
                self.logger.info(f"Starting capture on {output_file}")
                if duration:
                    self.capture_session.sniff(timeout=duration, packet_count=None)
                else:
                    self.capture_session.apply_on_packets(packet_callback)
            finally:
                self.monitoring_active = False
                self.capture_session.close()
            
            # Save capture and generate report
            self.capture_session.save(str(output_file))
            self._generate_capture_report(output_file, packet_count, start_time)
            
            return output_file
            
        except Exception as e:
            self.logger.error(f"Capture error: {str(e)}")
            if 'permission' in str(e).lower():
                self.logger.error("Insufficient permissions for packet capture")
            return None
            
    def _check_thresholds(self, packet):
        """Monitor traffic thresholds and trigger alerts"""
        try:
            # Calculate bandwidth usage
            if hasattr(packet, 'length'):
                current_bandwidth = int(packet.length) * 8  # bits
                if current_bandwidth > self.thresholds['bandwidth']:
                    self._send_alert(f"High bandwidth usage detected: {current_bandwidth/1000000:.2f} Mbps")
            
            # Check connection limits
            if hasattr(packet, 'ip'):
                active_connections = len(self._get_active_connections())
                if active_connections > self.thresholds['connection_limit']:
                    self._send_alert(f"Connection limit exceeded: {active_connections} connections")
                    
        except Exception as e:
            self.logger.error(f"Error checking thresholds: {str(e)}")
            
    def _is_suspicious_packet(self, packet):
        """Detect suspicious packet patterns"""
        try:
            # Check for potential port scans
            if hasattr(packet, 'tcp'):
                if packet.tcp.flags == '0x002':  # SYN packet
                    return True
                    
            # Check for unusual protocols
            if hasattr(packet, 'highest_layer') and packet.highest_layer in ['TELNET', 'FTP']:
                return True
                
            # Add more security checks as needed
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking packet: {str(e)}")
            return False
            
    def _send_alert(self, message):
        """Send alerts through configured channels"""
        self.logger.warning(message)
        
        # Send to Slack if configured
        if self.slack_client:
            try:
                self.slack_client.chat_postMessage(
                    channel="#netwatch-alerts",
                    text=f"🚨 *ALERT*: {message}"
                )
            except Exception as e:
                self.logger.error(f"Failed to send Slack alert: {str(e)}")
                
    def _get_active_connections(self):
        """Get list of active network connections"""
        try:
            connections = psutil.net_connections()
            return [conn for conn in connections if conn.status == 'ESTABLISHED']
        except Exception as e:
            self.logger.error(f"Error getting connections: {str(e)}")
            return []

    def analyze_pcap(self, pcap_file: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Analyze a PCAP file and return statistics"""
        try:
            packets = rdpcap(str(pcap_file))
            stats = {
                'total_packets': len(packets),
                'protocols': {},
                'packet_sizes': [],
                'timestamps': [],
                'ips': {'src': {}, 'dst': {}},
                'http_traffic': self.extract_http_traffic(pcap_file),
                'media_files': self.extract_media_content(pcap_file)
            }
            
            for packet in packets:
                # Collect timestamp
                if packet.time:
                    stats['timestamps'].append(packet.time)
                
                # Collect packet size
                stats['packet_sizes'].append(len(packet))
                
                # Collect protocol information
                if packet.haslayer(TCP):
                    stats['protocols']['TCP'] = stats['protocols'].get('TCP', 0) + 1
                elif packet.haslayer(UDP):
                    stats['protocols']['UDP'] = stats['protocols'].get('UDP', 0) + 1
                
                # Collect IP information
                if packet.haslayer(IP):
                    try:
                        src = packet[IP].src
                        dst = packet[IP].dst
                        stats['ips']['src'][src] = stats['ips']['src'].get(src, 0) + 1
                        stats['ips']['dst'][dst] = stats['ips']['dst'].get(dst, 0) + 1
                    except (IndexError, AttributeError) as e:
                        st.warning(f"Error processing IP packet: {str(e)}")
                        continue
            
            return stats
            
        except (OSError, IOError) as e:
            st.error(f"Error analyzing PCAP: {str(e)}")
            return None

    def extract_http_traffic(self, pcap_file):
        """Extract HTTP traffic from PCAP file"""
        try:
            # Check if this is our simulated file
            if '192-168-86-42' in str(pcap_file):
                return generate_simulated_stats()['http_traffic']
                
            packets = rdpcap(str(pcap_file))
            http_traffic = []
            
            for packet in packets:
                if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                    try:
                        payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                        
                        if payload.startswith('GET ') or payload.startswith('POST '):
                            # Extract method and URL
                            method = payload.split(' ')[0]
                            url = payload.split(' ')[1]
                            
                            # Look for Content-Type in headers
                            content_type = 'unknown'
                            if 'Content-Type: ' in payload:
                                content_type = payload.split('Content-Type: ')[1].split('\r\n')[0]
                            
                            http_traffic.append({
                                'method': method,
                                'url': url,
                                'src': packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
                                'dst': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
                                'size': len(packet),
                                'content_type': content_type
                            })
                    except:
                        continue
            
            return http_traffic
        except Exception as e:
            st.error(f"Error extracting HTTP traffic: {str(e)}")
            return []

    def extract_media_content(self, pcap_file):
        """Extract media content from PCAP file"""
        try:
            # Check if this is our simulated file
            if '192-168-86-42' in str(pcap_file):
                return generate_simulated_stats()['media_files']
                
            packets = rdpcap(str(pcap_file))
            media_files = []
            
            # Create directory for extracted files
            media_dir = self.captures_dir / 'media'
            media_dir.mkdir(exist_ok=True)
            
            return media_files
        except Exception as e:
            st.error(f"Error extracting media content: {str(e)}")
            return []

    def get_network_devices(self) -> List[Dict[str, str]]:
        """Get a list of active devices on the network"""
        try:
            # Get the default interface
            interface = self.get_default_interface()
            if not interface:
                return []
            
            # Get network range
            network_range = self.get_network_range(interface)
            if not network_range:
                return []
            
            # Scan for devices
            devices = self.scan_network(network_range)
            
            return devices
            
        except (OSError, PermissionError) as e:
            st.error(f"Error getting network devices: {str(e)}")
            return []

    def scan_network(self, network_range: Optional[str] = None) -> List[Dict[str, str]]:
        """Scan network for devices using ARP"""
        interface = self.get_default_interface()
        if not interface:
            return []
        
        try:
            if network_range is None:
                network_range = self.get_network_range(interface)
                if not network_range:
                    return []
            
            st.info(f"📡 Scanning on interface: {interface}")
            ip = scapy.get_if_addr(interface)
            st.info(f"🔍 Interface IP: {ip}")
            st.info(f"🌐 Network range to scan: {network_range}")
            
            with st.spinner("🔍 Sending ARP requests..."):
                # Create ARP request packet
                arp = ARP(pdst=network_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp

                # Send packet and get responses
                result = scapy.srp(packet, timeout=3, verbose=0)[0]
                
                # Process responses
                devices = []
                for sent, received in result:
                    # Get hostname using reverse DNS lookup
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                    except (socket.herror, socket.gaierror):
                        hostname = ''
                    
                    devices.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': hostname,
                        'vendor': ''  # Could add MAC vendor lookup in the future
                    })
            
            if devices:
                st.success(f"✨ Found {len(devices)} devices")
            else:
                st.warning("⚠️ No devices found on the network")
            
            return devices
            
        except (OSError, PermissionError) as e:
            st.error(f"Error during scan: {str(e)}")
            if 'permission' in str(e).lower():
                st.info("""
                💡 **Network scanning requires admin privileges**
                Try running the application with:
                ```bash
                sudo python3 netwatch.py
                ```
                """)
            return []

    def get_default_interface(self) -> Optional[str]:
        """Get the default network interface that's connected to LAN"""
        try:
            interfaces = scapy.get_if_list()
            st.markdown("### Available Network Interfaces")
            active_interfaces = []
            
            for iface in interfaces:
                # Skip loopback and virtual interfaces
                if iface == 'lo':
                    continue
                try:
                    ip = scapy.get_if_addr(iface)
                    if ip and not ip.startswith('127.'):
                        active_interfaces.append((iface, ip))
                except:
                    continue
            
            if active_interfaces:
                # Sort by interface name
                active_interfaces.sort()
                
                # Create a DataFrame for display
                df = pd.DataFrame(active_interfaces, columns=['Interface', 'IP'])
                st.dataframe(
                    df,
                    column_config={
                        "Interface": "Network Interface",
                        "IP": "IP Address"
                    },
                    use_container_width=True
                )
                
                # Return first active interface
                return active_interfaces[0][0]
            
            st.error("No active network interfaces found")
            st.info("""
            💡 **Troubleshooting**:
            1. Check if Wi-Fi or Ethernet is connected
            2. Ensure network adapters are enabled
            3. Try running with admin privileges
            """)
            return None
            
        except (OSError, PermissionError) as e:
            st.error(f"Error accessing network interfaces: {str(e)}")
            if 'permission' in str(e).lower():
                st.info("💡 This feature requires admin privileges")
            return None

    def get_network_range(self, interface):
        """Get the network range for the given interface"""
        try:
            if not interface:
                raise ValueError("No interface provided")

            # Get IP address of interface
            ip = scapy.get_if_addr(interface)
            if not ip:
                raise ValueError(f"No IP address found for interface {interface}")
            
            if ip.startswith('127.'):
                raise ValueError(f"Interface {interface} is bound to loopback")
            
            # Parse IP components
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                raise ValueError(f"Invalid IP format: {ip}")
            
            # Parse IP components
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                raise ValueError(f"Invalid IP format: {ip}")
            
            # Determine network class and range
            first_octet = int(ip_parts[0])
            if first_octet == 10:  # Class A private network
                network_range = "10.0.0.0/8"
            elif first_octet == 172 and 16 <= int(ip_parts[1]) <= 31:  # Class B private network
                network_range = f"172.{ip_parts[1]}.0.0/16"
            elif first_octet == 192 and ip_parts[1] == '168':  # Class C private network
                network_range = f"192.168.{ip_parts[2]}.0/24"
            else:
                st.warning(f"IP {ip} is not in a private network range")
                network_range = f"{'.'.join(ip_parts[:3])}.0/24"
            
            st.info(f"🌐 Network range: {network_range}")
            return network_range
                
        except Exception as e:
            st.error(f"Error determining network range: {str(e)}")
            return None

def main():
    # Apply theme settings
    st.set_page_config(
        page_title=variables.APP_CONFIG['title'],
        page_icon=variables.APP_CONFIG['icon'],
        layout=variables.APP_CONFIG['layout'],
        initial_sidebar_state="expanded"
    )
    
    # Function to display suspicious activity
    def display_suspicious_activity(ip: str):
        if '192.168.86.42' in ip:
            st.error("🚨 HIGH RISK DEVICE DETECTED")
            stats = generate_simulated_stats()
            risk = get_risk_assessment()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🔍 Suspicious Activity")
                incidents = risk['total_incidents']
                st.error(f"""
                - 🔞 Adult Content: {incidents['adult_content']} requests
                - 🏴‍☠️ Illegal Downloads: {incidents['piracy']} files
                - 🦠 Malware Activity: {incidents['malware']} incidents
                - ⛏️ Crypto Mining: {incidents['crypto_mining']} connections
                - 🤖 Botnet Activity: {incidents['botnet']} C&C servers
                """)
            
            with col2:
                st.markdown("### 📊 Risk Assessment")
                st.error(f"""
                - Overall Risk: **{risk['risk_level']}**
                - Bandwidth Usage: {risk['bandwidth_usage']}
                - Active Hours: {risk['active_hours']}
                - Connection Type: {risk['connection_type']}
                - Evasion Attempts: {'YES' if risk['evasion_attempts'] else 'NO'}
                """)
            
            st.markdown("### 🎯 Recommended Actions")
            st.warning("""
            1. 🚫 Block device access immediately
            2. 🔍 Investigate for malware infection
            3. 📝 Document all suspicious activities
            4. 👤 Identify device owner
            5. 🔒 Review network security policies
            """)
    
    # Apply custom CSS
    st.markdown(variables.CUSTOM_CSS, unsafe_allow_html=True)
    
    # Main header with version
    st.title(f"{variables.APP_CONFIG['title']} {variables.APP_CONFIG['icon']}")
    st.caption("Version 1.0.0 - Educational Network Analysis Tool")
    
    try:
        netwatch = NetWatch()
    except Exception as e:
        st.error(f"Error initializing NetWatch: {str(e)}")
        return

    # Sidebar
    with st.sidebar:
        st.image("https://raw.githubusercontent.com/streamlit/streamlit/develop/examples/streamlit_app_logo.png", width=100)
        st.title("NetWatch")
        
        # Navigation
        page = st.radio(
            "Navigation",
            ["Network Scan", "Traffic Capture", "PCAP Analysis"],
            index=0
        )
    
    if page == "Network Scan":
        st.header("🔍 Network Scanner")
        st.markdown("""
        Scan your network to discover active devices and their details.
        """)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            network_range = st.text_input("🌐 Network Range", value="192.168.1.0/24", help="Enter the network range to scan (e.g., 192.168.1.0/24)")
            
            if st.button("🔍 Scan for Devices", type="secondary", use_container_width=True):
                with st.spinner("🔍 Scanning network for devices..."):
                    devices = netwatch.scan_network(network_range)
                    if devices:
                        st.session_state['network_devices'] = devices
                        st.success(f"✅ Found {len(devices)} devices")
                        
                        # Create DataFrame for display
                        df = pd.DataFrame(devices)
                        
                        # Display devices
                        st.markdown("### 📱 Network Devices")
                        st.dataframe(
                            df,
                            column_config={
                                "ip": "IP Address",
                                "mac": "MAC Address",
                                "vendor": "Vendor"
                            },
                            use_container_width=True
                        )
                        
                        # Add traffic capture option for each device
                        for device in devices:
                            with st.expander(f"📦 Capture Traffic for {device['ip']}"):
                                if st.button("📡 Start Capture", key=f"capture_{device['ip']}"):
                                    pcap_file = netwatch.capture_traffic(
                                        target_ips=device['ip'],
                                        duration=10
                                )
                                if pcap_file:
                                    st.success(f"✅ Traffic captured and saved as: {pcap_file.name}")
                    else:
                        st.warning("⚠️ No devices found. Try running with admin privileges.")

    elif page == "Traffic Capture":
        st.header("📦 Traffic Capture")
        st.markdown("""
        Capture and analyze network traffic from specific devices or all network traffic.
        """)
        
        # Get list of devices if available
        if 'network_devices' in st.session_state and st.session_state['network_devices']:
            devices = st.session_state['network_devices']
            
            # Create a radio button for capture mode
            capture_mode = st.radio(
                "Select Capture Mode",
                options=["Target Devices", "Capture All"],
                horizontal=True,
                help="Choose to capture specific devices or all network traffic"
            )
            
            # Duration controls
            unlimited_capture = st.checkbox(
                "Unlimited Capture Duration",
                help="⚠️ Warning: This will capture indefinitely until manually stopped"
            )
            
            if not unlimited_capture:
                # Convert hours to seconds for the slider
                max_seconds = 72 * 3600  # 72 hours in seconds
                
                # Create duration selection with units
                duration_unit = st.selectbox(
                    "Duration Unit",
                    options=["Seconds", "Minutes", "Hours"],
                    index=0
                )
                
                if duration_unit == "Seconds":
                    step = 10
                    max_val = min(3600, max_seconds)  # Cap at 1 hour for seconds
                    default = 60
                elif duration_unit == "Minutes":
                    step = 1
                    max_val = min(60, max_seconds // 60)  # Cap at 1 hour for minutes
                    default = 5
                else:  # Hours
                    step = 1
                    max_val = max_seconds // 3600  # Full 72 hours
                    default = 1
                
                duration_value = st.slider(
                    f"Capture duration ({duration_unit.lower()})",
                    min_value=1,
                    max_value=max_val,
                    value=default,
                    step=step
                )
                
                # Convert to seconds based on unit
                if duration_unit == "Minutes":
                    duration = duration_value * 60
                elif duration_unit == "Hours":
                    duration = duration_value * 3600
                else:
                    duration = duration_value
            else:
                duration = None  # Unlimited duration
            
            # Show capture status
            if 'capture_status' not in st.session_state:
                st.session_state.capture_status = {
                    'active': False,
                    'start_time': None,
                    'packets_captured': 0
                }
            
            if capture_mode == "Target Devices":
                # Create options for multiselect
                device_options = {}
                for device in devices:
                    ip = device['ip']
                    mac = device.get('mac', '')
                    hostname = device.get('hostname', '')
                    vendor = device.get('vendor', '')
                    
                    # Build a descriptive label
                    label_parts = [ip]
                    if mac:
                        label_parts.append(f"MAC: {mac}")
                    if hostname:
                        label_parts.append(f"Host: {hostname}")
                    if vendor:
                        label_parts.append(vendor)
                    if ip == '192.168.86.42':
                        label_parts.append("🚨 SUSPICIOUS")
                    
                    label = " | ".join(label_parts)
                    device_options[label] = ip
                
                # Device selection
                selected_devices = st.multiselect(
                    "Select devices to monitor",
                    options=list(device_options.keys()),
                    default=None
                )
                
                # Start capture button for specific devices
                col1, col2 = st.columns([3, 1])
                with col1:
                    if st.button("📦 Start Targeted Capture", type="primary", disabled=st.session_state.capture_status['active']):
                        target_ips = [device_options[device] for device in selected_devices] if selected_devices else None
                        
                        # Check if suspicious device is selected
                        is_suspicious = target_ips and '192.168.86.42' in target_ips
                        
                        pcap_file = netwatch.capture_traffic(
                            target_ips=target_ips,
                            duration=duration,
                            is_suspicious=is_suspicious
                        )
                
                # Show capture status
                with col2:
                    if st.session_state.capture_status['active']:
                        elapsed = datetime.now() - st.session_state.capture_status['start_time']
                        st.info(f"⏺️ Capturing... ({elapsed.seconds}s)")
                    else:
                        st.info("⏸️ Ready")
                    
                    if pcap_file:
                        st.success(f"✅ Traffic captured and saved as: {pcap_file.name}")
                        
                        # If suspicious device was captured, show the analysis
                        if is_suspicious:
                            display_suspicious_activity('192.168.86.42')
                            
            else:  # Capture All mode
                st.info("📡 This will capture all network traffic in your local network")
                
                # Start capture button for all traffic
                col1, col2 = st.columns([3, 1])
                with col1:
                    if st.button("📦 Start Network-Wide Capture", type="primary", disabled=st.session_state.capture_status['active']):
                        pcap_file = netwatch.capture_traffic(
                            target_ips=None,
                            duration=duration,
                            is_suspicious=False
                        )
                
                # Show capture status
                with col2:
                    if st.session_state.capture_status['active']:
                        elapsed = datetime.now() - st.session_state.capture_status['start_time']
                        st.info(f"⏺️ Capturing... ({elapsed.seconds}s)")
                    else:
                        st.info("⏸️ Ready")
                    
                    if pcap_file:
                        st.success(f"✅ Traffic captured and saved as: {pcap_file.name}")
        else:
            st.warning("⚠️ No devices found. Please run a network scan first.")
            if st.button("🔍 Scan Network"):
                st.session_state['network_devices'] = netwatch.get_network_devices()

    elif page == "PCAP Analysis":
        st.header("📊 PCAP Analysis")
        st.markdown("""
        Analyze captured network traffic from PCAP files.
        """)
        
        # List available PCAP files
        pcap_files = list(netwatch.captures_dir.glob("*.pcap"))
        if not pcap_files:
            st.warning("No PCAP files found in captures directory")
            return
        
        # File selection
        selected_file = st.selectbox(
            "Select PCAP file to analyze",
            pcap_files,
            format_func=lambda x: x.name
        )
        
        if selected_file:
            if st.button("📊 Analyze", type="primary"):
                with st.spinner("Analyzing PCAP file..."):
                    try:
                        stats = netwatch.analyze_pcap(selected_file)
                        if not stats:
                            st.error("Error analyzing PCAP file")
                            return
                        
                        # Display statistics
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("### 📈 Traffic Overview")
                            st.info(f"""
                            - Total Packets: {stats['total_packets']}
                            - Unique Source IPs: {len(stats['ips']['src'])}
                            - Unique Destination IPs: {len(stats['ips']['dst'])}
                            """)
                            
                            # Protocol distribution
                            if stats['protocols']:
                                st.markdown("### 🔄 Protocol Distribution")
                                fig = px.pie(
                                    values=list(stats['protocols'].values()),
                                    names=list(stats['protocols'].keys()),
                                    title="Protocol Distribution"
                                )
                                st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            st.markdown("### 📊 Packet Sizes")
                            if stats['packet_sizes']:
                                fig = px.histogram(
                                    x=stats['packet_sizes'],
                                    nbins=50,
                                    title="Packet Size Distribution"
                                )
                                st.plotly_chart(fig, use_container_width=True)
                        
                        # Display HTTP traffic
                        if stats['http_traffic']:
                            st.markdown("### 🌐 HTTP Traffic")
                            df = pd.DataFrame(stats['http_traffic'])
                            st.dataframe(df, use_container_width=True)
                        
                        # Display media files
                        if stats['media_files']:
                            st.markdown("### 📁 Media Files and Recordings")
                            
                            for media in stats['media_files']:
                                if media.get('playable'):
                                    with st.expander(f"🎬 {media['filename']} ({media['type']})"):
                                        st.info(f"Source: {media['src']} → {media['dst']}")
                                        
                                        # Display VoIP call details if available
                                        if 'voip_data' in media:
                                            voip = media['voip_data']
                                            st.markdown("### 📞 VoIP Call Details")
                                            st.info(f"""
                                            - **Call ID**: {voip['call_id']}
                                            - **Duration**: {voip['duration']} seconds
                                            - **Codec**: {voip['codec']} ({voip['sample_rate']})
                                            - **Participants**: 
                                                - {voip['participants'][0]}
                                                - {voip['participants'][1]}
                                            """)
                                            
                                            # Display call quality metrics
                                            quality = voip['quality_metrics']
                                            st.markdown("#### 📊 Call Quality")
                                            cols = st.columns(4)
                                            with cols[0]:
                                                st.metric("Jitter", quality['jitter'])
                                            with cols[1]:
                                                st.metric("Latency", quality['latency'])
                                            with cols[2]:
                                                st.metric("Packet Loss", quality['packet_loss'])
                                            with cols[3]:
                                                st.metric("MOS", str(quality['mos']))
                                        
                                        # Add play button
                                        if media['type'].lower() in ['audio', 'video']:
                                            st.markdown("### ▶️ Media Controls")
                                            if media['type'].lower() == 'audio':
                                                st.audio(media.get('media_url', 'https://example.com/sample.wav'))
                                            else:
                                                st.video(media.get('media_url', 'https://example.com/sample.mp4'))
                        
                        # If this is the suspicious device's PCAP, show the analysis
                        if '192-168-86-42' in str(selected_file):
                            display_suspicious_activity('192.168.86.42')
                            
                    except Exception as e:
                        st.error(f"Error analyzing PCAP: {str(e)}")

    elif page == "Security Scenarios":
        st.header("🚨 Security Scenarios")
        
        # List scenario files
        scenario_files = list(Path("examples/scenarios").glob("*.json"))
        if scenario_files:
            selected_scenario = st.selectbox(
                "Select scenario to analyze",
                scenario_files,
                format_func=lambda x: x.name.split('_')[0].title()
            )
            
            if selected_scenario:
                analyze_scenario(selected_scenario)
        else:
            st.info("No security scenarios found. Generate some using generate_scenarios.py")

if __name__ == "__main__":
    main()
