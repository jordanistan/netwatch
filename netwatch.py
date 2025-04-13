#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple

import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
from scapy.layers.l2 import Ether, ARP
import streamlit as st
import pandas as pd
import plotly.express as px

import variables
from simulated_data import generate_simulated_stats, get_risk_assessment

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def capture_traffic(self, target_ips=None, duration=60, is_suspicious=False):
        """Capture network traffic for specific IPs or all traffic"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create a descriptive filename
            if target_ips:
                if isinstance(target_ips, str):
                    target_ips = [target_ips]
                # Add ALERT tag for suspicious traffic
                alert_tag = "_ALERT" if is_suspicious else ""
                filename = f"traffic{'_suspicious' if is_suspicious else ''}_{'_'.join(ip.replace('.', '-') for ip in target_ips)}_{timestamp}{alert_tag}.pcap"
            else:
                filename = f"traffic_all_{timestamp}.pcap"
            
            output_file = self.captures_dir / filename
            
            # Build capture filter
            if target_ips:
                filter_expr = " or ".join(f"host {ip}" for ip in target_ips)
            else:
                filter_expr = ""
            
            # Start packet capture
            st.info(f"📦 Starting packet capture for {duration} seconds...")
            packets = scapy.sniff(filter=filter_expr, timeout=duration)
            
            # Save captured packets
            if packets:
                wrpcap(str(output_file), packets)
                st.success(f"""
                ✅ Capture complete!
                - Captured {len(packets)} packets
                - Saved to: {output_file}
                
                Contains:
                - HTTP/HTTPS traffic
                - DNS queries
                - ICMP (ping) packets
                """)
            else:
                st.warning("⚠️ No packets captured in the given duration")
            
            return output_file
            
        except Exception as e:
            st.error(f"Error during capture: {str(e)}")
            if 'permission' in str(e).lower():
                st.info("""
                💡 **Traffic capture requires admin privileges**
                Try running the application with:
                ```bash
                sudo python3 netwatch.py
                ```
                """)
            return None

    def analyze_pcap(self, pcap_file: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """Analyze a PCAP file and return statistics"""
        try:
            # Check if this is our simulated file
            if '192-168-86-42' in str(pcap_file):
                return generate_simulated_stats()
                
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
            
            # Add simulated device
            simulated_device = {
                'ip': '192.168.86.42',
                'mac': '00:11:22:33:44:55',
                'hostname': 'suspicious-device',
                'vendor': 'Unknown'
            }
            if not any(d.get('ip') == '192.168.86.42' for d in devices):
                devices.append(simulated_device)
            
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
                    devices.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': '',  # Could add reverse DNS lookup
                        'vendor': ''  # Could add MAC vendor lookup
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
                if iface.startswith('en'):
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
            if st.button("🔍 Scan for Devices", type="secondary", use_container_width=True):
                with st.spinner("🔍 Scanning network for devices..."):
                    devices = netwatch.get_network_devices()
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
                        
                        # Display suspicious activity for simulated device
                        for device in devices:
                            if device['ip'] == '192.168.86.42':
                                display_suspicious_activity('192.168.86.42')
                                
                                # Capture traffic for suspicious device
                                st.markdown("### 📦 Traffic Capture")
                                st.warning("⚠️ Suspicious activity detected! Capturing traffic...")
                                pcap_file = netwatch.capture_traffic(
                                    target_ips='192.168.86.42',
                                    duration=10,
                                    is_suspicious=True
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
            
            # Create options for multiselect
            device_options = {}
            for device in devices:
                ip = device['ip']
                label = f"{ip}"
                if device.get('hostname'):
                    label += f" ({device['hostname']})"
                if device.get('vendor'):
                    label += f" - {device['vendor']}"
                device_options[label] = ip
            
            # Device selection
            selected_devices = st.multiselect(
                "Select devices to monitor",
                options=list(device_options.keys()),
                default=None
            )
            
            # Duration selection
            duration = st.slider(
                "Capture duration (seconds)",
                min_value=10,
                max_value=300,
                value=60,
                step=10
            )
            
            # Start capture button
            if st.button("📦 Start Capture", type="primary"):
                target_ips = [device_options[device] for device in selected_devices] if selected_devices else None
                
                # Check if suspicious device is selected
                is_suspicious = target_ips and '192.168.86.42' in target_ips
                
                pcap_file = netwatch.capture_traffic(
                    target_ips=target_ips,
                    duration=duration,
                    is_suspicious=is_suspicious
                )
                
                if pcap_file:
                    st.success(f"✅ Traffic captured and saved as: {pcap_file.name}")
                    
                    # If suspicious device was captured, show the analysis
                    if is_suspicious:
                        display_suspicious_activity('192.168.86.42')
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

if __name__ == "__main__":
    main()
