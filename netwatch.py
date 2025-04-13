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

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

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
    
    def get_default_interface(self) -> Optional[str]:
        """Get the default network interface that's connected to LAN"""
        try:
            # On macOS, common LAN interfaces start with 'en' (ethernet/wifi)
            interfaces = scapy.get_if_list()
            
            # Show available interfaces
            st.markdown("### Available Network Interfaces")
            active_interfaces = []
            
            # First, try to find active ethernet or wifi interface
            for iface in interfaces:
                if iface.startswith('en'):
                    try:
                        ip = scapy.get_if_addr(iface)
                        if ip and not ip.startswith('169.254') and ip != '0.0.0.0':  # Exclude invalid IPs
                            st.info(f"📡 {iface}: {ip}")
                            active_interfaces.append((iface, ip))
                    except (OSError, IOError):
                        continue
            
            # If no 'en' interface, try other interfaces except loopback and virtual
            if not active_interfaces:
                for iface in interfaces:
                    if not any(iface.startswith(x) for x in ['lo', 'docker', 'br-', 'vbox', 'vmnet']):
                        try:
                            ip = scapy.get_if_addr(iface)
                            if ip and not ip.startswith('169.254') and ip != '0.0.0.0':
                                st.info(f"📡 {iface}: {ip}")
                                active_interfaces.append((iface, ip))
                        except (OSError, IOError):
                            continue
            
            if active_interfaces:
                # Sort interfaces by IP to prioritize non-zero IPs
                active_interfaces.sort(key=lambda x: x[1] != '0.0.0.0', reverse=True)
                selected_interface = active_interfaces[0]
                st.success(f"✅ Selected interface: {selected_interface[0]} ({selected_interface[1]})")
                return selected_interface[0]
            
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

    def scan_network(self, network_range: Optional[str] = None) -> List[Dict[str, str]]:
        """Scan network for devices using ARP"""
        # Get the default interface
        interface = self.get_default_interface()
        if not interface:
            return []
        
        try:
            # Get the network range
            if network_range is None:
                network_range = self.get_network_range(interface)
                if not network_range:
                    return []
            
            st.info(f"📡 Scanning on interface: {interface}")
            
            # Create and send ARP request
            with st.spinner("🔍 Sending ARP requests..."):
                ans, _ = scapy.srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range),
                    timeout=2,
                    iface=interface,
                    verbose=False
                )
                
                # Process results
                devices = []
                for _, rcv in ans:
                    try:
                        # Get vendor info from MAC address
                        mac = rcv[Ether].src
                        vendor = 'Unknown'
                        
                        # Get first 3 octets of MAC (vendor part)
                        oui = ':'.join(mac.split(':')[:3]).upper()
                        vendor = f"OUI: {oui}"
                        
                        devices.append({
                            'ip': rcv[ARP].psrc,
                            'mac': mac,
                            'vendor': vendor
                        })
                    except (IndexError, KeyError, AttributeError) as e:
                        st.warning(f"Error processing device: {str(e)}")
                        continue
                
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

    def capture_traffic(self, target_ips=None, duration=60):
        """Capture network traffic for specific IPs or all traffic"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create a descriptive filename
            if target_ips:
                if isinstance(target_ips, str):
                    target_ips = [target_ips]
                filename = f"traffic_{'_'.join(ip.replace('.', '-') for ip in target_ips)}_{timestamp}.pcap"
            else:
                filename = f"traffic_all_{timestamp}.pcap"
            
            output_file = self.captures_dir / filename
            
            # Set capture filter for multiple IPs
            if target_ips:
                capture_filter = " or ".join(f"host {ip}" for ip in target_ips)
            else:
                capture_filter = ""
            
            st.info(f"💾 Saving capture to: {output_file.name}")
            if target_ips:
                st.info(f"🌐 Capturing traffic for {len(target_ips)} device(s)")
                for ip in target_ips:
                    st.info(f"  • {ip}")
            else:
                st.info("🌐 Capturing all network traffic")
            
            # Using scapy for capture
            with st.spinner(f"📊 Capturing traffic for {duration} seconds..."):
                packets = scapy.sniff(
                    filter=capture_filter,
                    timeout=duration,
                    store=True,
                    count=0
                )
                
                # Save the capture
                if packets:
                    wrpcap(str(output_file), packets)
                    st.success(f"✅ Captured {len(packets)} packets")
                    st.info("""
                    💡 You can analyze this capture in the PCAP Analysis section.
                    Common protocols captured:
                    - TCP/UDP traffic
                    - HTTP/HTTPS connections
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

    def extract_http_traffic(self, pcap_file):
        """Extract HTTP traffic from PCAP file"""
        try:
            # Read PCAP file
            packets = rdpcap(str(pcap_file))
            http_traffic = []
            
            # Process packets
            for packet in packets:
                if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                    try:
                        # Get payload
                        payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                        
                        # Look for HTTP requests
                        if payload.startswith('GET ') or payload.startswith('POST '):
                            # Parse request
                            request_line = payload.split('\r\n')[0]
                            method = request_line.split()[0]
                            path = request_line.split()[1]
                            host = None
                            content_type = None
                            
                            # Find Host and Content-Type headers
                            for line in payload.split('\r\n'):
                                if line.lower().startswith('host:'):
                                    host = line.split(': ')[1].strip()
                                elif line.lower().startswith('content-type:'):
                                    content_type = line.split(': ')[1].strip()
                            
                            if host:
                                url = f"http://{host}{path}"
                                http_traffic.append({
                                    'timestamp': datetime.fromtimestamp(float(packet.time)),
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
            # Read PCAP file
            packets = rdpcap(str(pcap_file))
            media_files = []
            
            # Create directory for extracted files
            media_dir = self.captures_dir / 'media'
            media_dir.mkdir(exist_ok=True)
            
            # Track TCP streams
            streams = {}
            
            # Process packets
            for packet in packets:
                if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                    # Get stream ID
                    stream_id = (packet[scapy.IP].src, packet[scapy.TCP].sport,
                               packet[scapy.IP].dst, packet[scapy.TCP].dport)
                    
                    # Add payload to stream
                    if stream_id not in streams:
                        streams[stream_id] = {'data': b'', 'timestamp': packet.time}
                    streams[stream_id]['data'] += packet[scapy.Raw].load
            
            # Process streams
            for stream_id, stream in streams.items():
                try:
                    data = stream['data']
                    # Check for common media headers
                    if (data.startswith(b'\xff\xd8\xff') or  # JPEG
                        data.startswith(b'\x89PNG\r\n') or   # PNG
                        data.startswith(b'GIF87a') or     # GIF
                        data.startswith(b'GIF89a') or     # GIF
                        b'ftypmp4' in data[:32] or    # MP4
                        data.startswith(b'ID3') or    # MP3
                        b'ftypisom' in data[:32]):    # MP4/ISO
                        
                        # Determine file type
                        ext = '.bin'
                        mime_type = 'application/octet-stream'
                        
                        if data.startswith(b'\xff\xd8\xff'):
                            ext = '.jpg'
                            mime_type = 'image/jpeg'
                        elif data.startswith(b'\x89PNG\r\n'):
                            ext = '.png'
                            mime_type = 'image/png'
                        elif data.startswith(b'GIF'):
                            ext = '.gif'
                            mime_type = 'image/gif'
                        elif b'ftyp' in data[:32]:
                            ext = '.mp4'
                            mime_type = 'video/mp4'
                        elif data.startswith(b'ID3'):
                            ext = '.mp3'
                            mime_type = 'audio/mpeg'
                        
                        # Save file
                        timestamp = datetime.fromtimestamp(float(stream['timestamp'])).strftime("%Y%m%d_%H%M%S")
                        filename = f"media_{timestamp}_{stream_id[0]}_{stream_id[2]}{ext}"
                        filepath = media_dir / filename
                        
                        with open(filepath, 'wb') as f:
                            f.write(data)
                        
                        media_files.append({
                            'filename': filename,
                            'path': filepath,
                            'type': ext[1:].upper(),
                            'mime_type': mime_type,
                            'size': len(data),
                            'src': stream_id[0],
                            'dst': stream_id[2],
                            'timestamp': datetime.fromtimestamp(float(stream['timestamp']))
                        })
                except:
                    continue
            
            return media_files
        except Exception as e:
            st.error(f"Error extracting media content: {str(e)}")
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
                stats['timestamps'].append(float(packet.time))
                
                # Collect packet size
                stats['packet_sizes'].append(len(packet))
                
                # Analyze protocols
                if packet.haslayer(TCP):
                    proto = 'TCP'
                elif packet.haslayer(UDP):
                    proto = 'UDP'
                else:
                    proto = 'Other'
                    
                stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
                
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

def main():
    # Apply theme settings
    st.set_page_config(
        page_title=variables.APP_CONFIG['title'],
        page_icon=variables.APP_CONFIG['icon'],
        layout=variables.APP_CONFIG['layout'],
        initial_sidebar_state="expanded"
    )
    
    # Apply custom CSS
    st.markdown(variables.CUSTOM_CSS, unsafe_allow_html=True)
    
    # Main header with version
    st.title(f"{variables.APP_CONFIG['title']} {variables.APP_CONFIG['icon']}")
    st.caption("Version 1.0.0 - Educational Network Analysis Tool")
    
    try:
        netwatch = NetWatch()
    except Exception as e:
        st.error(f"Error initializing NetWatch: {str(e)}")
        st.info("""
        💡 **Tip**: Some features require root/admin privileges. Try running with:
        ```bash
        sudo python3 netwatch.py
        ```
        """)
        return

    # Use the UI module for sidebar
    import ui
    action = ui.setup_sidebar()

    if action == "Network Scan":
        st.header("Network Device Scanner 📡")
        
        # Instructions
        st.markdown("""
        This tool scans your local network to discover active devices using ARP requests.
        Results will show IP addresses, MAC addresses, and vendor information when available.
        """)
        
        col1, col2 = st.columns([2,1])
        with col1:
            if st.button("🔍 Start Network Scan", use_container_width=True):
                with st.spinner("🔄 Scanning network..."):
                    try:
                        devices = netwatch.scan_network()
                        if devices:
                            df = pd.DataFrame(devices)
                            st.success(f"Found {len(devices)} devices")
                            st.dataframe(
                                df,
                                column_config={
                                    "ip": "IP Address",
                                    "mac": "MAC Address",
                                    "vendor": "Vendor"
                                },
                                use_container_width=True
                            )
                        else:
                            st.warning("⚠️ No devices found. Try running with admin privileges.")
                    except Exception as e:
                        st.error(f"Error during scan: {str(e)}")
                        if 'permission' in str(e).lower():
                            st.info("💡 This feature requires admin privileges")
        
        with col2:
            st.info("""
            ### Tips
            - Ensure you're connected to a network
            - Some devices may not respond to ARP
            - Scan may take a few seconds
            """)

    elif action == "Traffic Capture":
        st.header("Traffic Capture 📊")
        
        st.markdown("""
        Capture and analyze network traffic in real-time. Monitor specific devices or capture all network traffic.
        Results will be saved as PCAP files that you can analyze later.
        """)
        
        col1, col2 = st.columns([2,1])
        with col1:
            # Target selection
            capture_mode = st.radio(
                "Capture Mode",
                ["All Traffic", "Specific Devices"],
                help="Choose what traffic to capture"
            )
            
            target_ips = None
            if capture_mode == "Specific Devices":
                col1, col2 = st.columns([3, 1])
                with col1:
                    # Add scan button
                    if st.button("🔍 Scan for Devices", type="secondary", use_container_width=True):
                        with st.spinner("🔍 Scanning network for devices..."):
                            devices = netwatch.get_network_devices()
                            if devices:
                                st.session_state['network_devices'] = devices
                                st.success(f"✅ Found {len(devices)} devices")
                            else:
                                st.warning("⚠️ No devices found on the network")
                                st.info("💡 Check your network connection and try again")
                                st.session_state['network_devices'] = []
                
                # Show device selection if we have devices
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
                    
                    # Show multiselect for devices
                    selected_labels = st.multiselect(
                        "Select Devices to Monitor",
                        options=list(device_options.keys()),
                        help="Choose one or more devices to capture traffic from"
                    )
                    
                    if selected_labels:
                        target_ips = [device_options[label] for label in selected_labels]
                        
                        # Show selected IPs
                        st.markdown("#### Selected Devices")
                        for ip in target_ips:
                            st.code(ip)
                elif 'network_devices' in st.session_state:
                    st.info("💡 Click 'Scan for Devices' to find available devices")
            
            # Duration settings
            duration_preset = st.select_slider(
                "Capture Duration",
                options=[10, 30, 60, 120, 180, 300],
                value=60,
                format_func=lambda x: f"{x} seconds",
                help="How long to capture traffic"
            )
            
            # Start capture button
            start_disabled = capture_mode == "Specific Devices" and not target_ips
            if st.button(
                "🏁 Start Capture",
                type="primary",
                use_container_width=True,
                disabled=start_disabled
            ):
                try:
                    pcap_file = netwatch.capture_traffic(target_ips, duration_preset)
                    if pcap_file:
                        st.balloons()
                        st.success("Capture completed successfully!")
                        st.markdown(f"""
                        💾 **Capture saved as**: `{pcap_file.name}`
                        
                        You can analyze this capture in the PCAP Analysis section to:
                        - View protocol distribution
                        - Identify top talkers
                        - Analyze traffic patterns
                        - Check packet sizes
                        """)
                except Exception as e:
                    st.error(f"Error during capture: {str(e)}")
                    if 'permission' in str(e).lower():
                        st.warning("""
                        ⚠️ **Admin privileges required**
                        
To capture network traffic, run the application with:
                        ```bash
                        sudo python3 netwatch.py
                        ```
                        """)
        
        with col2:
            st.info("""
            ### Capture Options
            📊 **All Traffic**
            - Captures every packet
            - Larger file sizes
            - Complete network view
            
            🌐 **Specific IP**
            - Monitor single device
            - Smaller captures
            - Focused analysis
            """)
            
            st.warning("""
            ### Requirements
            - Admin privileges
            - Active network
            - Sufficient disk space
            """)

    elif action == "PCAP Analysis":
        st.header("PCAP Analysis 📂")
        
        st.markdown("""
        Analyze captured network traffic files (PCAPs) to understand network behavior,
        protocol distribution, and identify patterns.
        """)
        
        pcap_files = list(netwatch.captures_dir.glob("*.pcap"))
        
        if not pcap_files:
            st.warning("⚠️ No PCAP files found in the captures directory")
            st.info(f"""
            💡 Capture some traffic first! PCAP files will be saved to:
            `{netwatch.captures_dir}`
            """)
            return

        col1, col2 = st.columns([2,1])
        with col1:
            selected_file = st.selectbox(
                "Select PCAP File",
                pcap_files,
                format_func=lambda x: f"{x.name} ({x.stat().st_size / 1024:.1f} KB)",
                help="Choose a PCAP file to analyze"
            )

            if st.button("🔍 Analyze PCAP", use_container_width=True):
                try:
                    with st.spinner("🔄 Analyzing PCAP file..."):
                        stats = netwatch.analyze_pcap(selected_file)
                        
                        # Overview stats
                        st.success(f"✅ Analysis complete!")
                        total_packets = sum(stats['protocols'].values())
                        st.metric("Total Packets", total_packets)
                        
                        # Protocol Distribution
                        st.subheader("📁 Protocol Distribution")
                        fig = px.pie(
                            values=list(stats['protocols'].values()),
                            names=list(stats['protocols'].keys()),
                            title="Network Protocols",
                            color_discrete_sequence=px.colors.qualitative.Set3
                        )
                        fig.update_traces(textposition='inside', textinfo='percent+label')
                        st.plotly_chart(fig, use_container_width=True)

                        # HTTP Traffic Analysis
                        st.subheader("🌐 HTTP Traffic")
                        if stats['http_traffic']:
                            # Convert to DataFrame for easier handling
                            http_df = pd.DataFrame(stats['http_traffic'])
                            http_df['timestamp'] = pd.to_datetime(http_df['timestamp'])
                            
                            # Group by domain
                            domains = http_df['url'].apply(lambda x: x.split('/')[2]).value_counts().head(10)
                            
                            # Show top domains
                            st.markdown("#### Top Domains")
                            fig = px.bar(
                                x=domains.index,
                                y=domains.values,
                                labels={'x': 'Domain', 'y': 'Requests'},
                                title="Most Visited Domains"
                            )
                            fig.update_layout(showlegend=False)
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Show HTTP requests
                            st.markdown("#### HTTP Requests")
                            for req in http_df.sort_values('timestamp', ascending=False).to_dict('records'):
                                with st.expander(
                                    f"{req['timestamp'].strftime('%H:%M:%S')} - {req['method']} {req['url']}",
                                    expanded=False
                                ):
                                    st.markdown(f"""
                                    - **Method**: {req['method']}
                                    - **URL**: `{req['url']}`
                                    - **Size**: {req['size']} bytes
                                    - **Source**: {req['src']}
                                    - **Destination**: {req['dst']}
                                    - **Content Type**: {req['content_type'] or 'Not specified'}
                                    """)
                        else:
                            st.info("💡 No HTTP traffic found in this capture")
                        
                        # Media Content Analysis
                        st.subheader("🎥 Media Content")
                        if stats['media_files']:
                            # Convert to DataFrame
                            media_df = pd.DataFrame(stats['media_files'])
                            media_df['timestamp'] = pd.to_datetime(media_df['timestamp'])
                            
                            # Group by type
                            media_types = media_df['type'].value_counts()
                            
                            # Show media type distribution
                            fig = px.pie(
                                values=media_types.values,
                                names=media_types.index,
                                title="Media Types",
                                color_discrete_sequence=px.colors.qualitative.Set2
                            )
                            fig.update_traces(textposition='inside', textinfo='percent+label')
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Show media files
                            st.markdown("#### Extracted Media Files")
                            for media in media_df.sort_values('timestamp', ascending=False).to_dict('records'):
                                with st.expander(
                                    f"{media['timestamp'].strftime('%H:%M:%S')} - {media['type']} ({media['size']/1024:.1f} KB)",
                                    expanded=False
                                ):
                                    st.markdown(f"""
                                    - **Type**: {media['type']}
                                    - **MIME Type**: {media['mime_type']}
                                    - **Size**: {media['size']/1024:.1f} KB
                                    - **Source**: {media['src']}
                                    - **Destination**: {media['dst']}
                                    - **File**: `{media['filename']}`
                                    """)
                                    
                                    # Preview/playback based on type
                                    if media['type'] in ['JPG', 'PNG', 'GIF']:
                                        st.image(media['path'])
                                    elif media['type'] in ['MP4']:
                                        st.video(media['path'])
                                    elif media['type'] in ['MP3']:
                                        st.audio(media['path'])
                        else:
                            st.info("💡 No media content found in this capture")

                        # Traffic Analysis
                        st.subheader("📈 Traffic Analysis")
                        df = pd.DataFrame({
                            'timestamp': pd.to_datetime(stats['timestamps'], unit='s'),
                            'size': stats['packet_sizes']
                        })
                        fig = px.line(
                            df,
                            x='timestamp',
                            y='size',
                            title="Packet Sizes Over Time",
                            labels={'timestamp': 'Time', 'size': 'Packet Size (bytes)'},
                        )
                        fig.update_layout(showlegend=False)
                        st.plotly_chart(fig, use_container_width=True)

                        # Top IPs Analysis
                        st.subheader("🏕 Top Network Endpoints")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("#### Top Source IPs")
                            src_ips = pd.DataFrame(
                                stats['ips']['src'].items(),
                                columns=['IP', 'Packets Sent']
                            ).sort_values('Packets Sent', ascending=False).head(10)
                            fig = px.bar(
                                src_ips,
                                x='IP',
                                y='Packets Sent',
                                title="Top Talkers"
                            )
                            fig.update_layout(showlegend=False)
                            st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            st.markdown("#### Top Destination IPs")
                            dst_ips = pd.DataFrame(
                                stats['ips']['dst'].items(),
                                columns=['IP', 'Packets Received']
                            ).sort_values('Packets Received', ascending=False).head(10)
                            fig = px.bar(
                                dst_ips,
                                x='IP',
                                y='Packets Received',
                                title="Top Receivers"
                            )
                            fig.update_layout(showlegend=False)
                            st.plotly_chart(fig, use_container_width=True)
                            
                except Exception as e:
                    st.error(f"Error analyzing PCAP: {str(e)}")
        
        with col2:
            st.info("""
            ### Analysis Features
            - Protocol Distribution
            - Traffic Patterns
            - Top Talkers
            - Packet Sizes
            """)
            
            # Show file details
            if selected_file:
                st.markdown("### Selected File")
                stats = selected_file.stat()
                st.markdown(f"""
                - **Name**: {selected_file.name}
                - **Size**: {stats.st_size / 1024:.1f} KB
                - **Created**: {pd.Timestamp(stats.st_ctime, unit='s').strftime('%Y-%m-%d %H:%M:%S')}
                - **Modified**: {pd.Timestamp(stats.st_mtime, unit='s').strftime('%Y-%m-%d %H:%M:%S')}
                """)

    # Add footer
    st.markdown(variables.FOOTER, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
