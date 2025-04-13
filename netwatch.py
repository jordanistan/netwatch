#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path

import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap
import streamlit as st
import pandas as pd
import plotly.express as px

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_network_devices(self):
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
            
        except Exception as e:
            st.error(f"Error getting network devices: {str(e)}")
            return []
    
    def get_default_interface(self):
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
                    except:
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
                        except:
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
            
        except Exception as e:
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

    def scan_network(self, network_range=None):
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
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=network_range),
                    timeout=2,
                    iface=interface,
                    verbose=False
                )
                
                # Process results
                devices = []
                for _, rcv in ans:
                    # Try to get vendor info from MAC address
                    mac = rcv[scapy.Ether].src
                    vendor = 'Unknown'
                    try:
                        # Get first 3 octets of MAC (vendor part)
                        oui = ':'.join(mac.split(':')[:3]).upper()
                        vendor = f"OUI: {oui}"
                    except:
                        pass
                    
                    devices.append({
                        'ip': rcv[scapy.ARP].psrc,
                        'mac': mac,
                        'vendor': vendor
                    })
                
                if devices:
                    st.success(f"✨ Found {len(devices)} devices")
                else:
                    st.warning("⚠️ No devices found on the network")
                
                return devices
                
        except Exception as e:
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

    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file and return statistics"""
        packets = rdpcap(str(pcap_file))
        stats = {
            'total_packets': len(packets),
            'protocols': {},
            'packet_sizes': [],
            'timestamps': [],
            'ips': {'src': {}, 'dst': {}}
        }
        
        for packet in packets:
            # Collect timestamp
            stats['timestamps'].append(float(packet.time))
            
            # Collect packet size
            stats['packet_sizes'].append(len(packet))
            
            # Analyze protocols
            if packet.haslayer(scapy.TCP):
                proto = 'TCP'
            elif packet.haslayer(scapy.UDP):
                proto = 'UDP'
            elif packet.haslayer(scapy.ICMP):
                proto = 'ICMP'
            else:
                proto = 'Other'
                
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            
            # Collect IP information
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                stats['ips']['src'][src] = stats['ips']['src'].get(src, 0) + 1
                stats['ips']['dst'][dst] = stats['ips']['dst'].get(dst, 0) + 1
        
        return stats

def main():
    st.set_page_config(
        page_title="NetWatch Dashboard",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Main header with version
    st.title("NetWatch Network Monitoring Dashboard 🔍")
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

                        # Packet Sizes Over Time
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
                        st.subheader("🏔 Top Network Endpoints")
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

if __name__ == "__main__":
    main()
