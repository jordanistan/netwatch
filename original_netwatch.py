# DO NOT MODIFY - Original working version
#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
import socket

import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap
import streamlit as st
import pandas as pd
import plotly.express as px
import netifaces

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_default_interface(self):
        """Get the default network interface that's connected to LAN"""
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                # Skip loopback and virtual interfaces
                if any(iface.startswith(x) for x in ['lo', 'docker', 'br-', 'vbox', 'vmnet']):
                    continue
                
                # Get interface addresses
                addrs = netifaces.ifaddresses(iface)
                
                # Check for IPv4 address
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    if not ip.startswith('169.254'):  # Exclude self-assigned IPs
                        st.write(f"Found active interface {iface} with IP {ip}")
                        return iface
            
            st.error("No suitable network interface found")
            return None
        except Exception as e:
            st.error(f"Error finding network interface: {str(e)}")
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
                return "10.0.0.0/8"
            elif first_octet == 172 and 16 <= int(ip_parts[1]) <= 31:  # Class B private network
                return f"172.{ip_parts[1]}.0.0/16"
            elif first_octet == 192 and ip_parts[1] == '168':  # Class C private network
                return f"192.168.{ip_parts[2]}.0/24"
            else:
                st.warning(f"IP {ip} is not in a private network range")
                return f"{'.'.join(ip_parts[:3])}.0/24"
                
        except Exception as e:
            st.error(f"Error determining network range: {str(e)}")
            return None

    def scan_network(self, network_range=None):
        """Scan network for devices using ARP"""
        # Get the default interface
        interface = self.get_default_interface()
        if not interface:
            st.error("Could not find a suitable network interface")
            return []

        # Get the network range
        if network_range is None:
            network_range = self.get_network_range(interface)
            if not network_range:
                st.error("Could not determine network range")
                return []

        st.info(f"📡 Interface: {interface}")
        st.info(f"🌐 Network: {network_range}")

        # Create and send ARP request
        try:
            with st.spinner("Scanning network..."):
                # Create ARP request packet
                arp = scapy.ARP(pdst=network_range)
                # Create broadcast Ethernet frame
                ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                # Combine frame and packet
                packet = ether/arp

                # Send packet and capture responses with interface specified
                ans, _ = scapy.srp(packet, timeout=3, verbose=0, iface=interface)
                
                # Process responses
                devices = []
                for sent, received in ans:
                    try:
                        # Try to get hostname but don't fail if we can't
                        try:
                            hostname = socket.gethostbyaddr(received.psrc)[0]
                        except (socket.gaierror, socket.herror):
                            hostname = "N/A"
                        
                        devices.append({
                            'ip': received.psrc,
                            'mac': received.hwsrc,
                            'hostname': hostname
                        })
                    except Exception as e:
                        st.warning(f"Could not process device {received.psrc}: {str(e)}")
                        continue
                
                return devices
        except Exception as e:
            st.error(f"Error scanning network: {str(e)}")
            return []

    def capture_traffic(self, target_ip, duration=60):
        """Capture network traffic for a specific IP"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = self.captures_dir / f"capture_{timestamp}.pcap"
        
        # Create capture filter
        capture_filter = f"host {target_ip}"
        
        # Start capture
        packets = scapy.sniff(filter=capture_filter, timeout=duration)
        wrpcap(str(pcap_file), packets)
        
        return pcap_file

    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file and return statistics"""
        packets = rdpcap(str(pcap_file))
        
        stats = {
            'protocols': {},
            'ips': {
                'src': {},
                'dst': {}
            },
            'packet_sizes': [],
            'timestamps': []
        }
        
        for packet in packets:
            # Get timestamp
            stats['timestamps'].append(float(packet.time))
            
            # Get packet size
            stats['packet_sizes'].append(len(packet))
            
            # Count protocols
            if packet.haslayer(scapy.TCP):
                proto = "TCP"
            elif packet.haslayer(scapy.UDP):
                proto = "UDP"
            elif packet.haslayer(scapy.ICMP):
                proto = "ICMP"
            else:
                proto = "Other"
            
            stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
            
            # Count IP addresses
            if scapy.IP in packet:
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                stats['ips']['src'][src] = stats['ips']['src'].get(src, 0) + 1
                stats['ips']['dst'][dst] = stats['ips']['dst'].get(dst, 0) + 1
        
        return stats

def main():
    st.set_page_config(
        page_title="NetWatch",
        page_icon="📶",
        layout="wide"
    )

    st.title("📶 NetWatch")

    # Initialize NetWatch
    netwatch = NetWatch()

    # Navigation in sidebar
    st.sidebar.title("Navigation")
    action = st.sidebar.radio(
        "Select Action",
        ["Network Scan", "Traffic Capture", "PCAP Analysis"]
    )

    # Network info in sidebar
    st.sidebar.title("Network Info")
    interface = netwatch.get_default_interface()
    
    if interface:
        ip = scapy.get_if_addr(interface)
        st.sidebar.success(f"🌐 Network Interface: {interface}")
        st.sidebar.info(f"📍 IP Address: {ip}")

        # Network interfaces in an expander
        with st.sidebar.expander("🔧 All Network Interfaces", expanded=False):
            for iface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
                    st.write(f"{iface}: {addr}")

    if action == "Network Scan":
        st.header("Network Scan")
        
        # Scan button at the top
        if st.button("🔍 Start Network Scan", type="primary", use_container_width=True):
            with st.spinner("Scanning network..."):
                devices = netwatch.scan_network()
                if devices:
                    st.success(f"✨ Found {len(devices)} devices")
                    st.balloons()

                    # Create a nice looking dataframe
                    df = pd.DataFrame(devices)
                    df = df.fillna("N/A")
                    # Add styling
                    st.dataframe(
                        df,
                        column_config={
                            "ip": st.column_config.TextColumn(
                                "IP Address",
                                help="Device IP address",
                                width="medium"
                            ),
                            "mac": st.column_config.TextColumn(
                                "MAC Address",
                                help="Physical hardware address",
                                width="medium"
                            ),
                            "hostname": st.column_config.TextColumn(
                                "Device Name",
                                help="Network hostname if available"
                            )
                        },
                        hide_index=True,
                        use_container_width=True
                    )
                else:
                    st.warning("😕 No devices found")

        if not interface:
            st.error("No suitable network interface found")

    elif action == "Traffic Capture":
        st.header("Traffic Capture")
        target_ip = st.text_input("Target IP")
        duration = st.slider("Capture Duration (seconds)", 10, 300, 60)

        if st.button("Start Capture"):
            with st.spinner(f"Capturing traffic for {duration} seconds..."):
                pcap_file = netwatch.capture_traffic(target_ip, duration)
                st.success(f"Capture completed: {pcap_file}")

    elif action == "PCAP Analysis":
        st.header("PCAP Analysis")
        pcap_files = list(netwatch.captures_dir.glob("*.pcap"))

        if not pcap_files:
            st.warning("No PCAP files found")
        else:
            selected_file = st.selectbox(
                "Select PCAP file",
                pcap_files,
                format_func=lambda x: x.name
            )

            if st.button("Analyze"):
                with st.spinner("Analyzing PCAP file..."):
                    stats = netwatch.analyze_pcap(selected_file)
                    
                    # Display statistics
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("Protocol Distribution")
                        fig = px.pie(
                            values=list(stats['protocols'].values()),
                            names=list(stats['protocols'].keys()),
                            title="Protocol Distribution"
                        )
                        st.plotly_chart(fig)

                    with col2:
                        st.subheader("Packet Sizes Over Time")
                        df = pd.DataFrame({
                            'timestamp': pd.to_datetime(stats['timestamps'], unit='s'),
                            'size': stats['packet_sizes']
                        })
                        fig = px.line(df, x='timestamp', y='size', title="Packet Sizes Over Time")
                        st.plotly_chart(fig)

                    # Top IPs
                    st.subheader("Top Source IPs")
                    src_ips = pd.DataFrame(
                        stats['ips']['src'].items(),
                        columns=['IP', 'Count']
                    ).sort_values('Count', ascending=False).head(10)
                    st.bar_chart(src_ips.set_index('IP'))

if __name__ == "__main__":
    main()
