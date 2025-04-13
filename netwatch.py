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

    def get_default_interface(self):
        """Get the default network interface that's connected to LAN"""
        try:
            # On macOS, common LAN interfaces start with 'en' (ethernet/wifi)
            interfaces = scapy.get_if_list()
            
            # First, try to find active ethernet or wifi interface
            for iface in interfaces:
                if iface.startswith('en'):
                    ip = scapy.get_if_addr(iface)
                    if ip and not ip.startswith('169.254'):  # Exclude self-assigned IPs
                        st.debug(f"Found active interface {iface} with IP {ip}")
                        return iface
            
            # If no 'en' interface, try other interfaces except loopback and virtual
            for iface in interfaces:
                if not any(iface.startswith(x) for x in ['lo', 'docker', 'br-', 'vbox', 'vmnet']):
                    ip = scapy.get_if_addr(iface)
                    if ip and not ip.startswith('169.254'):
                        st.debug(f"Found alternative interface {iface} with IP {ip}")
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
                # Configure Scapy for the interface
                scapy.conf.iface = interface
                
                # Create ARP request
                arp = scapy.ARP(pdst=network_range)
                ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp

                # Send packet and get responses
                result = scapy.srp(packet, timeout=5, verbose=0, iface=interface)[0]
                
                # Process responses
                devices = []
                for sent, received in result:
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': None
                    }
                    try:
                        # Try to get hostname (optional)
                        hostname = scapy.conf.socket.gethostbyaddr(received.psrc)[0]
                        device['hostname'] = hostname
                    except:
                        pass
                    devices.append(device)

                # Show results
                if devices:
                    st.success(f"✨ Found {len(devices)} devices")
                    return devices
                else:
                    st.warning("⚠️ No devices responded to ARP scan")
                    return []

        except Exception as e:
            st.error(f"❌ Scan failed: {str(e)}")
            return []

    def capture_traffic(self, target_ip, duration=60):
        """Capture network traffic for a specific IP"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.captures_dir / f"traffic_{target_ip.replace('.', '_')}_{timestamp}.pcap"
        
        # Using scapy for capture
        packets = scapy.sniff(
            filter=f"host {target_ip}",
            timeout=duration
        )
        wrpcap(str(output_file), packets)
        return output_file

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
            return

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
