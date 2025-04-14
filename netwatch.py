#!/usr/bin/env python3
from pathlib import Path

import streamlit as st
import pandas as pd

from network.scanner import NetworkScanner
from network.capture import TrafficCapture
from network.monitor import DeviceMonitor
from ui.components import setup_page, show_network_info, show_scan_results, show_pcap_analysis, show_traffic_capture_ui

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        # Initialize components
        self.scanner = NetworkScanner()
        self.capture = TrafficCapture(self.captures_dir)
        self.monitor = DeviceMonitor(self.captures_dir)
        # Start device monitoring
        self.monitor.start_monitoring()

def main():
    # Initialize NetWatch
    netwatch = NetWatch()
    # Setup page
    setup_page()
    # Navigation in sidebar
    st.sidebar.title("Navigation")
    action = st.sidebar.radio(
        "Select Action",
        ["Network Scan", "Traffic Capture", "PCAP Analysis"]
    )
    # Get network interface
    interface, ip = netwatch.scanner.get_default_interface()
    show_network_info(interface, ip)

    if action == "Network Scan":
        st.header("Network Scan")
        # Scan button at the top
        if st.button("🔍 Start Network Scan", type="primary", use_container_width=True):
            if interface and ip:
                # Get network range
                network_range = netwatch.scanner.get_network_range(interface, ip)
                if network_range:
                    st.info(f"📡 Interface: {interface}")
                    st.info(f"🌐 Network: {network_range}")
                    # Scan for devices
                    with st.spinner("Scanning network..."):
                        devices = netwatch.scanner.scan_devices(interface, network_range)
                        show_scan_results(devices, netwatch)
            else:
                st.error("No suitable network interface found")

    elif action == "Traffic Capture":
        # Initialize devices list
        devices = []
        # First try to get cached devices
        devices = netwatch.scanner.get_cached_devices() or []
        # Always do a fresh scan when navigating to Traffic Capture
        if interface and ip:
            network_range = netwatch.scanner.get_network_range(interface, ip)
            if network_range:
                with st.spinner("Scanning network for devices..."):
                    devices = netwatch.scanner.scan_devices(interface, network_range)
                    if devices:
                        st.success(f"✨ Found {len(devices)} devices on your network")
                        # Get activity status for each device
                        devices_with_status = []
                        for d in devices:
                            # Get device history
                            device_history = netwatch.scanner.device_history['devices'].get(d['mac'], {})
                            if device_history:
                                activity = netwatch.scanner._get_activity_status(device_history)
                            else:
                                activity = "New Device"
                            devices_with_status.append({
                                'IP Address': d['ip'],
                                'MAC Address': d['mac'],
                                'Device Name': d.get('hostname', 'N/A'),
                                'Activity': activity
                            })
                        # Create a DataFrame for better visualization
                        device_df = pd.DataFrame(devices_with_status)
                        st.dataframe(
                            device_df,
                            column_config={
                                'IP Address': st.column_config.TextColumn(width="medium"),
                                'MAC Address': st.column_config.TextColumn(width="medium"),
                                'Device Name': st.column_config.TextColumn(width="medium"),
                                'Activity': st.column_config.TextColumn(
                                    width="small",
                                    help="Device activity status"
                                )
                            },
                            hide_index=True,
                            use_container_width=True
                        )
                    else:
                        st.info("No devices found on the network")
        # Show traffic capture UI with the devices we found
        show_traffic_capture_ui(netwatch, devices)

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
                    stats = netwatch.capture.analyze_pcap(selected_file)
                    show_pcap_analysis(stats)

if __name__ == "__main__":
    main()
