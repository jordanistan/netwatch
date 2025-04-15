#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path

import streamlit as st

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
    try:
        # Initialize session state
        if 'netwatch' not in st.session_state:
            st.session_state.netwatch = NetWatch()
        netwatch = st.session_state.netwatch

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
                        st.info(f"📱 Interface: {interface}")
                        st.info(f"🌐 Network: {network_range}")
                        # Scan for devices
                        with st.spinner("Scanning network..."):
                            devices = netwatch.scanner.scan_devices(interface, network_range)
                            show_scan_results(devices, netwatch)
                else:
                    st.error("No suitable network interface found")

        elif action == "Traffic Capture":
            # Initialize session state for devices if not exists
            if 'traffic_capture_devices' not in st.session_state or st.button("🔄 Refresh Device List"):
                try:
                    # First try to get cached devices
                    devices = netwatch.scanner.get_cached_devices() or []
                    # Do a fresh scan only if we have no cached devices
                    if not devices and interface and ip:
                        network_range = netwatch.scanner.get_network_range(interface, ip)
                        if network_range:
                            with st.spinner("Scanning network for devices..."):
                                devices = netwatch.scanner.scan_devices(interface, network_range)
                    if devices:
                        # Get activity status for each device
                        devices_with_status = []
                        for d in devices:
                            try:
                                # Get device history
                                device_history = netwatch.scanner.device_history['devices'].get(d['mac'], {})
                                activity = netwatch.scanner._get_activity_status(device_history) if device_history else "New Device"
                                d['activity'] = activity
                                devices_with_status.append(d)
                            except Exception as e:
                                st.warning(f"Error processing device {d.get('mac', 'unknown')}: {str(e)}")
                                continue
                        st.session_state.traffic_capture_devices = devices_with_status
                    else:
                        st.warning("No devices found in cache or network scan")
                except Exception as e:
                    st.error(f"Error scanning network: {str(e)}")
                    st.session_state.traffic_capture_devices = []

            # Show traffic capture UI with the devices we found
            show_traffic_capture_ui(netwatch, st.session_state.traffic_capture_devices)

        elif action == "PCAP Analysis":
            st.header("PCAP Analysis")
            try:
                pcap_files = list(netwatch.captures_dir.glob("*.pcap"))

                if not pcap_files:
                    st.warning("No PCAP files found in captures directory")
                else:
                    # Sort files by modification time (newest first)
                    pcap_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        selected_file = st.selectbox(
                            "Select PCAP file",
                            pcap_files,
                            format_func=lambda x: f"{x.name} ({datetime.fromtimestamp(x.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')})"
                        )
                    with col2:
                        file_size = selected_file.stat().st_size
                        st.info(f"File size: {file_size / (1024*1024):.1f} MB")

                    if st.button("🔍 Analyze", type="primary", use_container_width=True):
                        try:
                            with st.spinner("Analyzing PCAP file..."):
                                stats = netwatch.capture.analyze_pcap(selected_file)
                                show_pcap_analysis(stats)
                        except Exception as e:
                            st.error(f"Error analyzing PCAP file: {str(e)}")
            except Exception as e:
                st.error(f"Error accessing captures directory: {str(e)}")

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
