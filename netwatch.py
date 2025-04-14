#!/usr/bin/env python3
import json
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
        # Check for tracked devices first
        tracked_devices_file = Path("data/tracked_devices.json")
        tracked_macs = set()
        if tracked_devices_file.exists():
            tracked_devices = json.loads(tracked_devices_file.read_text())
            tracked_macs = {d["mac"] for d in tracked_devices["devices"]}
            # If we have tracked devices but no cached devices, do a scan
            if tracked_macs and not netwatch.scanner.get_cached_devices():
                st.info("✨ Checking for tracked devices...")
                if interface and ip:
                    network_range = netwatch.scanner.get_network_range(interface, ip)
                    if network_range:
                        with st.spinner("Scanning for tracked devices..."):
                            scan_devices = netwatch.scanner.scan_devices(interface, network_range)
                            # Filter to show only tracked devices
                            devices = [d for d in scan_devices if d["mac"] in tracked_macs]
                            if devices:
                                st.success(f"Found {len(devices)} tracked devices")
                            else:
                                st.warning("No tracked devices found on the network")
        # If no devices found from tracked scan, use cached devices
        if not devices:
            devices = netwatch.scanner.get_cached_devices() or []
            if not devices:
                st.info("🔍 Click 'Scan for Devices' to discover network devices")
        # Show traffic capture UI
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
