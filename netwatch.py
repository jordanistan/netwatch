#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
import logging

import streamlit as st

from network.scanner import NetworkScanner
from network.capture import TrafficCapture
from network.monitor import DeviceMonitor
from ui.components import setup_page, show_network_info, show_scan_results, show_pcap_analysis_ui, show_traffic_capture_page

import json

class NetWatch:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.captures_dir = self.base_dir / "captures"
        self.reports_dir = self.base_dir / "reports"
        self.logs_dir = self.base_dir / "logs"
        self.config_path = self.base_dir / "config" / "config.json"
        # Load config
        self.config = self._load_config()
        # Create necessary directories
        for dir_path in [self.captures_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        # Initialize components with config
        self.scanner = NetworkScanner()
        self.capture = TrafficCapture(self.captures_dir)
        self.monitor = DeviceMonitor(self.captures_dir)
        # Start device monitoring
        self.monitor.start_monitoring()

    def _load_config(self):
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[Config] Error loading config: {e}")
        # Return defaults if not found or error
        return {
            "network": {"interface": "auto", "scan_interval": 300, "exclude_ips": ["127.0.0.1"]},
            "capture": {"rotate_size": "1GB", "max_files": 10, "compression": True},
            "monitoring": {"check_interval": 60, "alert_threshold": 1000}
        }

    def start_capture(self, target_ips=None):
        """Start network traffic capture
        Args:
            target_ips: List of IP addresses to capture traffic for, or None for all traffic
        Returns:
            Path: Path to the saved capture file, or None if capture failed
        """
        if target_ips:
            print(f"[Capture] Starting capture for IPs: {target_ips}")
        else:
            print("[Capture] Starting capture for all traffic")
        return self.capture.capture_traffic(target_ips=target_ips)

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
            ["Network Scan", "Traffic Capture", "PCAP Analysis", "Alerts"]
        )

        # Get network interface (from config if set)
        interface = None
        ip = None
        config_iface = netwatch.config.get('network', {}).get('interface', 'auto')
        if config_iface != 'auto':
            # Try to get IP for specified interface
            import netifaces
            try:
                addrs = netifaces.ifaddresses(config_iface)
                ip = addrs[netifaces.AF_INET][0]['addr'] if netifaces.AF_INET in addrs else None
                interface = config_iface
            except Exception:
                interface, ip = netwatch.scanner.get_default_interface()
        else:
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
                            try:
                                devices = netwatch.scanner.scan_devices(interface, network_range)
                                # Log the raw devices list returned by the scanner
                                logging.debug(f"Devices returned from scan: {devices}")
                                show_scan_results(devices, netwatch)
                                # Celebration effect when scan completes successfully
                                st.balloons()
                                st.success("🎉 Network scan completed successfully!")
                            except Exception as e:
                                st.error(f"Error during network scan: {e}")
                                logging.exception("Network scan failed") # Log traceback
                else:
                    st.error("No suitable network interface found")

        elif action == "Traffic Capture":
            st.header("Traffic Capture")
            # Initialize session state for devices if not exists
            refresh_clicked = st.button("🔄 Refresh Device List")
            if 'traffic_capture_devices' not in st.session_state or refresh_clicked:
                try:
                    devices = []
                    # Always do a fresh scan when refresh is clicked
                    if refresh_clicked and interface and ip:
                        network_range = netwatch.scanner.get_network_range(interface, ip)
                        if network_range:
                            with st.spinner("Scanning network for devices..."):
                                devices = netwatch.scanner.scan_devices(interface, network_range)
                    else:
                        # Try to get cached devices if not refreshing
                        devices = netwatch.scanner.get_cached_devices() or []
                        # Do a fresh scan if no cached devices
                        if not devices and interface and ip:
                            network_range = netwatch.scanner.get_network_range(interface, ip)
                            if network_range:
                                with st.spinner("Scanning network for devices..."):
                                    devices = netwatch.scanner.scan_devices(interface, network_range)

                    if devices:
                        # Get activity status for each device
                        devices_with_status = []
                        for device in devices:
                            try:
                                # Get device history
                                device_history = netwatch.scanner.device_history['devices'].get(device.mac_address, {})
                                activity = netwatch.scanner._get_activity_status(device_history) if device_history else "New Device"
                                device.activity = activity
                                devices_with_status.append(device)
                            except Exception as e:
                                st.warning(f"Error processing device {device.mac_address}: {str(e)}")
                                continue
                        st.session_state.traffic_capture_devices = devices_with_status
                    else:
                        st.warning("No devices found in cache or network scan")
                        st.session_state.traffic_capture_devices = []
                except Exception as e:
                    st.error(f"Error scanning network: {str(e)}")
                    st.session_state.traffic_capture_devices = []

            # Show traffic capture UI with the devices we found
            if 'traffic_capture_devices' in st.session_state:
                show_traffic_capture_page(netwatch, st.session_state.traffic_capture_devices)

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
                        selected_pcap = st.selectbox(
                            "Select PCAP file",
                            pcap_files,
                            format_func=lambda x: f"{x.name} ({datetime.fromtimestamp(x.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')})"
                        )
                    with col2:
                        # Display file size
                        file_size = selected_pcap.stat().st_size
                        st.info(f"Size: {file_size / (1024*1024):.2f} MB")
                        st.info(f"Selected PCAP: {selected_pcap.name}")
                    # Place Analyze button below selectbox and size info
                    if st.button("\U0001f50d Analyze", type="primary", use_container_width=True):
                        try:
                            with st.spinner("Analyzing PCAP file..."):
                                # Correctly call analyze_pcap on the netwatch instance
                                analysis_results = netwatch.capture.analyze_pcap(selected_pcap)
                                if analysis_results:
                                    # Pass both netwatch and analysis_results
                                    show_pcap_analysis_ui(netwatch, analysis_results)
                                else:
                                    st.warning("No analysis results generated.")
                        except Exception as e:
                            st.error(f"Error analyzing PCAP file: {e}")
                            logging.exception("PCAP Analysis failed") # Log traceback
            except Exception as e:
                st.error(f"Error accessing captures directory: {str(e)}")
                logging.exception("Error listing PCAP files") # Log traceback

        elif action == "Alerts":
            from ui.components import show_alerts_page
            show_alerts_page()

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
