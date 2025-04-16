"""UI components for NetWatch"""
from datetime import datetime
from pathlib import Path
import json
import netifaces
import streamlit as st
import pandas as pd
import plotly.express as px
from network.visualizations.analyzer import TrafficVisualizer

def setup_page():
    """Setup the main page configuration"""
    st.title("📶 NetWatch")

def show_network_info(interface, ip):
    """Display network information in the sidebar"""
    st.sidebar.title("Network Info")

    if interface and ip:
        st.sidebar.success(f"🌐 Network Interface: {interface}")
        st.sidebar.info(f"📍 IP Address: {ip}")

        # Network interfaces in an expander
        with st.sidebar.expander("🔧 All Network Interfaces", expanded=False):
            for iface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
                    st.write(f"{iface}: {addr}")

def show_scan_results(devices, netwatch):
    """Display network scan results"""
    if devices:
        # Show tracked devices first
        st.subheader("📌 Tracked Devices")
        tracked_devices = netwatch.scanner.get_tracked_devices()
        if tracked_devices:
            st.success(f"🎯 {len(tracked_devices)} tracked devices found")
            tracked_df = pd.DataFrame([
                {
                    'IP Address': device.ip_address,
                    'MAC Address': device.mac_address,
                    'Device Name': device.hostname or 'Unknown',
                    'Activity': device.activity,
                    'First Seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S') if device.first_seen else 'N/A',
                    'Last Seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S') if device.last_seen else 'N/A',
                    'Actions': False
                }
                for device in tracked_devices
            ])
            # Display tracked devices with untrack button
            edited_tracked_df = st.data_editor(
                tracked_df,
                column_config={
                    'IP Address': st.column_config.TextColumn(width="medium"),
                    'MAC Address': st.column_config.TextColumn(width="medium"),
                    'Device Name': st.column_config.TextColumn(width="medium"),
                    'Activity': st.column_config.TextColumn(
                        width="small",
                        help="Device activity status"
                    ),
                    'First Seen': st.column_config.TextColumn(width="medium"),
                    'Last Seen': st.column_config.TextColumn(width="medium"),
                    'Actions': st.column_config.CheckboxColumn(
                        "Untrack Device",
                        help="Uncheck to stop tracking this device",
                        default=False
                    )
                },
                hide_index=True,
                use_container_width=True
            )
            # Handle untracking devices
            for _, row in edited_tracked_df.iterrows():
                if row['Actions']:
                    netwatch.scanner.untrack_device(row['MAC Address'])
                    st.rerun()
        else:
            st.info("No tracked devices yet")
        # Show other devices
        st.subheader("🌞 Other Network Devices")
        new_devices = netwatch.scanner.get_new_devices(limit=50, include_tracked=True)
        untracked_devices = [d for d in new_devices if not d.tracked]
        if untracked_devices:
            st.info(f"✨ {len(untracked_devices)} untracked devices")
            # Create a DataFrame for untracked devices
            new_df = pd.DataFrame([
                {
                    'IP Address': d.ip_address,
                    'MAC Address': d.mac_address,
                    'Device Name': d.hostname or 'Unknown',
                    'Activity': d.activity,
                    'First Seen': d.first_seen.strftime('%Y-%m-%d %H:%M:%S') if d.first_seen else 'N/A',
                    'Last Seen': d.last_seen.strftime('%Y-%m-%d %H:%M:%S') if d.last_seen else 'N/A',
                    'Track': False
                }
                for d in untracked_devices
            ])
            # Display untracked devices with track button
            edited_df = st.data_editor(
                new_df,
                column_config={
                    'IP Address': st.column_config.TextColumn(width="medium"),
                    'MAC Address': st.column_config.TextColumn(width="medium"),
                    'Device Name': st.column_config.TextColumn(width="medium"),
                    'Activity': st.column_config.TextColumn(
                        width="small",
                        help="Device activity status"
                    ),
                    'First Seen': st.column_config.TextColumn(width="medium"),
                    'Last Seen': st.column_config.TextColumn(width="medium"),
                    'Track': st.column_config.CheckboxColumn(
                        "Track Device",
                        help="Check to track this device",
                        default=False
                    )
                },
                hide_index=True,
                use_container_width=True
            )
            # Handle device tracking
            for _, row in edited_df.iterrows():
                device_mac = row['MAC Address']
                is_tracked = netwatch.scanner.is_device_tracked(device_mac)
                if row['Track'] != is_tracked:  # Only update if tracking status changed
                    if row['Track']:
                        netwatch.scanner.track_device(device_mac)
                    else:
                        netwatch.scanner.untrack_device(device_mac)
                    # Use session state to trigger rerun only once after all changes
                    if 'tracking_changed' not in st.session_state:
                        st.session_state.tracking_changed = True
                        st.rerun()
        else:
            st.info("No new devices found")
    else:
        st.warning("🛡️ No devices found. Please refresh the device list.")

def get_duration_parts(seconds):
    """Convert seconds into days, hours, minutes, seconds"""
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return days, hours, minutes, seconds

def get_duration_label(seconds):
    """Get human-readable duration label"""
    days, hours, minutes, secs = get_duration_parts(seconds)
    parts = []
    if days > 0:
        parts.append(f"{days} days")
    if hours > 0:
        parts.append(f"{hours} hours")
    if minutes > 0:
        parts.append(f"{minutes} minutes")
    if secs > 0 or not parts:
        parts.append(f"{secs} seconds")
    return ", ".join(parts)

def format_duration(value):
    """Format duration for slider"""
    return get_duration_label(value)

def show_traffic_capture_ui(netwatch, devices):
    """Display traffic capture UI"""
    # Show scanning status
    if not devices:
        st.warning("🛡️ No devices found. Use the 'Refresh Device List' button to scan for devices.")
        return

    # Quick actions at the top
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Quick Actions")
        capture_all = st.button("🔥 Capture All Traffic", type="primary", use_container_width=True)
    with col2:
        st.subheader("Duration")
        duration_option = st.selectbox(
            "Duration",  # Changed from empty string to label
            ["1 minute", "10 minutes", "30 minutes", "Custom"],
            index=0
        )

    # Duration settings
    if duration_option == "Custom":
        col1, col2 = st.columns([3, 1])
        with col1:
            minutes = st.number_input("Minutes", min_value=0, max_value=60, value=1)
            seconds = st.number_input("Seconds", min_value=0, max_value=59, value=0)
            duration = minutes * 60 + seconds
        with col2:
            unlimited = st.checkbox("Unlimited")
            if unlimited:
                duration = None
    else:
        duration = {
            "1 minute": 60,
            "10 minutes": 600,
            "30 minutes": 1800
        }[duration_option]

    # Device selection
    st.subheader("🔍 Select Devices")
    device_options = [f"{d.ip_address} ({d.hostname or 'N/A'})" for d in devices]
    selected_options = st.multiselect(
        "Select devices to monitor (optional)",
        options=device_options,
        help="Choose specific devices to capture traffic from, or capture all traffic"
    )

    # Get the full device info for each selected device
    selected_devices = []
    for option in selected_options:
        for device in devices:
            try:
                if f"{device.ip_address} ({device.hostname or 'N/A'})" == option:
                    selected_devices.append(device)
                    break
            except AttributeError:
                st.error(f"Error processing device: {device}. Please refresh the device list.")
                break

    # Show tracked devices
    with st.expander("📌 Tracked Devices", expanded=False):
        tracked_devices = netwatch.scanner.get_tracked_devices()
        if tracked_devices:
            for device in tracked_devices:
                try:
                    st.markdown(f"**{device.hostname or 'Unknown Device'} ({device.ip_address})**")
                    st.text(f"MAC: {device.mac_address}")
                    st.text(f"First Seen: {device.first_seen.strftime('%Y-%m-%d %H:%M')}")
                    st.text(f"Last Seen: {device.last_seen.strftime('%Y-%m-%d %H:%M')}")
                    st.text(f"Status: {device.activity}")
                    st.divider()
                except AttributeError:
                    st.error(f"Error displaying device info. Please refresh the device list.")
        else:
            st.info("No devices are currently being tracked")

    # Refresh button
    if st.button("🔄 Refresh Device List", type="secondary", use_container_width=True):
        st.rerun()

    # Start capture button
    if capture_all or selected_devices:
        start_capture = st.button("🎥 Start Capture", type="primary", use_container_width=True)
        if start_capture:
            target_ips = None if capture_all else [d.ip_address for d in selected_devices]

            # Create a unique filename for this capture
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if target_ips:
                if len(target_ips) == 1:
                    filename = f"capture_{timestamp}_{target_ips[0]}.pcap"
                else:
                    filename = f"capture_{timestamp}_{len(target_ips)}_devices.pcap"
            else:
                filename = f"capture_{timestamp}_all_traffic.pcap"

            # Start the capture
            with st.spinner(f"📦 Capturing traffic for {format_duration(duration) if duration else 'unlimited time'}..."):
                try:
                    netwatch.capture.capture_traffic(
                        target_ips=target_ips,
                        duration=duration,
                        filename=filename
                    )
                    st.success("✅ Capture completed successfully!")
                    st.info(f"💾 Saved as: {filename}")
                except Exception as e:
                    st.error(f"Error capturing traffic: {str(e)}. Please try again.")
    elif not selected_devices:
        st.info("👆 Select devices to monitor or use 'Capture All Traffic'")
    else:  # Device selection mode
        num_devices = len(selected_devices)
        if num_devices == 0:
            button_label = "🏳 SELECT DEVICES TO CAPTURE"
        elif num_devices == 1:
            button_label = "🏳 CAPTURE 1 DEVICE"
        else:
            button_label = f"🏳 CAPTURE {num_devices} DEVICES"
        button_type = "primary"
        can_capture = len(selected_devices) > 0
        target_ips = [d['ip'] for d in selected_devices] if selected_devices else None

    if can_capture and st.button(button_label, type=button_type, use_container_width=True):
        if duration or unlimited:
            # Show capture status
            status_container = st.empty()
            progress_container = st.empty()
            info_container = st.empty()

            # Show initial status
            if target_ips:
                status_container.info(f"🌐 Starting capture for {len(target_ips)} device{'s' if len(target_ips) > 1 else ''}...")
                device_info = []
                for ip in target_ips:
                    device = next((d for d in selected_devices if d['ip'] == ip), None)
                    if device:
                        device_info.append(f"📱 {device.get('hostname', 'Unknown Device')} ({ip})")
                if device_info:
                    info_container.markdown("\n".join(device_info))
            else:
                status_container.warning("🔥 Starting capture for ALL network traffic...")

            # Show duration info
            if duration:
                info_container.caption(f"⏱️ Duration: {get_duration_label(duration)}")
            else:
                info_container.caption("♻️ Unlimited duration (Press Stop when done)")

            # Start capture with progress bar
            progress = progress_container.progress(0)
            pcap_file = netwatch.capture.capture_traffic(
                target_ips=target_ips,
                duration=duration,
                progress_callback=progress.progress
            )

            if pcap_file:
                # Update status with success
                status_container.success("🎉 Capture completed successfully!")
                info_container.info(f"📂 Saved as: {pcap_file}")
                # Multiple celebrations!
                st.balloons()
                st.snow()

def format_bytes(size):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def show_pcap_analysis(stats):
    """Display PCAP analysis results with interactive visualizations"""
    if not stats:
        st.warning("No PCAP analysis results available")
        return

    # Display basic stats in an expander for cleaner UI
    with st.expander("📊 Basic Statistics", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Packets", f"{stats['summary']['total_packets']:,}")
        with col2:
            st.metric("Total Bytes", format_bytes(stats['summary']['total_bytes']))
        with col3:
            duration = stats['summary']['end_time'] - stats['summary']['start_time']
            st.metric("Duration", f"{duration:.2f}s")

    # Create tabs for different analysis views
    traffic_tab, protocol_tab, web_tab = st.tabs(["🌐 Traffic Analysis", "📡 Protocol Analysis", "🔍 Web Traffic"])
    # Display interactive visualizations
    viz = TrafficVisualizer()
    # Add visualization tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Traffic Overview", "Network Analysis", "Performance", "Security"])
    with tab1:
        st.subheader("Protocol Distribution")
        st.plotly_chart(viz.create_protocol_distribution(stats))
        st.subheader("Bandwidth Usage")
        st.plotly_chart(viz.create_bandwidth_timeline(stats))
        st.subheader("Protocol Activity")
        st.plotly_chart(viz.create_protocol_activity(stats))
    with tab2:
        st.subheader("Network Flow Diagram")
        st.plotly_chart(viz.create_network_flow_diagram(stats))
        st.subheader("Connection Matrix")
        st.plotly_chart(viz.create_connection_matrix(stats))
        if stats.get('media', {}).get('streaming'):
            st.subheader("Streaming Media Quality")
            st.plotly_chart(viz.create_media_quality(stats))
        if stats.get('voip', {}).get('calls'):
            st.subheader("VoIP Call Quality")
            st.plotly_chart(viz.create_voip_quality(stats))
    with tab3:
        st.subheader("Performance Metrics")
        st.plotly_chart(viz.create_performance_metrics(stats))
        st.subheader("TCP Metrics")
        st.plotly_chart(viz.create_tcp_metrics(stats))
    with tab4:
        st.subheader("Security Overview")
        st.plotly_chart(viz.create_security_overview(stats))
        if stats.get('security', {}).get('port_scans'):
            st.subheader("Port Scan Attempts")
            st.plotly_chart(viz.create_port_scan_viz(stats))
        if stats.get('security', {}).get('ssl_issues'):
            st.subheader("SSL/TLS Issues")
            st.plotly_chart(viz.create_ssl_issues_viz(stats))
    # Create two columns - device captures and conversations
    col1, col2 = st.columns([7, 3])
    with col2:
        st.header("📱 Device Captures")
        # Load tracked devices
        with open('data/tracked_devices.json', 'r', encoding='utf-8') as f:
            tracked_devices = json.load(f)['devices']
        # List PCAP files for each device
        for device in tracked_devices:
            device_id = device.get('mac', '').replace(':', '')
            if device_id:
                device_name = device.get('name', device.get('hostname', device_id))
                with st.expander(f"📱 {device_name}"):
                    # Find device's PCAP files
                    device_pcaps = sorted(
                        Path('captures').glob(f'*{device_id}*.pcap'),
                        key=lambda x: x.stat().st_mtime,
                        reverse=True
                    )
                    if device_pcaps:
                        for pcap in device_pcaps:
                            # Get file info
                            mtime = datetime.fromtimestamp(pcap.stat().st_mtime)
                            size = pcap.stat().st_size
                            size_str = f"{size/1024/1024:.1f}MB" if size > 1024*1024 else f"{size/1024:.1f}KB"
                            # Show file with download button
                            col_a, col_b = st.columns([3, 1])
                            with col_a:
                                st.text(f"{mtime.strftime('%Y-%m-%d %H:%M')} ({size_str})")
                            with col_b:
                                with open(pcap, 'rb', encoding=None) as f:
                                    st.download_button(
                                        "📥",
                                        f,
                                        file_name=pcap.name,
                                        mime="application/vnd.tcpdump.pcap"
                                    )
                    else:
                        st.info("No captures yet")

    with col1:
        # Check VoIP analysis availability
        from network.capture import HAS_VOIP_LAYERS
        if not HAS_VOIP_LAYERS:
            st.warning("VoIP analysis features are not available. Install scapy[voip] for full functionality.")

    def get_device_info(ip, scanner=None):
        """Get device info from IP address
        Args:
            ip: IP address to lookup
            scanner: Optional NetworkScanner instance
        Returns:
            str: Device hostname if found, None otherwise
        """
        if scanner:
            device = scanner.get_device_by_ip(ip)
            if device and device.hostname:
                return device.hostname
        return None

    with web_tab:
        if stats['web'].get('urls'):
            # Group URLs by device with better organization
            for ip, urls in stats['web']['urls'].items():
                device_info = get_device_info(ip, netwatch.scanner if netwatch else None)
                title = f"{device_info} ({ip})" if device_info else ip

                with st.expander(f"📱 {title} - {len(urls)} URLs visited"):
                    # Create a DataFrame for better visualization
                    url_df = pd.DataFrame([
                        {
                            'URL': url['url'],
                            'Timestamp': datetime.fromtimestamp(url.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                            'Method': url.get('method', 'GET'),
                            'Status': url.get('status', 'Unknown')
                        }
                        for url in urls
                    ])
                    st.dataframe(url_df, hide_index=True, use_container_width=True)
        else:
            st.info("No web traffic data available")
        if stats['web'].get('urls'):
            for url, visits in stats['web']['urls'].items():
                for visit in visits:
                    timestamp = visit['timestamp']
                    method = visit.get('method', 'GET')
                    # Create a card-like display for each URL
                    col1, col2 = st.columns([1, 3])
                    with col1:
                        # Show favicon if available
                        favicon = stats['web']['favicons'].get(url)
                        if favicon:
                            st.image(favicon, width=32)
                        else:
                            st.markdown("🌐")
                    with col2:
                        # Show URL with title and description
                        title = stats['web']['titles'].get(url, url)
                        description = stats['web']['descriptions'].get(url, '')
                        st.markdown(f"**[{title}]({url})**")
                        if description:
                            st.markdown(f"_{description}_")
                        st.text(f"{method} - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    # Summary statistics
    st.header("📊 Traffic Analysis")

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", f"{stats['summary']['total_packets']:,}")
    with col2:
        st.metric("Duration", f"{stats['summary']['duration']:.2f}s")
    with col3:
        st.metric("Packets/Second", f"{stats['summary']['packets_per_second']:.1f}")
    with col4:
        st.metric("Bandwidth", f"{stats['summary']['bandwidth_mbps']:.2f} Mbps")

    # Web Traffic Analysis
    if stats['web']['urls']:
        st.subheader("🌐 Web Traffic")
        tabs = st.tabs(["URLs by Device", "Top Domains", "Media Types"])
        with tabs[0]:
            # Show URLs visited by each device
            for ip, urls in stats['web']['urls'].items():
                with st.expander(f"💻 Device {ip} - {len(urls)} URLs visited"):
                    for visit in urls:
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown(f"[🌐 {visit['url']}]({visit['url']})")
                        with col2:
                            st.caption(datetime.fromtimestamp(visit['timestamp']).strftime('%H:%M:%S'))
        with tabs[1]:
            # Show top domains
            domains_df = pd.DataFrame(
                stats['web']['domains'].items(),
                columns=['Domain', 'Visits']
            ).sort_values('Visits', ascending=False).head(20)
            fig = px.bar(domains_df,
                         x='Domain', y='Visits',
                         title="Top Domains Visited",
                         color='Visits',
                         color_continuous_scale='Viridis')
            fig.update_layout(xaxis_tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        with tabs[2]:
            # Show media types
            if stats['web']['media_types']:
                media_df = pd.DataFrame(
                    stats['web']['media_types'].items(),
                    columns=['Type', 'Count']
                ).sort_values('Count', ascending=False)
                fig = px.pie(media_df,
                            values='Count',
                            names='Type',
                            title="Content Types Distribution")
                st.plotly_chart(fig, use_container_width=True)
    # Media Analysis
    if stats.get('media', {}).get('streams') or stats.get('media', {}).get('files'):
        st.subheader("🎥 Media Analysis")
        # Voice/Video Calls (SIP/RTP)
        if stats.get('media', {}).get('streams'):
            st.write("📞 Voice/Video Streams")
            for stream in sorted(stats.get('media', {}).get('streams', []), key=lambda x: x.get('timestamp', 0)):
                with st.expander(f"{stream['type']} Stream: {stream['source']} → {stream['destination']}"):
                    st.write(f"Started at: {datetime.fromtimestamp(stream['timestamp']).strftime('%H:%M:%S')}")
                    if 'size' in stream:
                        st.write(f"Data transferred: {format_bytes(stream['size'])}")
                    if stream['type'] == 'SIP':
                        st.write(f"Call {stream['method']}")
                        if stream['method'] == 'INVITE':
                            st.button("▶️ Play Call Recording", key=f"play_{stream['timestamp']}")
        # Media Files
        if stats['media']['files']:
            st.write("🎨 Media Files")
            for media in sorted(stats['media']['files'], key=lambda x: x['timestamp']):
                with st.expander(f"{media['type']}: {media['source']} → {media['destination']}"):
                    st.write(f"Time: {datetime.fromtimestamp(media['timestamp']).strftime('%H:%M:%S')}")
                    st.write(f"Size: {format_bytes(media['size'])}")
                    st.button("▶️ Play Media", key=f"play_media_{media['timestamp']}")
    # File Transfer Analysis
    if stats['file_transfers']['ftp'] or stats['file_transfers']['sftp']:
        st.subheader("📁 File Transfers")
        col1, col2 = st.columns(2)
        with col1:
            if stats['file_transfers']['ftp']:
                st.write("📂 FTP Transfers")
                for transfer in sorted(stats['file_transfers']['ftp'], key=lambda x: x['timestamp']):
                    st.info(f"Command: {transfer['command']}")
                    st.caption(f"{transfer['source']} → {transfer['destination']} at {datetime.fromtimestamp(transfer['timestamp']).strftime('%H:%M:%S')}")
        with col2:
            if stats['file_transfers']['sftp']:
                st.write("🔒 SFTP Transfers")
                for transfer in sorted(stats['file_transfers']['sftp'], key=lambda x: x['timestamp']):
                    st.info(f"Size: {format_bytes(transfer['size'])}")
                    st.caption(f"{transfer['source']} → {transfer['destination']} at {datetime.fromtimestamp(transfer['timestamp']).strftime('%H:%M:%S')}")
    # BitTorrent Analysis
    if stats['torrents']['peers'] or stats['torrents']['data_transfer']:
        st.subheader("🔥 P2P Traffic")
        col1, col2 = st.columns(2)
        with col1:
            # Show peer connections
            peers_data = [(ip, len(peers)) for ip, peers in stats['torrents']['peers'].items()]
            if peers_data:
                peers_df = pd.DataFrame(peers_data, columns=['IP', 'Peer Count'])
                fig = px.bar(peers_df,
                            x='IP', y='Peer Count',
                            title="P2P Connections per IP",
                            color='Peer Count',
                            color_continuous_scale='Viridis')
                st.plotly_chart(fig, use_container_width=True)
        with col2:
            # Show data transfer
            transfer_data = [(ip, bytes) for ip, bytes in stats['torrents']['data_transfer'].items()]
            if transfer_data:
                transfer_df = pd.DataFrame(transfer_data, columns=['IP', 'Bytes'])
                transfer_df['Data'] = transfer_df['Bytes'].apply(format_bytes)
                fig = px.bar(transfer_df,
                            x='IP', y='Bytes',
                            title="P2P Data Transfer per IP",
                            color='Bytes',
                            color_continuous_scale='Viridis')
                st.plotly_chart(fig, use_container_width=True)

    # TCP Flags Analysis (if TCP traffic exists)
    if any(stats['tcp_flags'].values()):
        st.subheader("🚩 TCP Flags Distribution")
        tcp_flags = pd.DataFrame([
            {"Flag": flag, "Count": count}
            for flag, count in stats['tcp_flags'].items()
            if count > 0  # Only show flags that were seen
        ])
        fig = px.bar(tcp_flags, x='Flag', y='Count',
                     title="TCP Flag Distribution",
                     color='Count',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)

    # Traffic Flow Analysis
    st.subheader("🌊 Traffic Flow Analysis")
    col1, col2 = st.columns(2)

    with col1:
        # Packet sizes over time
        df = pd.DataFrame({
            'timestamp': pd.to_datetime(stats['timestamps'], unit='s'),
            'size': stats['packet_sizes']
        })
        fig = px.line(df, x='timestamp', y='size',
                      title="Packet Sizes Over Time",
                      labels={'timestamp': 'Time', 'size': 'Packet Size (bytes)'})
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Packet size distribution
        fig = px.histogram(df, x='size',
                          title="Packet Size Distribution",
                          labels={'size': 'Packet Size (bytes)', 'count': 'Frequency'},
                          nbins=50)
        st.plotly_chart(fig, use_container_width=True)

    # Data Usage Analysis
    st.subheader("📊 Data Usage Analysis")
    if stats['ips']['data_usage']:
        usage_data = [(ip, bytes) for ip, bytes in stats['ips']['data_usage'].items()]
        usage_df = pd.DataFrame(usage_data, columns=['IP', 'Bytes'])
        usage_df['Data'] = usage_df['Bytes'].apply(format_bytes)
        usage_df = usage_df.sort_values('Bytes', ascending=False)

        fig = px.bar(usage_df,
                     x='IP', y='Bytes',
                     title="Data Usage by IP",
                     color='Bytes',
                     color_continuous_scale='Viridis')
        fig.update_layout(yaxis_title="Data Usage")
        st.plotly_chart(fig, use_container_width=True)

        # Show detailed table
        st.dataframe(
            usage_df[['IP', 'Data']].rename(columns={'Data': 'Total Usage'}),
            hide_index=True,
            use_container_width=True
        )

    # Protocol Analysis
    st.subheader("🔍 Protocol Analysis")
    col1, col2 = st.columns(2)

    with col1:
        # Transport protocols
        fig = px.pie(
            values=list(stats['protocols']['transport'].values()),
            names=list(stats['protocols']['transport'].keys()),
            title="Transport Protocols",
            hole=0.4  # Make it a donut chart
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Application protocols
        fig = px.pie(
            values=list(stats['protocols']['application'].values()),
            names=list(stats['protocols']['application'].keys()),
            title="Application Protocols",
            hole=0.4  # Make it a donut chart
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

    # IP Analysis
    st.subheader("🌐 IP Analysis")
    # Load tracked devices for reference
    try:
        with open('data/tracked_devices.json', 'r', encoding='utf-8') as f:
            tracked_devices = json.load(f)['devices']
            # Create lookup maps for device info
            ip_to_device = {}
            for device in tracked_devices:
                if 'ip' in device:
                    ip_to_device[device['ip']] = device
                if 'last_known_ip' in device:
                    ip_to_device[device['last_known_ip']] = device
    except (OSError, IOError, json.JSONDecodeError):
        tracked_devices = []
        ip_to_device = {}

    def get_device_info(ip):
        if ip in ip_to_device:
            device = ip_to_device[ip]
            name = device.get('name', device.get('hostname', ''))
            description = device.get('description', '')
            return f"{name} ({description})" if description else name
        return ''

    # Create three columns for analysis
    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("**Top Sources**")
        for ip, count in sorted(stats['ips']['src'].items(), key=lambda x: x[1], reverse=True)[:10]:
            device_info = get_device_info(ip)
            title = f"{device_info} ({ip})" if device_info else ip
            with st.expander(f"📱 {title} - {count:,} packets"):
                # Show data usage
                data_usage = stats['ips']['data_usage'].get(ip, 0)
                st.text(f"Total Data: {format_bytes(data_usage)}")
                # Show top destinations for this source
                st.markdown("**Top Destinations:**")
                dest_data = []
                for conv, conv_count in stats['ips']['conversations'].items():
                    src, dst = conv.split(' → ')
                    if src == ip:
                        dest_info = get_device_info(dst)
                        dest_name = f"{dest_info} ({dst})" if dest_info else dst
                        protocols = stats['ips']['conversation_protocols'][conv]
                        dest_data.append({
                            'destination': dest_name,
                            'packets': conv_count,
                            'protocols': dict(protocols)
                        })

                for dest in sorted(dest_data, key=lambda x: x['packets'], reverse=True)[:5]:
                    st.text(f"→ {dest['destination']}: {dest['packets']:,} packets")
                    if dest['protocols']:
                        st.text("  Protocols:")
                        for proto, proto_count in sorted(dest['protocols'].items(), key=lambda x: x[1], reverse=True):
                            st.text(f"    {proto}: {proto_count:,} packets")
    with col2:
        st.markdown("**Top Destinations**")
        for ip, count in sorted(stats['ips']['dst'].items(), key=lambda x: x[1], reverse=True)[:10]:
            device_info = get_device_info(ip)
            title = f"{device_info} ({ip})" if device_info else ip
            with st.expander(f"📱 {title} - {count:,} packets"):
                # Show data usage
                data_usage = stats['ips']['data_usage'].get(ip, 0)
                st.text(f"Total Data: {format_bytes(data_usage)}")
                # Show top sources for this destination
                st.markdown("**Top Sources:**")
                src_data = []
                for conv, conv_count in stats['ips']['conversations'].items():
                    src, dst = conv.split(' → ')
                    if dst == ip:
                        src_info = get_device_info(src)
                        src_name = f"{src_info} ({src})" if src_info else src
                        protocols = stats['ips']['conversation_protocols'][conv]
                        src_data.append({
                            'source': src_name,
                            'packets': conv_count,
                            'protocols': dict(protocols)
                        })

                for src in sorted(src_data, key=lambda x: x['packets'], reverse=True)[:5]:
                    st.text(f"← {src['source']}: {src['packets']:,} packets")
                    if src['protocols']:
                        st.text("  Protocols:")
                        for proto, proto_count in sorted(src['protocols'].items(), key=lambda x: x[1], reverse=True):
                            st.text(f"    {proto}: {proto_count:,} packets")

def show_pcap_analysis(stats):
    """Display PCAP analysis results with interactive visualizations"""
    # Create tabs for different analysis views
    overview_tab, conversation_tab, protocol_tab = st.tabs(["Overview", "Conversations", "Protocols"])

    # Overview tab
    with overview_tab:
        # Basic statistics
        st.subheader("📊 Basic Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Packets", f"{stats['total_packets']:,}")
            st.metric("Total Bytes", format_bytes(stats['total_bytes']))
        with col2:
            st.metric("Duration", get_duration_label(stats['duration']))
            st.metric("Average Packet Size", format_bytes(stats['avg_packet_size']))

        # Traffic over time
        if stats['traffic_over_time']:
            st.subheader("📈 Traffic Over Time")
            time_df = pd.DataFrame([
                {'Time': time, 'Packets': count}
                for time, count in stats['traffic_over_time'].items()
            ])
            fig = px.line(time_df, x='Time', y='Packets',
                         title='Packet Count Over Time')
            st.plotly_chart(fig, use_container_width=True)

    # Conversations tab
    with conversation_tab:
        st.subheader("🗣️ Top Conversations")
        conversations = stats['ips']['conversations']
        if conversations:
            # Sort conversations by packet count
            sorted_convs = sorted(conversations.items(),
                                 key=lambda x: x[1], reverse=True)
            for conv, count in sorted_convs[:10]:
                src, dst = conv.split(' → ')
                src_info = get_device_info(src)
                dst_info = get_device_info(dst)
                src_title = f"{src_info} ({src})" if src_info else src
                dst_title = f"{dst_info} ({dst})" if dst_info else dst
                with st.expander(f"{src_title} → {dst_title} - {count:,} packets"):
                    # Show protocol breakdown
                    if conv in stats['ips']['conversation_protocols']:
                        st.markdown("**Protocol Breakdown:**")
                        protocols = stats['ips']['conversation_protocols'][conv]
                        for proto, proto_count in sorted(protocols.items(),
                                                       key=lambda x: x[1],
                                                       reverse=True):
                            percentage = (proto_count / count) * 100
                            st.text(f"{proto}: {proto_count:,} packets ({percentage:.1f}%)")

                    # Show data transfer
                    src_data = stats['ips']['data_usage'].get(src, 0)
                    dst_data = stats['ips']['data_usage'].get(dst, 0)
                    st.markdown("**Data Transfer:**")
                    st.text(f"Source → Destination: {format_bytes(src_data)}")
                    st.text(f"Destination → Source: {format_bytes(dst_data)}")

    with protocol_tab:
        # Protocol Analysis with better organization
        if stats['protocols']:
            col1, col2 = st.columns(2)
            with col1:
                # Create DataFrame for protocols
                proto_df = pd.DataFrame([
                    {'Protocol': proto, 'Count': count}
                    for proto, count in stats['protocols'].items()
                ]).sort_values('Count', ascending=False)

                st.dataframe(proto_df, hide_index=True, use_container_width=True)

            with col2:
                fig = px.pie(proto_df, values='Count', names='Protocol',
                            title='Protocol Distribution')
                st.plotly_chart(fig, use_container_width=True)

        # Port Analysis
        st.markdown("### 🔌 Port Analysis")
        port_source_tab, port_dest_tab = st.tabs(["Source Ports", "Destination Ports"])

        with port_source_tab:
            if stats['ports']['src']:
                # Create DataFrame for source ports
                src_ports = pd.DataFrame([
                    {'Port': str(port), 'Count': count}
                    for port, count in stats['ports']['src'].items()
                ]).sort_values('Count', ascending=False).head(10)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(src_ports, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.bar(src_ports, x='Port', y='Count',
                                title='Top Source Ports',
                                color='Count',
                                color_continuous_scale='Viridis')
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No source port data available")

        with port_dest_tab:
            if stats['ports']['dst']:
                # Create DataFrame for destination ports
                dst_ports = pd.DataFrame([
                    {'Port': str(port), 'Count': count}
                    for port, count in stats['ports']['dst'].items()
                ]).sort_values('Count', ascending=False).head(10)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(dst_ports, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.bar(dst_ports, x='Port', y='Count',
                                title='Top Destination Ports',
                                color='Count',
                                color_continuous_scale='Viridis')
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No destination port data available")
