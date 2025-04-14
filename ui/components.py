"""UI components for NetWatch"""
import json
from datetime import datetime
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
import netifaces

def setup_page():
    """Setup the main page configuration"""
    st.set_page_config(
        page_title="NetWatch",
        page_icon="📶",
        layout="wide"
    )
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
        # Show newest devices first
        st.subheader("🌞 Latest Network Activity")
        new_devices = netwatch.scanner.get_new_devices(limit=10)
        if new_devices:
            st.info(f"✨ {len(new_devices)} recently active devices")
            # Create a DataFrame for new devices
            new_df = pd.DataFrame([
                {
                    'IP Address': d['ip'],
                    'MAC Address': d['mac'],
                    'Device Name': d['hostname'],
                    'Activity': d['activity'],
                    'First Seen': datetime.fromisoformat(d['first_seen']).strftime('%Y-%m-%d %H:%M:%S'),
                    'Last Seen': datetime.fromisoformat(d['last_seen']).strftime('%Y-%m-%d %H:%M:%S')
                }
                for d in new_devices
            ])
            st.dataframe(
                new_df,
                column_config={
                    'IP Address': st.column_config.TextColumn(width="medium"),
                    'MAC Address': st.column_config.TextColumn(width="medium"),
                    'Device Name': st.column_config.TextColumn(width="medium"),
                    'Activity': st.column_config.TextColumn(
                        width="small",
                        help="Whether this is a new device or a device that has rejoined the network"
                    ),
                    'First Seen': st.column_config.TextColumn(width="medium"),
                    'Last Seen': st.column_config.TextColumn(width="medium")
                },
                hide_index=True,
                use_container_width=True
            )
        
        # Show all devices
        st.subheader("📶 All Network Devices")
        st.success(f"✨ Found {len(devices)} total devices")
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
        st.balloons()
    else:
        st.warning("😕 No devices found")

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
    st.header("Traffic Capture")
    
    # Container to store the updated devices list
    if 'devices' not in st.session_state:
        st.session_state.devices = devices
    
    # Manual scan button
    if st.button("🔍 Scan for Devices", type="primary", use_container_width=True):
        with st.spinner("Scanning network..."):
            interface, ip = netwatch.scanner.get_default_interface()
            if interface and ip:
                network_range = netwatch.scanner.get_network_range(interface, ip)
                if network_range:
                    st.session_state.devices = netwatch.scanner.scan_devices(interface, network_range)
                    if st.session_state.devices:
                        st.success(f"✨ Found {len(st.session_state.devices)} devices")
                        st.balloons()
    
    # Traffic capture mode selection
    if 'previous_mode' not in st.session_state:
        st.session_state.previous_mode = "All Traffic 🔥"
    
    capture_mode = st.radio(
        "Capture Mode",
        ["All Traffic 🔥", "Select Devices 🏳"],
        horizontal=True,
        help="Choose to capture all network traffic or select specific devices"
    )
    
    # Auto-scan when switching to device selection mode
    if capture_mode != st.session_state.previous_mode and capture_mode == "Select Devices 🏳":
        if not st.session_state.devices:
            with st.spinner("Scanning network for devices..."):
                interface, ip = netwatch.scanner.get_default_interface()
                if interface and ip:
                    network_range = netwatch.scanner.get_network_range(interface, ip)
                    if network_range:
                        st.session_state.devices = netwatch.scanner.scan_devices(interface, network_range)
                        if st.session_state.devices:
                            st.success(f"✨ Found {len(st.session_state.devices)} devices")
                            st.balloons()
    
    st.session_state.previous_mode = capture_mode
    
    # Device selection (only shown for device selection mode)
    selected_devices = []
    if capture_mode == "Select Devices 🏳":
        if st.session_state.devices:
            # Create a list of device options
            device_options = [f"{d['ip']} ({d.get('hostname', 'N/A')})" for d in st.session_state.devices]
            selected_options = st.multiselect(
                "Select Target Devices",
                options=device_options,
                help="Choose one or more devices to monitor"
            )
            # Get the full device info for each selected option
            for option in selected_options:
                for device in st.session_state.devices:
                    if f"{device['ip']} ({device.get('hostname', 'N/A')})" == option:
                        selected_devices.append(device)
                        break
        else:
            st.warning("🛡️ No devices available. Use the scan button above to discover devices.")
    
    # Duration settings
    col1, col2 = st.columns([3, 1])
    with col1:
        max_seconds = 3 * 24 * 60 * 60  # 3 days in seconds
        days, hours, minutes, secs = get_duration_parts(max_seconds)
        st.caption(f"Maximum duration: {days} days, {hours} hours, {minutes} minutes, {secs} seconds")
        
        duration = st.slider(
            "Capture Duration",
            min_value=10,
            max_value=max_seconds,
            value=60,
            format="%d",
            help="Slide to adjust duration from 10 seconds up to 3 days"
        )
        
        # Show detailed duration breakdown
        days, hours, minutes, secs = get_duration_parts(duration)
        parts = []
        if days > 0:
            parts.append(f"{days} days")
        if hours > 0:
            parts.append(f"{hours} hours")
        if minutes > 0:
            parts.append(f"{minutes} minutes")
        if secs > 0 or not parts:
            parts.append(f"{secs} seconds")
        st.caption("Duration: " + ", ".join(parts))
    with col2:
        unlimited = st.checkbox("Unlimited")
        if unlimited:
            duration = None
    
    # Automated capture settings
    auto_capture = st.checkbox("Enable Automated Capture")
    if auto_capture:
        st.info("⚠️ Automated capture will start when the selected device is detected on the network")
        # Save selected devices for tracking
        tracked_devices_file = Path("data/tracked_devices.json")
        tracked_devices_file.parent.mkdir(parents=True, exist_ok=True)
        
        if tracked_devices_file.exists():
            tracked_devices = json.loads(tracked_devices_file.read_text())
        else:
            tracked_devices = {"devices": []}
        
        # Add selected devices if not already tracked
        for device in selected_devices:
            device_info = {
                "mac": device["mac"],
                "last_known_ip": device["ip"],
                "hostname": device.get("hostname", "N/A")
            }
            if device_info not in tracked_devices["devices"]:
                tracked_devices["devices"].append(device_info)
        
        # Save updated tracked devices
        tracked_devices_file.write_text(json.dumps(tracked_devices, indent=4))
    
    # Show capture button with dynamic text and color based on mode
    if capture_mode == "All Traffic 🔥":
        button_label = "🔥 CAPTURE ALL TRAFFIC ☠️"
        button_type = "secondary"
        can_capture = True
        target_ips = None
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
                progress_callback=lambda p: progress.progress(p)
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
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def show_pcap_analysis(stats):
    """Display PCAP analysis results"""
    # Check VoIP analysis availability
    from network.capture import HAS_VOIP_LAYERS
    if not HAS_VOIP_LAYERS:
        st.warning("VoIP analysis features are not available. Install scapy[voip] for full functionality.")
    # Web Traffic Analysis
    st.header("🌐 Web Traffic Analysis")
    # URLs by Device
    if stats['web']['urls']:
        st.subheader("🌐 URLs by Device")
        for ip, urls in stats['web']['urls'].items():
            with st.expander(f"Device {ip} - {len(urls)} URLs visited"):
                for visit in urls:
                    url = visit['url']
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
    if stats['media']['streams'] or stats['media']['files']:
        st.subheader("🎥 Media Analysis")
        # Voice/Video Calls (SIP/RTP)
        if stats['media']['streams']:
            st.write("📞 Voice/Video Streams")
            for stream in sorted(stats['media']['streams'], key=lambda x: x['timestamp']):
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
    tab1, tab2, tab3 = st.tabs(["Top Sources", "Top Destinations", "Top Conversations"])
    
    with tab1:
        # Top source IPs
        src_ips = pd.DataFrame(
            stats['ips']['src'].items(),
            columns=['IP', 'Packets Sent']
        ).sort_values('Packets Sent', ascending=False).head(10)
        
        fig = px.bar(src_ips,
                     x='IP', y='Packets Sent',
                     title="Top Source IPs",
                     color='Packets Sent',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Top destination IPs
        dst_ips = pd.DataFrame(
            stats['ips']['dst'].items(),
            columns=['IP', 'Packets Received']
        ).sort_values('Packets Received', ascending=False).head(10)
        
        fig = px.bar(dst_ips,
                     x='IP', y='Packets Received',
                     title="Top Destination IPs",
                     color='Packets Received',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Top conversations
        conversations = pd.DataFrame(
            stats['ips']['conversations'].items(),
            columns=['Flow', 'Packets']
        ).sort_values('Packets', ascending=False).head(10)
        
        fig = px.bar(conversations,
                     x='Flow', y='Packets',
                     title="Top IP Conversations",
                     color='Packets',
                     color_continuous_scale='Viridis')
        fig.update_layout(xaxis_tickangle=45)
        st.plotly_chart(fig, use_container_width=True)
    
    # Port Analysis
    st.subheader("🔌 Port Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        # Top source ports
        src_ports = pd.DataFrame(
            stats['ports']['src'].items(),
            columns=['Port', 'Count']
        ).sort_values('Count', ascending=False).head(10)
        
        fig = px.bar(src_ports,
                     x='Port', y='Count',
                     title="Top Source Ports",
                     color='Count',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Top destination ports
        dst_ports = pd.DataFrame(
            stats['ports']['dst'].items(),
            columns=['Port', 'Count']
        ).sort_values('Count', ascending=False).head(10)
        
        fig = px.bar(dst_ports,
                     x='Port', y='Count',
                     title="Top Destination Ports",
                     color='Count',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)
