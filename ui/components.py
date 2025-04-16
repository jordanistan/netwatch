"""UI components for NetWatch"""
import streamlit as st
import pandas as pd
import plotly.express as px
import netifaces

def setup_page():
    """Setup the main page configuration"""
    st.title("📶 NetWatch")

def show_network_info(interface, ip):
    """Display network information in the sidebar
    Args:
        interface: Network interface name
        ip: IP address of the interface
    """
    st.sidebar.title("Network Info")

    if interface and ip:
        st.sidebar.success(f"Network Interface: {interface}")
        st.sidebar.info(f"IP Address: {ip}")

        # Network interfaces in an expander
        with st.sidebar.expander("All Network Interfaces", expanded=False):
            for iface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    addr = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
                    st.write(f"{iface}: {addr}")

def show_scan_results(devices, netwatch_instance):
    """Display network scan results
    Args:
        devices: List of network devices
        netwatch_instance: NetWatch instance
    """
    if devices:
        # Show tracked devices first
        st.subheader("Tracked Devices")
        tracked_devices = netwatch_instance.scanner.get_tracked_devices()
        if tracked_devices:
            device_count = len(tracked_devices)
            st.success(f"Found {device_count} tracked devices")
            with st.expander("📌 Tracked Devices", expanded=False):
                for device in tracked_devices:
                    try:
                        st.markdown(f"**{device.hostname or 'Unknown Device'} ({device.ip_address})**")
                        st.text(f"MAC: {device.mac_address}")
                        st.text(f"First Seen: {device.first_seen.strftime('%Y-%m-%d %H:%M')}")
                        st.text(f"Last Seen: {device.last_seen.strftime('%Y-%m-%d %H:%M')}")
                        st.text(f"Status: {device.activity}")
                        st.divider()
                    except AttributeError:
                        st.error("Error displaying device info. Please refresh the device list.")
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
                    netwatch_instance.scanner.untrack_device(row['MAC Address'])
                    st.rerun()
        else:
            st.info("No tracked devices yet")
        # Show other devices
        st.subheader("Other Network Devices")
        new_devices = netwatch_instance.scanner.get_new_devices(limit=50, include_tracked=True)
        untracked_devices = [d for d in new_devices if not d.tracked]
        if untracked_devices:
            device_count = len(untracked_devices)
            st.info(f"Found {device_count} untracked devices")
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
                is_tracked = netwatch_instance.scanner.is_device_tracked(device_mac)
                if row['Track'] != is_tracked:  # Only update if tracking status changed
                    if row['Track']:
                        netwatch_instance.scanner.track_device(device_mac)
                    else:
                        netwatch_instance.scanner.untrack_device(device_mac)
                    # Use session state to trigger rerun only once after all changes
                    if 'tracking_changed' not in st.session_state:
                        st.session_state.tracking_changed = True
                        st.rerun()
        else:
            st.info("No new devices found")
    else:
        st.warning(" No devices found. Please refresh the device list.")

def show_traffic_capture_ui(netwatch_instance, devices):
    """Display traffic capture UI
    Args:
        netwatch_instance: NetWatch instance
        devices: List of network devices
    """
    # Show scanning status
    if not devices:
        st.warning("No devices found. Use the 'Refresh Device List' button to scan for devices.")
        return

    # Quick actions at the top
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Quick Actions")
        capture_all = st.button("Capture All Traffic", type="primary", use_container_width=True)
    with col2:
        st.subheader("Duration")
        duration_option = st.selectbox(
            "Select Duration",
            ["1 minute", "10 minutes", "30 minutes", "Custom"],
            index=0
        )

    if duration_option == "Custom":
        duration = st.number_input(
            "Enter duration in minutes",
            min_value=1,
            max_value=60,
            value=5
        )
    else:
        duration = int(duration_option.split()[0])

    # Show tracked devices
    st.subheader("Tracked Devices")
    tracked_devices = netwatch_instance.scanner.get_tracked_devices()
    if tracked_devices:
        device_count = len(tracked_devices)
        st.info(f"Currently tracking {device_count} devices")
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
        edited_tracked_df = st.data_editor(
            tracked_df,
            column_config={
                'Actions': st.column_config.CheckboxColumn(
                    'Untrack',
                    help="Select to untrack device"
                )
            },
            hide_index=True,
            use_container_width=True
        )
        # Handle untracking devices
        for _, row in edited_tracked_df.iterrows():
            if row['Actions']:
                netwatch_instance.scanner.untrack_device(row['MAC Address'])
                st.rerun()
    else:
        st.info("No tracked devices yet")

    # Show other devices
    st.subheader("Other Network Devices")
    new_devices = netwatch_instance.scanner.get_new_devices(limit=50, include_tracked=True)
    untracked_devices = [d for d in new_devices if not d.tracked]
    if untracked_devices:
        device_count = len(untracked_devices)
        st.info(f"Found {device_count} untracked devices")
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

        edited_df = st.data_editor(
            new_df,
            column_config={
                'Track': st.column_config.CheckboxColumn(
                    'Track',
                    help="Select to track device"
                )
            },
            hide_index=True,
            use_container_width=True
        )

        # Handle tracking changes
        for _, row in edited_df.iterrows():
            if row['Track']:
                netwatch_instance.scanner.track_device(row['MAC Address'])
                st.rerun()
    else:
        st.info("No new devices found")

    # Capture controls
    st.subheader("Capture Controls")

    # Handle button state
    can_capture = True  # Default to True unless conditions prevent capture
    is_capturing = False  # Default to False unless capture is in progress
    button_label = "Cannot Start Capture"
    button_type = "secondary"

    if can_capture and not is_capturing:
        button_label = "Start Capture"
        button_type = "primary"
    elif is_capturing:
        button_label = "Capture in Progress..."
        button_type = "secondary"

    # Start capture button
    if st.button(button_label, type=button_type, use_container_width=True):
        try:
            if capture_all:
                st.info("Starting capture for all traffic...")
                netwatch_instance.capture.start_capture(
                    duration=duration * 60  # Convert to seconds
                )
            else:
                tracked_devices = [d for d in devices if d.tracked]
                if not tracked_devices:
                    st.error("Please select at least one device to track")
                    return

                device_count = len(tracked_devices)
                st.info(f"Starting capture for {device_count} devices...")
                netwatch_instance.capture.start_capture(
                    duration=duration * 60,  # Convert to seconds
                    devices=tracked_devices
                )

            st.success("Capture started successfully!")
        except Exception as e:
            st.error(f"Failed to start capture: {str(e)}")

    # Add refresh button
    if st.button("Refresh Device List"):
        st.rerun()

def show_untracked_devices(netwatch_instance, devices):
    """Display untracked devices UI
    Args:
        netwatch_instance: NetWatch instance
        devices: List of network devices
    """
    # Show scanning status
    if not devices:
        st.warning("No devices found. Please refresh the device list.")
        return

    # Show untracked devices
    new_devices = netwatch_instance.scanner.get_new_devices(limit=10, include_tracked=False)
    if new_devices:
        device_count = len(new_devices)
        st.info(f"Found {device_count} new untracked devices")
        # Create a DataFrame for untracked devices
        new_df = pd.DataFrame([
            {
                'IP Address': device.ip_address,
                'MAC Address': device.mac_address,
                'Device Name': device.hostname or 'Unknown',
                'Activity': device.activity,
                'First Seen': device.first_seen.strftime('%Y-%m-%d %H:%M:%S') if device.first_seen else 'N/A',
                'Last Seen': device.last_seen.strftime('%Y-%m-%d %H:%M:%S') if device.last_seen else 'N/A',
                'Track': False
            }
            for device in new_devices
        ])

        edited_df = st.data_editor(
            new_df,
            column_config={
                'Track': st.column_config.CheckboxColumn(
                    'Track',
                    help="Select to track device"
                )
            },
            hide_index=True,
            use_container_width=True
        )

        # Handle tracking changes
        for _, row in edited_df.iterrows():
            if row['Track']:
                netwatch_instance.scanner.track_device(row['MAC Address'])
                st.rerun()
    else:
        st.warning("No devices found. Please refresh the device list.")

def format_bytes(size):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

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

def show_pcap_analysis_ui(stats, scanner=None):
    """Display PCAP analysis results with interactive visualizations
    Args:
        stats: Dictionary containing PCAP analysis statistics
        scanner: Optional NetworkScanner instance for device info lookup
    """
    # Create tabs for different analysis views
    analysis_tabs = st.tabs(["Overview", "Conversations", "Protocols"])

    # Overview tab
    with analysis_tabs[0]:
        # Basic statistics
        st.subheader("Basic Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Packets", f"{stats['total_packets']:,}")
            st.metric("Total Bytes", format_bytes(stats['total_bytes']))
        with col2:
            st.metric("Duration", get_duration_label(stats['duration']))
            st.metric("Average Packet Size", format_bytes(stats['avg_packet_size']))

        # Traffic over time
        if stats['traffic_over_time']:
            st.subheader("Traffic Over Time")
            time_df = pd.DataFrame([
                {'Time': time, 'Packets': count}
                for time, count in stats['traffic_over_time'].items()
            ])
            fig = px.line(time_df, x='Time', y='Packets',
                         title='Packet Count Over Time')
            st.plotly_chart(fig, use_container_width=True)

    # Conversations tab
    with analysis_tabs[1]:
        st.subheader("Top Conversations")
        conversations = stats['ips']['conversations']
        if conversations:
            # Sort conversations by packet count
            sorted_convs = sorted(conversations.items(),
                                 key=lambda x: x[1], reverse=True)
            for conv, count in sorted_convs[:10]:
                src, dst = conv.split(' → ')
                src_info = get_device_info(src, scanner) if scanner else None
                dst_info = get_device_info(dst, scanner) if scanner else None
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

    # Protocol tab
    with analysis_tabs[2]:
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
        st.markdown("### Port Analysis")
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

def show_pcap_analysis(stats, scanner=None):
    """Display PCAP analysis results with interactive visualizations
    Args:
        stats: Dictionary containing PCAP analysis statistics
        scanner: Optional NetworkScanner instance for device info lookup
    """
    # Create tabs for different analysis views
    traffic_tab, web_tab, dns_tab, voip_tab, protocol_tab = st.tabs([
        "Traffic Overview", "Web Analysis", "DNS Analysis", "VoIP Analysis", "Protocol Analysis"
    ])

    with traffic_tab:
        st.subheader("Traffic Overview")
        # Basic statistics
        st.subheader("Basic Statistics")
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
                src_info = get_device_info(src, scanner) if scanner else None
                dst_info = get_device_info(dst, scanner) if scanner else None
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

def show_web_analysis(stats):
    """Display web traffic analysis
    Args:
        stats: Dictionary containing web traffic statistics
    """
    # Create tabs for different views
    web_tab, dns_tab, voip_tab = st.tabs(["Web Traffic", "DNS Analysis", "VoIP Analysis"])

    with web_tab:
        if stats['web'].get('urls'):
            st.subheader("Top URLs")
            urls_df = pd.DataFrame([
                {'URL': url, 'Hits': count}
                for url, count in stats['web']['urls'].items()
            ]).sort_values('Hits', ascending=False).head(10)

            st.dataframe(urls_df, hide_index=True, use_container_width=True)

            # Show domain stats
            st.subheader("Top Domains")
            domains_df = pd.DataFrame([
                {'Domain': domain, 'Hits': count}
                for domain, count in stats['web']['domains'].items()
            ]).sort_values('Hits', ascending=False).head(10)

            col1, col2 = st.columns(2)
            with col1:
                st.dataframe(domains_df, hide_index=True, use_container_width=True)
            with col2:
                fig = px.pie(domains_df, values='Hits', names='Domain',
                            title='Top Domains Distribution')
                st.plotly_chart(fig, use_container_width=True)

            # Show HTTP methods
            if stats['web'].get('methods'):
                st.subheader("HTTP Methods")
                methods_df = pd.DataFrame([
                    {'Method': method, 'Count': count}
                    for method, count in stats['web']['methods'].items()
                ]).sort_values('Count', ascending=False)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(methods_df, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.pie(methods_df, values='Count', names='Method',
                                title='HTTP Methods Distribution')
                    st.plotly_chart(fig, use_container_width=True)

            # Show response codes
            if stats['web'].get('status_codes'):
                st.subheader("HTTP Status Codes")
                codes_df = pd.DataFrame([
                    {'Status Code': code, 'Count': count}
                    for code, count in stats['web']['status_codes'].items()
                ]).sort_values('Count', ascending=False)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(codes_df, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.pie(codes_df, values='Count', names='Status Code',
                                title='Status Codes Distribution')
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No web traffic detected")

    with dns_tab:
        if stats.get('dns'):
            st.subheader("DNS Queries")
            # Show top queried domains
            queries_df = pd.DataFrame([
                {'Domain': domain, 'Count': count}
                for domain, count in stats['dns']['queries'].items()
            ]).sort_values('Count', ascending=False).head(10)

            col1, col2 = st.columns(2)
            with col1:
                st.dataframe(queries_df, hide_index=True, use_container_width=True)
            with col2:
                fig = px.pie(queries_df, values='Count', names='Domain',
                            title='Top DNS Queries')
                st.plotly_chart(fig, use_container_width=True)

            # Show query types
            if stats['dns'].get('types'):
                st.subheader("Query Types")
                types_df = pd.DataFrame([
                    {'Type': qtype, 'Count': count}
                    for qtype, count in stats['dns']['types'].items()
                ]).sort_values('Count', ascending=False)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(types_df, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.pie(types_df, values='Count', names='Type',
                                title='DNS Query Types')
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No DNS traffic detected")

    with voip_tab:
        if stats.get('voip'):
            st.subheader("VoIP Analysis")
            # Show SIP methods
            if stats['voip'].get('methods'):
                st.subheader("SIP Methods")
                voip_methods_df = pd.DataFrame([
                    {'Method': method, 'Count': count}
                    for method, count in stats['voip']['methods'].items()
                ]).sort_values('Count', ascending=False)

                col1, col2 = st.columns(2)
                with col1:
                    st.dataframe(voip_methods_df, hide_index=True, use_container_width=True)
                with col2:
                    fig = px.pie(voip_methods_df, values='Count', names='Method',
                                title='SIP Methods Distribution')
                    st.plotly_chart(fig, use_container_width=True)

            # Show call statistics
            if stats['voip'].get('calls'):
                st.subheader("Call Statistics")
                calls = stats['voip']['calls']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Calls", calls['total'])
                with col2:
                    st.metric("Active Calls", calls['active'])
                with col3:
                    st.metric("Failed Calls", calls['failed'])
        else:
            st.warning("VoIP analysis features are not available. Install scapy[voip] for full functionality.")
