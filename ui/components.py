"""UI components for NetWatch"""
import streamlit as st
import pandas as pd
import plotly.express as px
import netifaces
from pathlib import Path
from network.capture import TrafficCapture
import logging

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

def show_scan_results(devices, netwatch):
    """Display network scan results
    Args:
        devices: List of network devices
        netwatch: NetWatch instance
    """
    try:
        if devices:
            # Show tracked devices first
            st.subheader("Tracked Devices")
            tracked_devices = netwatch.scanner.get_tracked_devices()
            if tracked_devices:
                device_count = len(tracked_devices)
                st.success(f"Found {device_count} tracked devices")
                with st.expander("📌 Tracked Devices", expanded=False):
                    for device in tracked_devices:
                        try:
                            st.markdown(f"**{device.hostname or 'Unknown Device'} ({device.ip_address})**")
                            st.text(f"MAC: {device.mac_address}")
                            st.text(f"First Seen: {device.first_seen.strftime('%Y-%m-%d %H:%M') if device.first_seen else 'N/A'}")
                            st.text(f"Last Seen: {device.last_seen.strftime('%Y-%m-%d %H:%M') if device.last_seen else 'N/A'}")
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
                for row in edited_tracked_df.itertuples():
                    try:
                        mac_address = row.mac
                        netwatch.scanner.untrack_device(mac_address)
                    except Exception as e:
                        st.error(f"Error untracking device: {str(e)}")
            else:
                st.info("No tracked devices yet")
            # Show other devices
            st.subheader("Other Network Devices")
            new_devices = netwatch.scanner.get_new_devices(limit=50, include_tracked=True)
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
                    is_tracked = netwatch.scanner.is_device_tracked(device_mac)
                    if row['Track'] != is_tracked:  # Only update if tracking status changed
                        if row['Track']:
                            netwatch.scanner.track_device(device_mac)
                            st.success(f"Now tracking {row['Device Name']}")
                            st.rerun()
                        else:
                            netwatch.scanner.untrack_device(device_mac)
                            st.success(f"Stopped tracking {row['Device Name']}")
                            st.rerun()
                    if 'tracking_changed' not in st.session_state:
                        st.session_state.tracking_changed = True
                        st.rerun()
            else:
                st.info("No new devices found")
        else:
            st.warning("No devices found. Please refresh the device list.")
            # Consider showing previously tracked devices if available
            tracked_devices = netwatch.scanner.get_tracked_devices()
            if tracked_devices:
                st.subheader("Previously Tracked Devices")
                # (Simplified display for brevity, reuse tracked display logic if needed)
                tracked_df = pd.DataFrame([{
                    'IP Address': d.ip_address,
                    'MAC Address': d.mac_address,
                    'Device Name': d.hostname or 'Unknown',
                    'Last Seen': d.last_seen.strftime('%Y-%m-%d %H:%M') if d.last_seen else 'N/A',
                    'Status': d.activity
                    } for d in tracked_devices])
                st.dataframe(tracked_df, hide_index=True, use_container_width=True)
    except Exception as e:
        st.error(f"An error occurred displaying scan results: {e}")
        logging.exception("Error in show_scan_results")
    finally:
        pass

def show_traffic_capture_page(netwatch, devices):
    """Display the Traffic Capture page with device selection and capture controls"""
    st.header("Traffic Capture 🚀")
    if 'network_devices' not in st.session_state:
        st.session_state['network_devices'] = []
    capture_col1, capture_col2 = st.columns([2, 1])
    with capture_col1:
        capture_mode = st.radio(
            "Capture Mode",
            ["All Traffic", "Select Devices"],
            horizontal=True
        )
        selected_devices = []
        if capture_mode == "Select Devices":
            if st.session_state['network_devices']:
                device_options = [f"{dev.hostname or 'Unknown'} ({dev.ip_address})"
                                for dev in st.session_state['network_devices']]
                selected_devices = st.multiselect(
                    "Select Devices for Traffic Capture",
                    options=device_options
                )
                # Map selected labels back to IP addresses
                selected_ips = []
                for label in selected_devices:
                    for dev in st.session_state['network_devices']:
                        if label == f"{dev.hostname or 'Unknown'} ({dev.ip_address})":
                            selected_ips.append(dev.ip_address)
                selected_devices = selected_ips
            else:
                st.warning("No devices found. Please run a network scan first.")
    with capture_col2:
        duration_options = {
            "Quick (1 min)": 60,
            "Standard (10 min)": 600,
            "Detailed (30 min)": 1800,
            "Custom": -1
        }
        duration_selection = st.selectbox(
            "Capture Duration",
            options=list(duration_options.keys())
        )
        capture_duration = st.number_input(
            "Enter duration in seconds" if duration_selection == "Custom" else "Duration",
            min_value=10,
            max_value=3600,
            value=300 if duration_selection == "Custom" else duration_options[duration_selection],
            step=10,
            disabled=duration_selection != "Custom"
        )
    if st.button("🚨 Capture Traffic", type='primary', use_container_width=True):
        try:
            target_ips = None
            if capture_mode == "Select Devices" and selected_devices:
                target_ips = selected_devices  # Already a list of selected IPs
            captures_dir = Path("captures")
            capture = TrafficCapture(captures_dir)
            progress_text = "Capturing network traffic..."
            progress_bar = st.progress(0, text=progress_text)

            def update_progress(percent):
                progress_bar.progress(percent, text=f"{progress_text} ({percent:.0f}%)")

            pcap_file = capture.capture_traffic(
                target_ips=target_ips,
                duration=capture_duration * 60,
                progress_callback=update_progress
            )
            if pcap_file:
                st.success(f"✅ Traffic capture completed! Saved to: {pcap_file}")
                if 'captured_files' not in st.session_state:
                    st.session_state['captured_files'] = []
                st.session_state['captured_files'].append(str(pcap_file))
            else:
                st.error("❌ Failed to capture traffic. Please check the logs.")
        except Exception as e:
            st.error(f"❌ Error during capture: {str(e)}")
        finally:
            progress_bar.empty()

def show_pcap_analysis_ui(netwatch, stats):
    """Display PCAP analysis results with interactive visualizations
    Args:
        netwatch: NetWatch instance
        stats: Dictionary containing PCAP analysis statistics
    """
    if not stats:
        st.warning("No PCAP analysis data available")
        return

    # Create tabs for different analysis views
    overview_tab, conversations_tab, protocols_tab, web_tab, dns_tab, voip_tab = st.tabs([
        "Overview", "Conversations", "Protocols", "Web", "DNS", "VoIP"
    ])

    with overview_tab:
        st.subheader("Basic Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Packets", f"{stats.get('total_packets', 0):,}")
            st.metric("Total Bytes", format_bytes(stats.get('total_bytes', 0)))
        with col2:
            st.metric("Duration", get_duration_label(stats.get('duration', 0)))
            st.metric("Average Packet Size", format_bytes(stats.get('avg_packet_size', 0)))

        # Show traffic over time if available
        if stats.get('traffic_over_time'):
            st.subheader("Traffic Over Time")
            # Convert keys to datetime if they are strings
            traffic_data = {
                pd.to_datetime(k): v 
                for k, v in stats['traffic_over_time'].items()
            }
            time_df = pd.DataFrame(
                list(traffic_data.items()),
                columns=['Time', 'Packets']
            ).sort_values('Time')
            
            if not time_df.empty:
                fig = px.line(time_df, x='Time', y='Packets', title='Packet Count Over Time')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No traffic over time data to display.")
        else:
            st.info("No traffic over time data available.")

    with conversations_tab:
        if stats.get('conversations'):
            st.subheader("Network Conversations")
            conversations_df = pd.DataFrame([
                {'Conversation': conv, 'Packets': count}
                for conv, count in stats['conversations'].items()
            ]).sort_values('Packets', ascending=False)
            st.dataframe(conversations_df, hide_index=True, use_container_width=True)
        else:
            st.info("No conversation data available")

    with protocols_tab:
        # Protocol Analysis
        if stats.get('protocols'):
            st.subheader("Protocol Distribution")
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
        else:
             st.info("No protocol data available")

        # Port Analysis
        st.markdown("### Port Analysis")
        port_source_tab, port_dest_tab = st.tabs(["Source Ports", "Destination Ports"])

        with port_source_tab:
            if stats.get('ports', {}).get('src'):
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
            if stats.get('ports', {}).get('dst'):
                # Create DataFrame for destination ports
                dst_ports = pd.DataFrame([
                    {'Port': str(port), 'Count': count}
                    for port, count in stats['ports']['dst'].items()
                ]).sort_values('Count', ascending=False).head(10)
                st.dataframe(dst_ports, hide_index=True, use_container_width=True)
            else:
                st.info("No destination port data available")

    with web_tab:
        show_web_analysis(stats)

    with dns_tab:
        st.info("DNS analysis coming soon")

    with voip_tab:
        show_voip_analysis(stats)

def show_pcap_analysis(netwatch, stats):
    """DEPRECATED: Use show_pcap_analysis_ui instead.
    Display PCAP analysis results with interactive visualizations
    Args:
        netwatch: NetWatch instance
        stats: Dictionary containing PCAP analysis statistics
    """
    if not stats:
        st.warning("No PCAP analysis data available")
        return

    # Create tabs for different analysis views
    traffic_tab, web_tab, dns_tab, voip_tab, protocol_tab = st.tabs([
        "Traffic Overview", "Web Analysis", "DNS Analysis", "VoIP Analysis", "Protocol Analysis"
    ])

    # Track whether tabs are used to avoid unused variable warnings
    _ = traffic_tab
    _ = protocol_tab

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
        if stats.get('traffic_over_time'):
            st.subheader("Traffic Over Time")
            time_df = pd.DataFrame([
                {'Time': time, 'Packets': count}
                for time, count in stats['traffic_over_time'].items()
            ])
            fig = px.line(time_df, x='Time', y='Packets',
                         title='Packet Count Over Time')
            st.plotly_chart(fig, use_container_width=True)

        # Conversations section moved to traffic tab
        st.subheader("Top Conversations")
        conversations = stats['ips']['conversations']
        if conversations:
            # Sort conversations by packet count
            sorted_convs = sorted(conversations.items(),
                                 key=lambda x: x[1], reverse=True)
            for conv, count in sorted_convs[:10]:
                src, dst = conv.split(' → ')
                # Get device info from scanner if available
                src_info = netwatch.get_device_name(src) if netwatch else None
                dst_info = netwatch.get_device_name(dst) if netwatch else None
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
                    st.text(f"From {src}: {format_bytes(src_data)}")
                    st.text(f"From {dst}: {format_bytes(dst_data)}")
                    total_data = src_data + dst_data
                    st.text(f"Total: {format_bytes(total_data)}")

                    # Show ports if available
                    if conv in stats['ips']['ports']:
                        st.markdown("**Ports Used:**")
                        ports = stats['ips']['ports'][conv]
                        for port_pair, port_count in sorted(ports.items(),
                                                        key=lambda x: x[1],
                                                        reverse=True):
                            st.text(f"{port_pair}: {port_count:,} packets")

        else:
            st.info("No conversations recorded")

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
                st.dataframe(dst_ports, hide_index=True, use_container_width=True)

    with web_tab:
        show_web_analysis(stats)

    with dns_tab:
        st.info("DNS analysis coming soon")

    with voip_tab:
        show_voip_analysis(stats)

def show_web_analysis(stats):
    """Display web traffic analysis
    Args:
        stats: Dictionary containing web traffic statistics
    """
    if not stats.get('web'):
        st.info("No web traffic detected")
        return

    web_stats = stats['web']
    st.subheader("Web Traffic Analysis")

    # Show HTTP methods
    if web_stats.get('methods'):
        st.markdown("### HTTP Methods")
        methods_df = pd.DataFrame([
            {'Method': method, 'Count': count}
            for method, count in web_stats['methods'].items()
        ]).sort_values('Count', ascending=False)

        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(methods_df, hide_index=True, use_container_width=True)
        with col2:
            fig = px.pie(methods_df, values='Count', names='Method',
                        title='HTTP Methods Distribution')
            st.plotly_chart(fig, use_container_width=True)

    # Show top domains
    if web_stats.get('domains'):
        st.markdown("### Top Domains")
        domains_df = pd.DataFrame([
            {'Domain': domain, 'Count': count}
            for domain, count in web_stats['domains'].items()
        ]).sort_values('Count', ascending=False).head(10)

        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(domains_df, hide_index=True, use_container_width=True)
        with col2:
            fig = px.pie(domains_df, values='Count', names='Domain',
                        title='Top Web Domains')
            st.plotly_chart(fig, use_container_width=True)

    # Show response codes
    if web_stats.get('status_codes'):
        st.markdown("### Response Codes")
        codes_df = pd.DataFrame([
            {'Code': code, 'Count': count}
            for code, count in web_stats['status_codes'].items()
        ]).sort_values('Count', ascending=False)

        col1, col2 = st.columns(2)
        with col1:
            st.dataframe(codes_df, hide_index=True, use_container_width=True)
        with col2:
            fig = px.pie(codes_df, values='Count', names='Code',
                        title='HTTP Status Codes')
            st.plotly_chart(fig, use_container_width=True)

def show_voip_analysis(stats):
    """Display VoIP traffic analysis
    Args:
        stats: Dictionary containing VoIP traffic statistics
    """
    if not stats.get('voip'):
        st.warning("VoIP analysis features are not available. Install scapy[voip] for full functionality.")
        return

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

def format_bytes(size):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"

def get_duration_parts(seconds):
    """Convert seconds into days, hours, minutes, seconds"""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        # Ensure seconds are formatted correctly, especially if zero
        parts.append(f"{seconds:.0f}s" if seconds % 1 == 0 else f"{seconds:.2f}s")
    return ", ".join(parts) if parts else "0s"

def get_duration_label(value):
    """Format duration for display"""
    return get_duration_parts(value)

def show_alerts_page():
    """Display alerts from reports/alerts/alerts.json"""
    import json
    from pathlib import Path
    import streamlit as st
    alerts_file = Path('reports/alerts/alerts.json')
    st.header('Security Alerts')
    if alerts_file.exists():
        with alerts_file.open('r', encoding='utf-8') as f:
            alerts = json.load(f)
        if alerts:
            import pandas as pd
            df = pd.DataFrame(alerts)
            st.dataframe(df, hide_index=True, use_container_width=True)
        else:
            st.info('No alerts found.')
    else:
        st.info('No alerts have been generated yet.')
