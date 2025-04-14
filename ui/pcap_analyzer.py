"""PCAP Analysis UI for NetWatch"""
import sys
from datetime import datetime
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import rdpcap

def setup_page():
    """Setup the main page configuration"""
    st.set_page_config(
        page_title="NetWatch PCAP Analysis",
        page_icon="📊",
        layout="wide"
    )
    
    # Add home button in sidebar
    with st.sidebar:
        if st.button("🏠 Back to NetWatch"):
            st.stop()
            import subprocess
            subprocess.Popen(['streamlit', 'run', 'netwatch.py'], cwd='/Users/jordan/projects/netwatch')
    
    st.title("📊 NetWatch PCAP Analysis")

def format_bytes(size):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def analyze_pcap(pcap_file):
    """Analyze PCAP file and return statistics"""
    packets = rdpcap(str(pcap_file))
    stats = {
        'total_packets': len(packets),
        'start_time': None,
        'end_time': None,
        'duration': 0,
        'protocols': {},
        'ports': {
            'src': {},
            'dst': {}
        },
        'ips': {
            'src': {},
            'dst': {},
            'conversations': {},
            'conversation_protocols': {},
            'data_usage': {}
        }
    }

    if packets:
        stats['start_time'] = datetime.fromtimestamp(float(packets[0].time))
        stats['end_time'] = datetime.fromtimestamp(float(packets[-1].time))
        stats['duration'] = (stats['end_time'] - stats['start_time']).total_seconds()

    for pkt in packets:
        # Protocol analysis
        proto = pkt.lastlayer().name
        stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1

        # IP analysis
        if 'IP' in pkt:
            src_ip = pkt['IP'].src
            dst_ip = pkt['IP'].dst
            
            # Count source and destination IPs
            stats['ips']['src'][src_ip] = stats['ips']['src'].get(src_ip, 0) + 1
            stats['ips']['dst'][dst_ip] = stats['ips']['dst'].get(dst_ip, 0) + 1
            
            # Track conversations
            conv_key = f"{src_ip} → {dst_ip}"
            stats['ips']['conversations'][conv_key] = stats['ips']['conversations'].get(conv_key, 0) + 1
            
            # Track protocols per conversation
            if conv_key not in stats['ips']['conversation_protocols']:
                stats['ips']['conversation_protocols'][conv_key] = {}
            stats['ips']['conversation_protocols'][conv_key][proto] = stats['ips']['conversation_protocols'][conv_key].get(proto, 0) + 1
            
            # Track data usage
            pkt_len = len(pkt)
            stats['ips']['data_usage'][src_ip] = stats['ips']['data_usage'].get(src_ip, 0) + pkt_len
            stats['ips']['data_usage'][dst_ip] = stats['ips']['data_usage'].get(dst_ip, 0) + pkt_len

        # Port analysis
        if 'TCP' in pkt or 'UDP' in pkt:
            layer = pkt['TCP'] if 'TCP' in pkt else pkt['UDP']
            stats['ports']['src'][layer.sport] = stats['ports']['src'].get(layer.sport, 0) + 1
            stats['ports']['dst'][layer.dport] = stats['ports']['dst'].get(layer.dport, 0) + 1

    return stats

def show_pcap_analysis(stats):
    """Display PCAP analysis results"""
    st.header("📊 Traffic Analysis")
    
    # Basic stats
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", f"{stats['total_packets']:,}")
    with col2:
        duration = f"{stats['duration']:.1f}s"
        st.metric("Duration", duration)
    with col3:
        pps = stats['total_packets'] / stats['duration'] if stats['duration'] > 0 else 0
        st.metric("Packets/Second", f"{pps:.1f}")
    with col4:
        total_data = sum(stats['ips']['data_usage'].values())
        st.metric("Total Data", format_bytes(total_data))

    # Protocol Distribution
    st.subheader("🔍 Protocol Distribution")
    proto_df = pd.DataFrame(
        [(proto, count) for proto, count in stats['protocols'].items()],
        columns=['Protocol', 'Count']
    ).sort_values('Count', ascending=False)

    fig = px.pie(proto_df,
                 values='Count',
                 names='Protocol',
                 title="Protocol Distribution")
    st.plotly_chart(fig)

    # IP Analysis
    st.subheader("🌐 IP Analysis")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Top Source IPs**")
        src_ips = pd.DataFrame(
            stats['ips']['src'].items(),
            columns=['IP', 'Packets']
        ).sort_values('Packets', ascending=False).head(10)
        
        fig = px.bar(src_ips,
                     x='IP', y='Packets',
                     title="Top Source IPs",
                     color='Packets',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("**Top Destination IPs**")
        dst_ips = pd.DataFrame(
            stats['ips']['dst'].items(),
            columns=['IP', 'Packets']
        ).sort_values('Packets', ascending=False).head(10)
        
        fig = px.bar(dst_ips,
                     x='IP', y='Packets',
                     title="Top Destination IPs",
                     color='Packets',
                     color_continuous_scale='Viridis')
        st.plotly_chart(fig, use_container_width=True)

    # Data Usage Analysis
    st.subheader("📈 Data Usage")
    usage_data = []
    for ip, bytes_used in stats['ips']['data_usage'].items():
        usage_data.append([ip, bytes_used])
    
    usage_df = pd.DataFrame(usage_data, columns=['IP', 'Bytes'])
    usage_df['Data'] = usage_df['Bytes'].apply(format_bytes)
    usage_df = usage_df.sort_values('Bytes', ascending=False)

    fig = px.bar(usage_df.head(10),
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

def main():
    setup_page()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--pcap':
        pcap_file = sys.argv[2]
        if Path(pcap_file).exists():
            st.success(f"📊 Analyzing PCAP file: {pcap_file}")
            stats = analyze_pcap(pcap_file)
            show_pcap_analysis(stats)
        else:
            st.error(f"❌ PCAP file not found: {pcap_file}")
    else:
        st.error("❌ Please provide a PCAP file using --pcap argument")

if __name__ == "__main__":
    main()
