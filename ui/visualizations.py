"""Visualization components for NetWatch"""
import streamlit as st
import pandas as pd
import numpy as np
from visualizations.analyzer import TrafficVisualizer


def display_traffic_visualizations(stats):
    """Display interactive traffic visualizations"""
    # Initialize visualizer
    viz = TrafficVisualizer()
    
    # Add visualization tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Traffic Overview", "Network Analysis", "Performance", "Security"])
    
    with tab1:
        st.subheader("Protocol Distribution")
        st.plotly_chart(viz.create_protocol_distribution(stats))
        
        st.subheader("Bandwidth Usage")
        st.plotly_chart(viz.create_bandwidth_timeline(stats))
        
        st.subheader("Protocol Timeline")
        st.plotly_chart(viz.create_protocol_timeline(stats))
        
    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Network Flow Diagram")
            st.plotly_chart(viz.create_network_flow_diagram(stats))
        
        with col2:
            st.subheader("Connection Matrix")
            st.plotly_chart(viz.create_connection_matrix(stats))
            
        # Media streaming analysis
        if any(stats['media']['streaming'].values()):
            st.subheader("Streaming Media Quality")
            st.plotly_chart(viz.create_media_quality_chart(stats))
            
        # VoIP analysis
        if any(stats['media']['voip'].values()):
            st.subheader("VoIP Call Quality")
            st.plotly_chart(viz.create_voip_quality_chart(stats))
            
    with tab3:
        st.subheader("Performance Analysis")
        st.plotly_chart(viz.create_performance_dashboard(stats))
        
        # Display TCP metrics table
        if stats['performance']['tcp_metrics']:
            st.subheader("TCP Connection Metrics")
            tcp_metrics = []
            for conn, metrics in stats['performance']['tcp_metrics'].items():
                tcp_metrics.append({
                    'Connection': conn,
                    'Avg RTT (ms)': f"{np.mean(metrics['rtt']):.2f}",
                    'Retransmissions': metrics['retransmissions'],
                    'Zero Windows': metrics['zero_windows'],
                    'Avg Window Size': f"{np.mean(metrics['window_sizes']):.0f}"
                })
            st.dataframe(pd.DataFrame(tcp_metrics))
            
    with tab4:
        st.subheader("Security Analysis")
        st.plotly_chart(viz.create_security_dashboard(stats))
        
        # Display security alerts
        if any([stats['security']['port_scans'], 
                stats['security']['plain_auth'], 
                stats['security']['ssl_issues']]):
            st.subheader("Security Alerts")
            for ip, scans in stats['security']['port_scans'].items():
                st.warning(f"Potential port scan from {ip}: {len(scans)} ports")
            
            for ip in stats['security']['plain_auth']:
                st.error(f"Plain text authentication detected from {ip}")
                
            for ip, issues in stats['security']['ssl_issues'].items():
                st.warning(f"SSL/TLS issues detected for {ip}: {len(issues)} issues")
