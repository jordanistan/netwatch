"""Network traffic visualization module for NetWatch"""
import plotly.graph_objects as go
import plotly.express as px
import plotly.subplots as sp
import numpy as np
from collections import defaultdict
from datetime import datetime

class TrafficVisualizer:
    def __init__(self):
        self.color_palette = px.colors.qualitative.Set3
        
    def create_protocol_distribution(self, stats):
        """Create an interactive pie chart of protocol distribution"""
        protocols = stats['protocols']['application']
        fig = go.Figure(data=[go.Pie(
            labels=list(protocols.keys()),
            values=list(protocols.values()),
            hole=.3,
            marker=dict(colors=self.color_palette)
        )])
        fig.update_layout(
            title="Protocol Distribution",
            showlegend=True,
            annotations=[dict(text='Protocols', x=0.5, y=0.5, font_size=20, showarrow=False)]
        )
        return fig
    
    def create_bandwidth_timeline(self, stats):
        """Create an interactive timeline of bandwidth usage"""
        # Convert timestamps to datetime
        timestamps = [datetime.fromtimestamp(ts) for ts in stats['timestamps']]
        bandwidth = []
        window_size = 1  # 1 second window
        
        # Calculate bandwidth in Mbps for each window
        for i in range(0, len(timestamps), window_size):
            window_bytes = sum(stats['packet_sizes'][i:i+window_size])
            bandwidth.append((window_bytes * 8) / (1024 * 1024))  # Convert to Mbps
            
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps[::window_size],
            y=bandwidth,
            mode='lines',
            name='Bandwidth',
            line=dict(color='blue', width=2)
        ))
        fig.update_layout(
            title="Bandwidth Usage Over Time",
            xaxis_title="Time",
            yaxis_title="Bandwidth (Mbps)",
            hovermode='x unified'
        )
        return fig
    
    def create_network_flow_diagram(self, stats):
        """Create an interactive network flow diagram"""
        # Extract unique IPs and their connections
        nodes = set()
        edges = []
        for src_ip, dst_ips in stats['ips']['conversations'].items():
            nodes.add(src_ip)
            for dst_ip, count in dst_ips.items():
                nodes.add(dst_ip)
                edges.append((src_ip, dst_ip, count))
        
        # Create node positions using a circular layout
        pos = {}
        n = len(nodes)
        for i, node in enumerate(nodes):
            angle = 2 * np.pi * i / n
            pos[node] = (np.cos(angle), np.sin(angle))
        
        # Create the network diagram
        edge_x = []
        edge_y = []
        edge_weights = []
        
        for src, dst, weight in edges:
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_weights.append(weight)
            
        # Create edges
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='#888'),
            hoverinfo='none',
            mode='lines')

        # Create nodes
        node_x = []
        node_y = []
        for node in nodes:
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=list(nodes),
            textposition="top center",
            marker=dict(
                showscale=True,
                colorscale='YlGnBu',
                size=20,
                colorbar=dict(
                    thickness=15,
                    title='Node Connections',
                    xanchor='left',
                    titleside='right'
                )
            ))

        # Count connections for each node
        node_adjacencies = []
        for node in nodes:
            connected = sum(1 for _, dst, _ in edges if dst == node)
            node_adjacencies.append(connected)
            
        node_trace.marker.color = node_adjacencies

        # Create the figure
        fig = go.Figure(data=[edge_trace, node_trace],
                     layout=go.Layout(
                        title='Network Flow Diagram',
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                        )
        return fig
    
    def create_protocol_timeline(self, stats):
        """Create a timeline of protocol activity"""
        # Prepare data
        protocol_times = defaultdict(list)
        protocol_counts = defaultdict(list)
        window_size = 10  # 10 second windows
        
        timestamps = stats['timestamps']
        min_time = min(timestamps)
        max_time = max(timestamps)
        windows = np.arange(min_time, max_time, window_size)
        
        for proto in stats['protocols']['application']:
            for window_start in windows:
                window_count = sum(1 for ts in timestamps 
                                 if window_start <= ts < window_start + window_size)
                protocol_times[proto].append(datetime.fromtimestamp(window_start))
                protocol_counts[proto].append(window_count)
        
        # Create figure
        fig = go.Figure()
        for proto in protocol_times:
            fig.add_trace(go.Scatter(
                x=protocol_times[proto],
                y=protocol_counts[proto],
                name=proto,
                mode='lines',
                stackgroup='one'
            ))
            
        fig.update_layout(
            title="Protocol Activity Timeline",
            xaxis_title="Time",
            yaxis_title="Packet Count",
            hovermode='x unified'
        )
        return fig
    
    def create_connection_matrix(self, stats):
        """Create an interactive connection matrix"""
        # Get unique IPs
        ips = set()
        for src_ip, dst_ips in stats['ips']['conversations'].items():
            ips.add(src_ip)
            ips.update(dst_ips.keys())
        ips = sorted(list(ips))
        
        # Create matrix
        matrix = np.zeros((len(ips), len(ips)))
        for i, src_ip in enumerate(ips):
            if src_ip in stats['ips']['conversations']:
                for j, dst_ip in enumerate(ips):
                    if dst_ip in stats['ips']['conversations'][src_ip]:
                        matrix[i][j] = stats['ips']['conversations'][src_ip][dst_ip]
        
        fig = go.Figure(data=go.Heatmap(
            z=matrix,
            x=ips,
            y=ips,
            colorscale='Viridis',
            showscale=True
        ))
        
        fig.update_layout(
            title='Connection Matrix',
            xaxis_title="Destination IP",
            yaxis_title="Source IP",
            xaxis={'tickangle': 45}
        )
        return fig
    
    def create_media_quality_chart(self, stats):
        """Create a chart showing streaming media quality changes"""
        quality_changes = []
        timestamps = []
        
        for _, streaming_data in stats['media']['streaming'].items():
            for change in streaming_data['quality_changes']:
                quality_changes.append(change['resolution'])
                timestamps.append(datetime.fromtimestamp(change['timestamp']))
            
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=quality_changes,
            mode='lines+markers',
            name='Resolution Changes'
        ))
        
        fig.update_layout(
            title="Streaming Media Quality Changes",
            xaxis_title="Time",
            yaxis_title="Resolution",
            hovermode='x unified'
        )
        return fig
    
    def create_voip_quality_chart(self, stats):
        """Create a chart showing VoIP call quality metrics"""
        call_metrics = defaultdict(list)
        timestamps = []
        
        for _, voip_data in stats['media']['voip'].items():
            for stream in voip_data:
                if 'rtp_timestamp' in stream:
                    timestamps.append(datetime.fromtimestamp(stream['timestamp']))
                    # Calculate jitter and packet loss here
                    call_metrics['packet_size'].append(len(stream.get('payload', b'')))
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=call_metrics['packet_size'],
            mode='lines',
            name='Packet Size'
        ))
        
        fig.update_layout(
            title="VoIP Call Quality Metrics",
            xaxis_title="Time",
            yaxis_title="Packet Size (bytes)",
            hovermode='x unified'
        )
        return fig
    
    def create_security_dashboard(self, stats):
        """Create a security-focused dashboard"""
        # Create subplots
        fig = sp.make_subplots(
            rows=2, cols=2,
            subplot_titles=("Port Scan Attempts", "Plain Text Auth", 
                          "SSL/TLS Issues", "TCP Flags Distribution")
        )
        
        # Port scan attempts
        port_scan_data = defaultdict(int)
        for ip, scans in stats['security']['port_scans'].items():
            port_scan_data[ip] = len(scans)
            
        fig.add_trace(
            go.Bar(x=list(port_scan_data.keys()), 
                  y=list(port_scan_data.values()),
                  name="Port Scans"),
            row=1, col=1
        )
        
        # Plain text authentication
        auth_data = defaultdict(int)
        for ip, auths in stats['security']['plain_auth'].items():
            auth_data[ip] = len(auths)
            
        fig.add_trace(
            go.Bar(x=list(auth_data.keys()), 
                  y=list(auth_data.values()),
                  name="Plain Auth"),
            row=1, col=2
        )
        
        # SSL/TLS issues
        ssl_data = defaultdict(int)
        for ip, issues in stats['security']['ssl_issues'].items():
            ssl_data[ip] = len(issues)
            
        fig.add_trace(
            go.Bar(x=list(ssl_data.keys()), 
                  y=list(ssl_data.values()),
                  name="SSL Issues"),
            row=2, col=1
        )
        
        # TCP flags distribution
        fig.add_trace(
            go.Pie(labels=list(stats['tcp_flags'].keys()),
                  values=list(stats['tcp_flags'].values()),
                  name="TCP Flags"),
            row=2, col=2
        )
        
        fig.update_layout(height=800, title_text="Security Analysis Dashboard")
        return fig

    def create_performance_dashboard(self, stats):
        """Create a performance-focused dashboard"""
        # Create subplots
        fig = sp.make_subplots(
            rows=2, cols=2,
            subplot_titles=("RTT Distribution", "Window Sizes", 
                          "Retransmissions", "Zero Windows")
        )
        
        # RTT distribution
        rtt_data = []
        for _, metrics in stats['performance']['tcp_metrics'].items():
            rtt_data.extend(metrics['rtt'])
        fig.add_trace(
            go.Histogram(x=rtt_data, name="RTT"),
            row=1, col=1
        )
        
        # Window sizes
        window_data = []
        for _, metrics in stats['performance']['tcp_metrics'].items():
            window_data.extend(metrics['window_sizes'])
        fig.add_trace(
            go.Box(y=window_data, name="Window Sizes"),
            row=1, col=2
        )
        
        # Retransmissions per connection
        retrans_data = {conn: metrics['retransmissions'] 
                       for conn, metrics in stats['performance']['tcp_metrics'].items()}
            
        fig.add_trace(
            go.Bar(x=list(retrans_data.keys()),
                  y=list(retrans_data.values()),
                  name="Retransmissions"),
            row=2, col=1
        )
        
        # Zero windows per connection
        zero_window_data = {conn: metrics['zero_windows'] 
                           for conn, metrics in stats['performance']['tcp_metrics'].items()}
            
        fig.add_trace(
            go.Bar(x=list(zero_window_data.keys()),
                  y=list(zero_window_data.values()),
                  name="Zero Windows"),
            row=2, col=2
        )
        
        fig.update_layout(height=800, title_text="Performance Analysis Dashboard")
        return fig
