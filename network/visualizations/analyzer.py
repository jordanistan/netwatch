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
            showlegend=True
        )
        return fig
    def create_protocol_activity(self, stats):
        """Create an interactive timeline of protocol activity"""
        # Initialize data structures
        protocol_counts = defaultdict(list)
        window_size = 5  # 5 second window
        # Convert timestamps to datetime and count protocols in windows
        timestamps = [datetime.fromtimestamp(ts) for ts in stats['timestamps']]
        start_time = min(timestamps)
        end_time = max(timestamps)
        # Create time windows
        time_windows = []
        current_time = start_time
        while current_time <= end_time:
            time_windows.append(current_time)
            current_time = datetime.fromtimestamp(current_time.timestamp() + window_size)
        # Initialize protocol counts for each window
        protocols = list(stats['protocols']['application'].keys())
        for protocol in protocols:
            for _ in time_windows:
                protocol_counts[protocol].append(0)
        # Count protocols in each window
        for ts in timestamps:
            window_index = int((ts - start_time).total_seconds() / window_size)
            if window_index < len(time_windows):
                for protocol in protocols:
                    if protocol in stats['protocols']['application']:
                        protocol_counts[protocol][window_index] += 1
        # Create stacked area chart
        fig = go.Figure()
        for protocol in protocols:
            fig.add_trace(go.Scatter(
                x=time_windows,
                y=protocol_counts[protocol],
                name=protocol,
                mode='none',
                fill='tonexty',
                stackgroup='one'
            ))
        fig.update_layout(
            title="Protocol Activity Over Time",
            xaxis_title="Time",
            yaxis_title="Packet Count",
            showlegend=True,
            hovermode='x unified'
        )
        return fig

    
    def create_network_flow_diagram(self, stats):
        """Create an interactive network flow diagram"""
        # Extract unique IPs and their connections
        nodes = set()
        edges = []
        connections = stats['ips']['conversations']
        
        if not connections:
            fig = go.Figure()
            fig.update_layout(
                title="No Network Flow Data Available",
                showlegend=False
            )
            return fig

        # Process connections
        for connection, weight in connections.items():
            src_ip, dst_ip = connection.split('-')
            nodes.add(src_ip)
            nodes.add(dst_ip)
            edges.append((src_ip, dst_ip, weight))
        
        # Calculate node adjacencies (number of connections for each node)
        node_adjacencies = {}
        for node in nodes:
            node_adjacencies[node] = sum(1 for src, dst, _ in edges if src == node or dst == node)

        # Create node positions using a circular layout
        pos = {}
        nodes = list(nodes)  # Convert set to list for consistent ordering
        n = len(nodes)
        for i, node in enumerate(nodes):
            angle = 2 * np.pi * i / n
            pos[node] = (np.cos(angle), np.sin(angle))
        
        # Create edge traces
        edge_x = []
        edge_y = []
        edge_text = []
        
        for src, dst, weight in edges:
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_text.append(f"{src} → {dst}: {weight} packets")
            
        # Create edges
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='#888'),
            hoverinfo='text',
            hovertext=edge_text,
            mode='lines')

        # Create nodes
        node_x = []
        node_y = []
        node_text = []
        node_sizes = []
        
        for node in nodes:
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            # Calculate total packets for this node
            total_packets = sum(weight for src, dst, weight in edges 
                              if src == node or dst == node)
            node_text.append(f"{node}\nConnections: {node_adjacencies[node]}\nTotal Packets: {total_packets}")
            node_sizes.append(np.sqrt(total_packets) * 10)  # Scale node size by sqrt of packet count
            
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="bottom center",
            marker=dict(
                showscale=True,
                colorscale='YlOrRd',
                size=node_sizes,
                color=[node_adjacencies[node] for node in nodes],  # Color by number of connections
                colorbar=dict(
                    thickness=15,
                    title='Connection Count',
                    xanchor='left',
                    titleside='right'
                )
            ))

        # Create the figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title="Network Flow Diagram",
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           width=800,
                           height=800
                       ))
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
        """Create an interactive connection matrix showing IP interactions"""
        # Get unique IPs and their connections
        connections = stats['ips']['conversations']
        if not connections:
            fig = go.Figure()
            fig.update_layout(
                title="No Connection Data Available",
                showlegend=False
            )
            return fig

        # Create matrix of connections
        ips = set()
        for connection in connections:
            src, dst = connection.split('-')
            ips.add(src)
            ips.add(dst)
        ips = sorted(list(ips))

        matrix = np.zeros((len(ips), len(ips)))
        for connection, weight in connections.items():
            src, dst = connection.split('-')
            i = ips.index(src)
            j = ips.index(dst)
            matrix[i][j] = weight

        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=matrix,
            x=ips,
            y=ips,
            colorscale='Viridis',
            showscale=True
        ))

        fig.update_layout(
            title="Connection Matrix",
            xaxis_title="Destination IP",
            yaxis_title="Source IP",
            width=800,
            height=800
        )
        return fig

    def create_media_quality(self, stats):
        """Create an interactive chart showing streaming media quality metrics"""
        if not stats.get('media', {}).get('streaming'):
            fig = go.Figure()
            fig.update_layout(
                title="No Streaming Data Available",
                showlegend=False
            )
            return fig

        # Extract streaming quality data
        quality_data = []
        for stream_id, metrics in stats['media']['streaming'].items():
            for event in metrics['quality_changes']:
                quality_data.append({
                    'Stream': stream_id,
                    'Time': datetime.fromtimestamp(event['timestamp']),
                    'Quality': event['quality'],
                    'Bitrate': event['bitrate']
                })

        if not quality_data:
            fig = go.Figure()
            fig.update_layout(
                title="No Quality Change Events Found",
                showlegend=False
            )
            return fig

        # Create figure with secondary y-axis
        fig = go.Figure()

        # Add traces for quality and bitrate
        for stream_id in set(d['Stream'] for d in quality_data):
            stream_data = [d for d in quality_data if d['Stream'] == stream_id]
            fig.add_trace(go.Scatter(
                x=[d['Time'] for d in stream_data],
                y=[d['Quality'] for d in stream_data],
                name=f"{stream_id} Quality",
                mode='lines+markers'
            ))
            fig.add_trace(go.Scatter(
                x=[d['Time'] for d in stream_data],
                y=[d['Bitrate'] for d in stream_data],
                name=f"{stream_id} Bitrate",
                mode='lines+markers',
                yaxis='y2'
            ))

        fig.update_layout(
            title="Streaming Media Quality",
            xaxis_title="Time",
            yaxis_title="Quality Level",
            yaxis2=dict(
                title="Bitrate (bps)",
                overlaying='y',
                side='right'
            ),
            showlegend=True
        )
        return fig

    def create_voip_quality(self, stats):
        """Create an interactive chart showing VoIP call quality metrics"""
        if not stats.get('media', {}).get('voip'):
            fig = go.Figure()
            fig.update_layout(
                title="No VoIP Data Available",
                showlegend=False
            )
            return fig

        # Extract VoIP call data
        call_data = []
        for call_id, metrics in stats['media']['voip'].items():
            for sample in metrics['quality_samples']:
                call_data.append({
                    'Call': call_id,
                    'Time': datetime.fromtimestamp(sample['timestamp']),
                    'MOS': sample['mos'],
                    'Jitter': sample['jitter'],
                    'Packet Loss': sample['packet_loss']
                })

        if not call_data:
            fig = go.Figure()
            fig.update_layout(
                title="No VoIP Quality Data Found",
                showlegend=False
            )
            return fig

        # Create subplots for different metrics
        fig = sp.make_subplots(rows=3, cols=1,
                              subplot_titles=("MOS Score", "Jitter", "Packet Loss"),
                              shared_xaxes=True)

        # Add traces for each call
        for call_id in set(d['Call'] for d in call_data):
            call_samples = [d for d in call_data if d['Call'] == call_id]
            fig.add_trace(
                go.Scatter(
                    x=[d['Time'] for d in call_samples],
                    y=[d['MOS'] for d in call_samples],
                    name=f"{call_id} MOS",
                    mode='lines+markers'
                ),
                row=1, col=1
            )
            fig.add_trace(
                go.Scatter(
                    x=[d['Time'] for d in call_samples],
                    y=[d['Jitter'] for d in call_samples],
                    name=f"{call_id} Jitter",
                    mode='lines+markers'
                ),
                row=2, col=1
            )
            fig.add_trace(
                go.Scatter(
                    x=[d['Time'] for d in call_samples],
                    y=[d['Packet Loss'] for d in call_samples],
                    name=f"{call_id} Loss",
                    mode='lines+markers'
                ),
                row=3, col=1
            )

        fig.update_layout(
            height=900,
            title_text="VoIP Call Quality Metrics",
            showlegend=True
        )
        return fig
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
