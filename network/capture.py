"""Traffic capture functionality for NetWatch"""
import time
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap

# Import additional Scapy layers
from scapy.layers.inet import UDP, IP, TCP
from scapy.packet import Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

# Try to import TLS layer
try:
    from scapy.layers.tls import TLS
    HAS_TLS_LAYER = True
except ImportError:
    HAS_TLS_LAYER = False

# Try to import optional layers
try:
    # Import RTP layer
    from scapy.layers.rtp import RTP
    scapy.load_layer('rtp')
    # Import SIP layer from contrib
    from scapy.contrib.sip import SIP
    scapy.load_contrib('sip')
    # Import VOIP module
    from scapy.modules import voip
    voip.load_module()
    HAS_VOIP_LAYERS = True
    print("[Init] Successfully loaded VoIP analysis layers")
except ImportError as e:
    HAS_VOIP_LAYERS = False
    print(f"[Init] VoIP analysis features not available: {e}")

class TrafficCapture:
    def __init__(self, captures_dir):
        self.captures_dir = Path(captures_dir)
        # Ensure captures directory exists
        try:
            self.captures_dir.mkdir(parents=True, exist_ok=True)
            print(f"[Capture] Created captures directory at {self.captures_dir}")
        except Exception as e:
            print(f"[Capture] Error creating captures directory: {e}")
        self.interface = None  # Will be set during capture
        # Initialize tracking sets and dictionaries
        self._seen_segments = set()  # For TCP retransmission detection
        self._pending_acks = {}  # For RTT calculation
        self._syn_counts = {}  # For port scan detection

    def capture_traffic(self, target_ips=None, duration=60, progress_callback=None):
        """Capture network traffic for specific IPs or all traffic
        Args:
            target_ips: List of IP addresses to capture, or None for all traffic
            duration: Duration in seconds, or None for unlimited
            progress_callback: Optional callback for progress updates
        """
        # Get default interface
        try:
            import netifaces
            default_iface = None
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                default_iface = gateways['default'][netifaces.AF_INET][1]
            
            if not default_iface:
                # Try to find first non-loopback interface
                for iface in netifaces.interfaces():
                    if iface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(iface):
                        default_iface = iface
                        break
            
            if not default_iface:
                print("[Capture] No suitable network interface found")
                return None
            
            self.interface = default_iface
            print(f"[Capture] 📶 Capturing on interface: {self.interface}")
        except Exception as e:
            print(f"[Capture] Error finding network interface: {str(e)}")
            return None
        # Reset stop flag
        self.stop_capture = False
        
        # Generate filename with timestamp and target info
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if target_ips:
            if len(target_ips) == 1:
                pcap_file = self.captures_dir / f"Traffic-Capture-{timestamp}-{target_ips[0]}.pcap"
            else:
                pcap_file = self.captures_dir / f"Traffic-Capture-{timestamp}-{len(target_ips)}-devices.pcap"
            # Create BPF filter combining all target IPs with 'or'
            capture_filter = " or ".join(f"host {ip}" for ip in target_ips)
        else:
            pcap_file = self.captures_dir / f"Traffic-Capture-{timestamp}-all-traffic.pcap"
            capture_filter = ""
        print(f"[Capture] Will save to: {pcap_file}")
        
        # Initialize packet storage and counters
        packets = []
        start_time = time.time()
        packet_count = 0
        last_progress_update = 0
        
        def packet_callback(packet):
            nonlocal packet_count, last_progress_update
            if self.stop_capture:
                return True  # Stop capture
            
            packets.append(packet)
            packet_count += 1
            current_time = time.time()
            
            # Update progress at most every 0.1 seconds to avoid overwhelming the UI
            if current_time - last_progress_update >= 0.1:
                if duration:
                    # Show progress based on time for timed captures
                    elapsed = current_time - start_time
                    progress = min(elapsed / duration, 1.0)
                else:
                    # Show progress based on packet count for unlimited captures
                    # Use packet count as a way to show activity
                    progress = (packet_count % 100) / 100
                
                if progress_callback:
                    progress_callback(progress)
                last_progress_update = current_time
            
            # Stop if duration is reached
            if duration and (current_time - start_time) >= duration:
                return True
            
            return False
        
        # Start capture
        try:
            if progress_callback:
                progress_callback(0)  # Show initial progress
            
            scapy.sniff(filter=capture_filter,
                      prn=packet_callback,
                      store=False,
                      timeout=duration,
                      iface=self.interface)
            
            # Save captured packets
            if packets:
                if progress_callback:
                    progress_callback(1.0)  # Show complete
                wrpcap(str(pcap_file), packets)
                print(f"[Capture] Captured {packet_count} packets!")
                return pcap_file
            else:
                print("[Capture] No packets were captured")
                return None
            
        except Exception as e:
            print(f"[Capture] Error during capture: {str(e)}")
            return None
        finally:
            if progress_callback:
                progress_callback(1.0)  # Ensure progress bar is complete
    
    def stop_current_capture(self):
        """Stop the current capture if running"""
        self.stop_capture = True

    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file and return statistics"""
        try:
            print(f"[Analysis] Reading PCAP file: {pcap_file}")
            # Ensure the file exists
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                print(f"[Analysis] Error: PCAP file not found at {pcap_file}")
                return None

            # Read the PCAP file
            packets = rdpcap(str(pcap_file))
            print(f"[Analysis] Successfully read {len(packets)} packets")
        except Exception as e:
            print(f"[Analysis] Error reading PCAP file: {e}")
            return None
        
        stats = {
            'summary': {
                'total_packets': len(packets),
                'start_time': None,
                'end_time': None,
                'duration': 0,
                'avg_packet_size': 0,
                'total_bytes': 0,
                'packets_per_second': 0,
                'bandwidth_mbps': 0
            },
            'security': {
                'port_scans': defaultdict(list),  # Potential port scanning activity
                'ssl_issues': defaultdict(list),  # SSL/TLS security issues
                'weak_ciphers': defaultdict(list),  # Weak cipher usage
                'plain_auth': defaultdict(list),  # Plain text authentication
                'malware_signatures': defaultdict(list)  # Known malware patterns
            },
            'performance': {
                'tcp_metrics': defaultdict(lambda: {
                    'retransmissions': 0,
                    'window_sizes': [],
                    'rtt': [],
                    'zero_windows': 0
                }),
                'latency': defaultdict(list),  # Per-connection latency
                'bandwidth': defaultdict(lambda: {
                    'in_bytes': 0,
                    'out_bytes': 0,
                    'time_series': defaultdict(int)
                }),
                'qos': defaultdict(lambda: defaultdict(int))  # QoS tags distribution
            },
            'protocols': {
                'transport': {},  # TCP, UDP, etc.
                'application': {}  # HTTP, DNS, etc.
            },
            'ports': {
                'src': {},
                'dst': {}
            },
            'ips': {
                'src': {},
                'dst': {},
                'conversations': {},  # src-dst pairs
                'conversation_protocols': defaultdict(lambda: defaultdict(int)),  # protocols per conversation
                'data_usage': defaultdict(int)  # bytes per IP
            },
            'packet_sizes': [],
            'timestamps': [],
            'tcp_flags': {
                'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0
            },
            'web': {
                'urls': defaultdict(lambda: []),  # URLs visited by each IP
                'domains': defaultdict(int),  # Domain visit counts
                'media_types': defaultdict(int),  # Content-Type counts
                'requests': defaultdict(list),  # Full HTTP request details by IP
                'responses': defaultdict(list),  # Full HTTP response details by IP
                'content': defaultdict(list)  # Decoded content by IP
            },
            'media': {
                'voip': defaultdict(list),  # VoIP calls by IP (SIP/RTP)
                'audio': defaultdict(list),  # Audio streams by IP
                'video': defaultdict(list),  # Video streams by IP
                'images': defaultdict(list),  # Image transfers by IP
                'files': defaultdict(list),  # File transfers by IP
                'streams': defaultdict(list),  # Generic media streams
                'streaming': defaultdict(lambda: {  # Streaming quality metrics
                    'buffering_events': 0,
                    'quality_changes': [],
                    'bitrate_changes': [],
                    'segment_downloads': []
                })
            },
            'applications': {
                'email': defaultdict(list),  # SMTP/IMAP/POP3 traffic
                'file_transfers': defaultdict(list),  # FTP/SFTP transfers
                'databases': defaultdict(lambda: {  # Database traffic
                    'queries': [],
                    'response_times': [],
                    'error_rates': defaultdict(int)
                }),
                'websockets': defaultdict(lambda: {  # WebSocket connections
                    'messages': [],
                    'frame_types': defaultdict(int),
                    'protocols': set()
                }),
                'api_calls': defaultdict(lambda: {  # REST API analytics
                    'endpoints': defaultdict(list),
                    'methods': defaultdict(int),
                    'status_codes': defaultdict(int),
                    'response_times': []
                })
            },
            'torrents': {
                'peers': defaultdict(set),  # Peers per IP
                'data_transfer': defaultdict(int)  # Bytes transferred per IP
            },
            'file_transfers': {
                'ftp': [],  # List of FTP transfers
                'sftp': []  # List of SFTP transfers
            }
        }
        
        for packet in packets:
            # Get timestamp and size
            timestamp = float(packet.time)
            size = len(packet)
            stats['timestamps'].append(timestamp)
            stats['packet_sizes'].append(size)
            stats['summary']['total_bytes'] += size
            
            # Update time range
            if stats['summary']['start_time'] is None or timestamp < stats['summary']['start_time']:
                stats['summary']['start_time'] = timestamp
            if stats['summary']['end_time'] is None or timestamp > stats['summary']['end_time']:
                stats['summary']['end_time'] = timestamp
            
            # Analyze protocols
            if packet.haslayer(scapy.TCP):
                proto = "TCP"
                tcp = packet[scapy.TCP]
                ip = packet[IP]
                conn_key = f"{ip.src}:{tcp.sport}-{ip.dst}:{tcp.dport}"
                # TCP Metrics
                metrics = stats['performance']['tcp_metrics'][conn_key]
                metrics['window_sizes'].append(tcp.window)
                if tcp.window == 0:
                    metrics['zero_windows'] += 1
                # Detect retransmissions
                if hasattr(tcp, 'seq') and hasattr(tcp, 'ack'):
                    seq_key = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
                    if seq_key in self._seen_segments:
                        metrics['retransmissions'] += 1
                    self._seen_segments.add(seq_key)
                # Calculate RTT if possible
                if tcp.flags & 0x10:  # ACK flag
                    if conn_key in self._pending_acks:
                        send_time = self._pending_acks[conn_key]
                        rtt = timestamp - send_time
                        metrics['rtt'].append(rtt)
                        stats['performance']['latency'][conn_key].append(rtt)
                        del self._pending_acks[conn_key]
                else:
                    self._pending_acks[conn_key] = timestamp
                # Update bandwidth metrics
                bw_stats = stats['performance']['bandwidth'][conn_key]
                pkt_size = len(packet)
                if ip.src < ip.dst:  # Consistent direction tracking
                    bw_stats['out_bytes'] += pkt_size
                else:
                    bw_stats['in_bytes'] += pkt_size
                bw_stats['time_series'][int(timestamp)] += pkt_size
                # Security Analysis
                # Port scanning detection
                if tcp.flags & 0x02:  # SYN
                    self._syn_counts[(ip.src, ip.dst, tcp.dport)] = \
                        self._syn_counts.get((ip.src, ip.dst, tcp.dport), 0) + 1
                    # Check for potential port scan
                    if len([k for k in self._syn_counts.keys()
                           if k[0] == ip.src and k[1] == ip.dst]) > 10:
                        stats['security']['port_scans'][ip.src].append({
                            'timestamp': timestamp,
                            'target': ip.dst,
                            'ports': [k[2] for k in self._syn_counts.keys()
                                     if k[0] == ip.src and k[1] == ip.dst]
                        })
                # Analyze TCP flags
                flags = tcp.flags
                if flags & 0x02:  # SYN
                    stats['tcp_flags']['SYN'] += 1
                if flags & 0x10:  # ACK
                    stats['tcp_flags']['ACK'] += 1
                if flags & 0x01:  # FIN
                    stats['tcp_flags']['FIN'] += 1
                if flags & 0x04:  # RST
                    stats['tcp_flags']['RST'] += 1
                if flags & 0x08:  # PSH
                    stats['tcp_flags']['PSH'] += 1
                if flags & 0x20:  # URG
                    stats['tcp_flags']['URG'] += 1
                # Check for plain text authentication
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    auth_patterns = [b'password=', b'pwd=', b'pass=', b'auth=', b'login=']
                    if any(pattern in payload.lower() for pattern in auth_patterns):
                        stats['security']['plain_auth'][ip.src].append({
                            'timestamp': timestamp,
                            'dst_port': tcp.dport,
                            'protocol': 'TCP'
                        })
                
                # Get port numbers
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
                stats['ports']['src'][sport] = stats['ports']['src'].get(sport, 0) + 1
                stats['ports']['dst'][dport] = stats['ports']['dst'].get(dport, 0) + 1
                # Initialize application protocol
                app_proto = f"TCP/{dport}"
                # Identify application protocols
                if dport == 80 or sport == 80:
                    app_proto = "HTTP"
                    if packet.haslayer(HTTPRequest):
                        http = packet[HTTPRequest]
                        src_ip = packet[IP].src
                        # Extract HTTP request details
                        request = {
                            'timestamp': timestamp,
                            'method': http.Method.decode() if hasattr(http, 'Method') else 'Unknown',
                            'path': http.Path.decode() if hasattr(http, 'Path') else '',
                            'host': http.Host.decode() if hasattr(http, 'Host') else '',
                            'headers': {}
                        }
                        # Add headers if present
                        for field in http.fields:
                            if hasattr(http, field):
                                value = getattr(http, field)
                                if isinstance(value, bytes):
                                    request['headers'][field] = value.decode(errors='ignore')
                        stats['web']['requests'][src_ip].append(request)
                    elif packet.haslayer(HTTPResponse):
                        http = packet[HTTPResponse]
                        dst_ip = packet[IP].dst
                        # Extract HTTP response details
                        response = {
                            'timestamp': timestamp,
                            'status_code': http.Status_Code if hasattr(http, 'Status_Code') else 0,
                            'reason': http.Reason_Phrase.decode() if hasattr(http, 'Reason_Phrase') else '',
                            'headers': {},
                            'content_type': None
                        }
                        # Add headers and detect content type
                        for field in http.fields:
                            if hasattr(http, field):
                                value = getattr(http, field)
                                if isinstance(value, bytes):
                                    decoded = value.decode(errors='ignore')
                                    response['headers'][field] = decoded
                                    if field.lower() == 'content-type':
                                        response['content_type'] = decoded
                        
                        # Try to extract and decode content
                        if hasattr(http, 'load'):
                            content = http.load
                            content_type = response['content_type']
                            if content_type:
                                if 'text/html' in content_type or 'text/plain' in content_type:
                                    try:
                                        decoded = content.decode(errors='ignore')
                                        stats['web']['content'][dst_ip].append({
                                            'timestamp': timestamp,
                                            'type': 'text',
                                            'content': decoded
                                        })
                                    except UnicodeDecodeError:
                                        pass  # Skip content that can't be decoded as text
                                elif 'image/' in content_type:
                                    stats['media']['images'][dst_ip].append({
                                        'timestamp': timestamp,
                                        'type': content_type,
                                        'size': len(content),
                                        'data': content  # Raw image data
                                    })
                                elif 'audio/' in content_type:
                                    stats['media']['audio'][dst_ip].append({
                                        'timestamp': timestamp,
                                        'type': content_type,
                                        'size': len(content),
                                        'data': content  # Raw audio data
                                    })
                                elif 'video/' in content_type:
                                    stats['media']['video'][dst_ip].append({
                                        'timestamp': timestamp,
                                        'type': content_type,
                                        'size': len(content),
                                        'data': content  # Raw video data
                                    })
                        stats['web']['responses'][dst_ip].append(response)
                elif dport == 443 or sport == 443:
                    app_proto = "HTTPS"
                    if HAS_TLS_LAYER and packet.haslayer(TLS):
                        # Record TLS handshake info
                        tls = packet[TLS]
                        if hasattr(tls, 'type') and tls.type == 22:  # Handshake
                            src_ip = packet[IP].src
                            stats['web']['requests'][src_ip].append({
                                'timestamp': timestamp,
                                'type': 'tls_handshake',
                                'version': tls.version if hasattr(tls, 'version') else 'Unknown'
                            })
                elif dport == 53 or sport == 53:
                    app_proto = "DNS"
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        if dns.qr == 0:  # DNS query
                            src_ip = packet[IP].src
                            stats['web']['requests'][src_ip].append({
                                'timestamp': timestamp,
                                'type': 'dns_query',
                                'query': dns.qd.qname.decode() if dns.qd else 'Unknown'
                            })
                # Email protocols
                elif dport in [25, 587, 465] or sport in [25, 587, 465]:  # SMTP
                    app_proto = "SMTP"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load.decode(errors='ignore')
                        # Extract email metadata
                        if 'MAIL FROM:' in payload:
                            match = re.search(r'MAIL FROM:\s*<(.+?)>', payload)
                            if match:
                                stats['applications']['email'][ip.src].append({
                                    'timestamp': timestamp,
                                    'type': 'smtp_from',
                                    'address': match.group(1)
                                })
                        elif 'RCPT TO:' in payload:
                            match = re.search(r'RCPT TO:\s*<(.+?)>', payload)
                            if match:
                                stats['applications']['email'][ip.src].append({
                                    'timestamp': timestamp,
                                    'type': 'smtp_to',
                                    'address': match.group(1)
                                })
                        elif 'Subject:' in payload:
                            match = re.search(r'Subject:\s*(.+?)\r\n', payload)
                            if match:
                                stats['applications']['email'][ip.src].append({
                                    'timestamp': timestamp,
                                    'type': 'smtp_subject',
                                    'subject': match.group(1)
                                })
                elif dport in [143, 993] or sport in [143, 993]:  # IMAP
                    app_proto = "IMAP"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load.decode(errors='ignore')
                        if 'FETCH' in payload:
                            stats['applications']['email'][ip.src].append({
                                'timestamp': timestamp,
                                'type': 'imap_fetch',
                                'command': payload.split('\r\n')[0]
                            })
                elif dport in [110, 995] or sport in [110, 995]:  # POP3
                    app_proto = "POP3"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load.decode(errors='ignore')
                        if 'RETR' in payload:
                            stats['applications']['email'][ip.src].append({
                                'timestamp': timestamp,
                                'type': 'pop3_retr',
                                'command': payload.split('\r\n')[0]
                            })
                # Database protocols
                elif dport == 3306 or sport == 3306:  # MySQL
                    app_proto = "MySQL"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load
                        # MySQL protocol analysis
                        if len(payload) > 4:  # Minimum MySQL packet length
                            pkt_len = int.from_bytes(payload[0:3], byteorder='little')
                            if pkt_len > 0:
                                stats['applications']['databases'][ip.src]['queries'].append({
                                    'timestamp': timestamp,
                                    'type': 'mysql',
                                    'size': pkt_len
                                })
                elif dport == 5432 or sport == 5432:  # PostgreSQL
                    app_proto = "PostgreSQL"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load
                        if len(payload) > 1:
                            msg_type = chr(payload[0])  # PostgreSQL message type
                            stats['applications']['databases'][ip.src]['queries'].append({
                                'timestamp': timestamp,
                                'type': 'postgresql',
                                'message_type': msg_type
                            })
                elif dport == 27017 or sport == 27017:  # MongoDB
                    app_proto = "MongoDB"
                    if packet.haslayer(Raw):
                        payload = packet[Raw].load
                        if len(payload) >= 16:  # Minimum MongoDB message length
                            msg_len = int.from_bytes(payload[0:4], byteorder='little')
                            stats['applications']['databases'][ip.src]['queries'].append({
                                'timestamp': timestamp,
                                'type': 'mongodb',
                                'size': msg_len
                            })
                # WebSocket Analysis
                elif (dport == 80 or sport == 80) and packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b'Upgrade: websocket' in payload:
                        app_proto = "WebSocket-Handshake"
                        stats['applications']['websockets'][ip.src]['protocols'].add('ws')
                    elif b'\x81' in payload[:2]:  # WebSocket text frame
                        app_proto = "WebSocket"
                        frame_type = 'text'
                        stats['applications']['websockets'][ip.src]['frame_types']['text'] += 1
                        stats['applications']['websockets'][ip.src]['messages'].append({
                            'timestamp': timestamp,
                            'type': frame_type,
                            'size': len(payload)
                        })
                    elif b'\x82' in payload[:2]:  # WebSocket binary frame
                        app_proto = "WebSocket"
                        frame_type = 'binary'
                        stats['applications']['websockets'][ip.src]['frame_types']['binary'] += 1
                        stats['applications']['websockets'][ip.src]['messages'].append({
                            'timestamp': timestamp,
                            'type': frame_type,
                            'size': len(payload)
                        })
                # Streaming Media Analysis
                elif packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # HLS (HTTP Live Streaming)
                    if b'.m3u8' in payload or b'.ts' in payload:
                        app_proto = "HLS"
                        if b'.m3u8' in payload:
                            stats['media']['streaming'][ip.src]['segment_downloads'].append({
                                'timestamp': timestamp,
                                'type': 'manifest',
                                'size': len(payload)
                            })
                        else:
                            stats['media']['streaming'][ip.src]['segment_downloads'].append({
                                'timestamp': timestamp,
                                'type': 'segment',
                                'size': len(payload)
                            })
                    # DASH (Dynamic Adaptive Streaming over HTTP)
                    elif b'.mpd' in payload or b'.m4s' in payload:
                        app_proto = "DASH"
                        if b'.mpd' in payload:
                            stats['media']['streaming'][ip.src]['segment_downloads'].append({
                                'timestamp': timestamp,
                                'type': 'manifest',
                                'size': len(payload)
                            })
                        else:
                            stats['media']['streaming'][ip.src]['segment_downloads'].append({
                                'timestamp': timestamp,
                                'type': 'segment',
                                'size': len(payload)
                            })
                    # Detect quality changes
                    if any(x in payload for x in [b'RESOLUTION=', b'BANDWIDTH=']):
                        match = re.search(b'BANDWIDTH=(\d+)', payload)
                        if match:
                            bitrate = int(match.group(1))
                            stats['media']['streaming'][ip.src]['bitrate_changes'].append({
                                'timestamp': timestamp,
                                'bitrate': bitrate
                            })
                        match = re.search(b'RESOLUTION=(\d+x\d+)', payload)
                        if match:
                            resolution = match.group(1).decode()
                            stats['media']['streaming'][ip.src]['quality_changes'].append({
                                'timestamp': timestamp,
                                'resolution': resolution
                            })
                
                elif dport == 22 or sport == 22:
                    app_proto = "SSH"
                else:
                    app_proto = f"TCP/{dport}"
                
            elif packet.haslayer(UDP):
                proto = "UDP"
                udp = packet[UDP]
                sport = udp.sport
                dport = udp.dport
                
                # Update port stats
                stats['ports']['src'][sport] = stats['ports']['src'].get(sport, 0) + 1
                stats['ports']['dst'][dport] = stats['ports']['dst'].get(dport, 0) + 1
                # SIP/RTP Analysis (if available)
                if HAS_VOIP_LAYERS:
                    if packet.haslayer(SIP):
                        app_proto = "SIP"
                        sip = packet[SIP]
                        if hasattr(sip, 'Method'):
                            src_ip = packet[IP].src
                            method = sip.Method.decode() if isinstance(sip.Method, bytes) else str(sip.Method)
                            # Extract call details
                            call_info = {
                                'timestamp': timestamp,
                                'method': method,
                                'from': sip.From.decode() if hasattr(sip, 'From') and isinstance(sip.From, bytes) else str(getattr(sip, 'From', 'Unknown')),
                                'to': sip.To.decode() if hasattr(sip, 'To') and isinstance(sip.To, bytes) else str(getattr(sip, 'To', 'Unknown')),
                                'call_id': sip.Call_ID.decode() if hasattr(sip, 'Call_ID') and isinstance(sip.Call_ID, bytes) else str(getattr(sip, 'Call_ID', 'Unknown'))
                            }
                            # Add SDP information if present
                            if hasattr(sip, 'sdp'):
                                sdp = sip.sdp
                                call_info['media'] = {
                                    'type': sdp.media if hasattr(sdp, 'media') else 'Unknown',
                                    'port': sdp.port if hasattr(sdp, 'port') else 0,
                                    'protocol': sdp.proto if hasattr(sdp, 'proto') else 'Unknown'
                                }
                            stats['media']['voip'][src_ip].append(call_info)
                    elif packet.haslayer(RTP):
                        app_proto = "RTP"
                        # Extract RTP stream data
                        rtp = packet[RTP]
                        src_ip = packet[IP].src
                        stream_info = {
                            'timestamp': timestamp,
                            'ssrc': rtp.sourcesync if hasattr(rtp, 'sourcesync') else 0,
                            'payload_type': rtp.payload_type if hasattr(rtp, 'payload_type') else 0,
                            'sequence': rtp.sequence if hasattr(rtp, 'sequence') else 0,
                            'rtp_timestamp': rtp.timestamp if hasattr(rtp, 'timestamp') else 0,
                            'payload': bytes(rtp.payload) if hasattr(rtp, 'payload') else b''
                        }
                        stats['media']['voip'][src_ip].append(stream_info)
                # HTTP Analysis
                elif TCP in packet and packet[TCP].dport == 80:
                    app_proto = "HTTP"
                    if packet.haslayer(HTTPRequest):
                        http_layer = packet[HTTPRequest]
                        if hasattr(http_layer, 'Host') and hasattr(http_layer, 'Path'):
                            try:
                                host = http_layer.Host.decode()
                                path = http_layer.Path.decode()
                                url = f"http://{host}{path}"
                                ip_src = packet[IP].src
                                # Store URL visit
                                stats['web']['urls'][ip_src].append({
                                    'url': url,
                                    'timestamp': timestamp,
                                    'method': http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'GET'
                                })
                                # Parse domain
                                parsed_url = urlparse(url)
                                stats['web']['domains'][parsed_url.netloc] += 1
                                # Look for metadata in subsequent packets
                                if hasattr(http_layer, 'Headers') and isinstance(http_layer.Headers, dict):
                                    content_type = http_layer.Headers.get(b'Content-Type', b'').decode()
                                    stats['web']['media_types'][content_type] += 1
                            except Exception as e:
                                print(f"[Capture] Error processing HTTP request: {e}")
                    elif packet.haslayer(HTTPResponse):
                        http_layer = packet[HTTPResponse]
                        if hasattr(http_layer, 'Headers') and isinstance(http_layer.Headers, dict):
                            try:
                                # Extract content type
                                content_type = http_layer.Headers.get(b'Content-Type', b'').decode()
                                stats['web']['media_types'][content_type] += 1
                                # Look for HTML content with metadata
                                if b'text/html' in http_layer.Headers.get(b'Content-Type', b''):
                                    payload = bytes(http_layer.payload)
                                    # Extract title
                                    title_match = re.search(b'<title[^>]*>([^<]+)</title>', payload, re.I)
                                    if title_match:
                                        title = title_match.group(1).decode()
                                        stats['web']['titles'][url] = title
                                    # Extract description
                                    desc_match = re.search(b'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\'>]+)', payload, re.I)
                                    if desc_match:
                                        desc = desc_match.group(1).decode()
                                        stats['web']['descriptions'][url] = desc
                                    # Extract favicon
                                    favicon_match = re.search(b'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\'>]+)', payload, re.I)
                                    if favicon_match:
                                        favicon = favicon_match.group(1).decode()
                                        if not favicon.startswith('http'):
                                            favicon = f"http://{host}{favicon}"
                                        stats['web']['favicons'][url] = favicon
                            except Exception as e:
                                print(f"[Capture] Error processing HTTP response: {e}")
                # HTTPS Analysis
                elif TCP in packet and packet[TCP].dport == 443:
                    app_proto = "HTTPS"
                    if HAS_TLS_LAYER and packet.haslayer(TLS):
                        try:
                            tls_layer = packet[TLS]
                            if hasattr(tls_layer, 'type') and tls_layer.type == 22:  # Handshake
                                if hasattr(tls_layer, 'msg') and hasattr(tls_layer.msg[0], 'servername'):
                                    hostname = tls_layer.msg[0].servername.decode()
                                    ip_src = packet[IP].src
                                    url = f"https://{hostname}/"
                                    # Store HTTPS connection
                                    stats['web']['urls'][ip_src].append({
                                        'url': url,
                                        'timestamp': timestamp,
                                        'method': 'CONNECT'
                                    })
                                    stats['web']['domains'][hostname] += 1
                        except Exception as e:
                            print(f"[Capture] Error processing HTTPS packet: {e}")
                
                # DNS Analysis
                elif packet.haslayer(DNS):
                    app_proto = "DNS"
                    dns = packet[DNS]
                    if dns.qr == 0:  # DNS Query
                        if dns.qd and dns.qd.qname:
                            try:
                                domain = dns.qd.qname.decode()
                                stats['web']['domains'][domain] += 1
                            except Exception as e:
                                print(f"[Capture] Error processing DNS packet: {e}")
                
                elif dport == 67 or dport == 68:
                    app_proto = "DHCP"
                else:
                    app_proto = f"UDP/{dport}"
                    
            elif packet.haslayer(scapy.ICMP):
                proto = "ICMP"
                app_proto = "ICMP"
            else:
                proto = "Other"
                app_proto = "Other"
            
            stats['protocols']['transport'][proto] = stats['protocols']['transport'].get(proto, 0) + 1
            stats['protocols']['application'][app_proto] = stats['protocols']['application'].get(app_proto, 0) + 1
            
            # Track protocols per conversation if IP layer exists
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                conversation = f"{src} → {dst}"
                stats['ips']['conversation_protocols'][conversation][app_proto] += 1
            # Analyze IP addresses and conversations
            if scapy.IP in packet:
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                stats['ips']['src'][src] = stats['ips']['src'].get(src, 0) + 1
                stats['ips']['dst'][dst] = stats['ips']['dst'].get(dst, 0) + 1
                
                # Track conversations (source-destination pairs)
                conversation = f"{src} → {dst}"
                stats['ips']['conversations'][conversation] = stats['ips']['conversations'].get(conversation, 0) + 1
        
        # Calculate summary statistics
        if stats['timestamps']:
            stats['summary']['duration'] = stats['summary']['end_time'] - stats['summary']['start_time']
            stats['summary']['avg_packet_size'] = stats['summary']['total_bytes'] / stats['summary']['total_packets']
            stats['summary']['packets_per_second'] = stats['summary']['total_packets'] / stats['summary']['duration'] if stats['summary']['duration'] > 0 else 0
            stats['summary']['bandwidth_mbps'] = (stats['summary']['total_bytes'] * 8 / 1_000_000) / stats['summary']['duration'] if stats['summary']['duration'] > 0 else 0
            
            # Convert sets to lists for JSON serialization
            for ip in stats['torrents']['peers']:
                stats['torrents']['peers'][ip] = list(stats['torrents']['peers'][ip])
        
        # --- Minimal Alerting Logic ---
        alerts = []
        # Port scan detection: many SYNs from one source to many ports
        syn_counts = {}
        for pkt in packets:
            if pkt.haslayer(scapy.TCP):
                tcp = pkt[scapy.TCP]
                if tcp.flags == 'S':  # SYN flag
                    src = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else None
                    dst_port = tcp.dport
                    if src:
                        if src not in syn_counts:
                            syn_counts[src] = set()
                        syn_counts[src].add(dst_port)
        for src, ports in syn_counts.items():
            if len(ports) > 20:
                alerts.append({
                    'type': 'port_scan',
                    'source': src,
                    'details': f'Port scan detected: {len(ports)} ports targeted',
                })
        # Brute force detection: many failed logins (simple heuristic: many TCP connections to common auth ports)
        auth_ports = {22, 23, 21, 25, 110, 143, 3389, 5900}
        auth_attempts = {}
        for pkt in packets:
            if pkt.haslayer(scapy.TCP):
                tcp = pkt[scapy.TCP]
                dport = tcp.dport
                src = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else None
                if dport in auth_ports and src:
                    if src not in auth_attempts:
                        auth_attempts[src] = 0
                    auth_attempts[src] += 1
        for src, count in auth_attempts.items():
            if count > 30:
                alerts.append({
                    'type': 'brute_force',
                    'source': src,
                    'details': f'Brute force attempts detected: {count} connections to auth ports',
                })
        # Save alerts to file
        alerts_dir = Path('reports/alerts')
        alerts_dir.mkdir(parents=True, exist_ok=True)
        alerts_file = alerts_dir / 'alerts.json'
        try:
            import json
            if alerts_file.exists():
                with alerts_file.open('r', encoding='utf-8') as f:
                    existing_alerts = json.load(f)
            else:
                existing_alerts = []
            existing_alerts.extend(alerts)
            with alerts_file.open('w', encoding='utf-8') as f:
                json.dump(existing_alerts, f, indent=2)
        except Exception as e:
            print(f"[Alert] Error saving alerts: {e}")
        # --- End Alerting Logic ---
        return stats
