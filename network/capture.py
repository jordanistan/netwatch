"""Traffic capture functionality for NetWatch"""
import time
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

import scapy.all as scapy
from scapy.utils import wrpcap, rdpcap
import streamlit as st

# Import additional Scapy layers
from scapy.layers.inet import UDP, IP, TCP
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
    from scapy.layers.rtp import RTP
    from scapy.layers.sip import SIP
    HAS_VOIP_LAYERS = True
except ImportError:
    HAS_VOIP_LAYERS = False

class TrafficCapture:
    def __init__(self, captures_dir):
        self.captures_dir = Path(captures_dir)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.interface = None  # Will be set during capture

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
                st.error("No suitable network interface found")
                return None
            
            self.interface = default_iface
            st.info(f"📶 Capturing on interface: {self.interface}")
        except Exception as e:
            st.error(f"Error finding network interface: {str(e)}")
            return None
        # Reset stop flag
        self.stop_capture = False
        
        # Generate filename with timestamp and target info
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if target_ips:
            if len(target_ips) == 1:
                pcap_file = self.captures_dir / f"Alert-Traffic-Capture-{timestamp}-{target_ips[0]}.pcap"
            else:
                pcap_file = self.captures_dir / f"Alert-Traffic-Capture-{timestamp}-{len(target_ips)}-devices.pcap"
            # Create BPF filter combining all target IPs with 'or'
            capture_filter = " or ".join(f"host {ip}" for ip in target_ips)
        else:
            pcap_file = self.captures_dir / f"Alert-Traffic-Capture-{timestamp}-all-traffic.pcap"
            capture_filter = ""
        
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
                st.success(f"Captured {packet_count} packets!")
                return pcap_file
            else:
                st.warning("No packets were captured")
                return None
            
        except Exception as e:
            st.error(f"Error during capture: {str(e)}")
            return None
        finally:
            if progress_callback:
                progress_callback(1.0)  # Ensure progress bar is complete
    
    def stop_current_capture(self):
        """Stop the current capture if running"""
        self.stop_capture = True

    def analyze_pcap(self, pcap_file):
        """Analyze a PCAP file and return statistics"""
        packets = rdpcap(str(pcap_file))
        
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
                'thumbnails': defaultdict(str),  # URL thumbnails
                'titles': defaultdict(str),  # Page titles
                'descriptions': defaultdict(str),  # Meta descriptions
                'favicons': defaultdict(str)  # Favicon URLs
            },
            'media': {
                'streams': [],  # List of media streams (SIP, RTP, etc.)
                'files': []  # List of media file transfers
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
                # Analyze TCP flags
                flags = packet[scapy.TCP].flags
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
                
                # Get port numbers
                sport = packet[scapy.TCP].sport
                dport = packet[scapy.TCP].dport
                stats['ports']['src'][sport] = stats['ports']['src'].get(sport, 0) + 1
                stats['ports']['dst'][dport] = stats['ports']['dst'].get(dport, 0) + 1
                
                # Identify application protocols
                if dport == 80 or sport == 80:
                    app_proto = "HTTP"
                elif dport == 443 or sport == 443:
                    app_proto = "HTTPS"
                elif dport == 53 or sport == 53:
                    app_proto = "DNS"
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
                        if hasattr(sip, 'Method') and sip.Method in [b'INVITE', b'BYE']:
                            if IP in packet:
                                ip = packet[IP]
                                stats['media']['streams'].append({
                                    'type': 'SIP',
                                    'method': sip.Method.decode(),
                                    'timestamp': timestamp,
                                    'source': ip.src,
                                    'destination': ip.dst
                                })
                    elif packet.haslayer(RTP):
                        app_proto = "RTP"
                        if IP in packet:
                            ip = packet[IP]
                            stats['media']['streams'].append({
                                'type': 'RTP',
                                'timestamp': timestamp,
                                'source': ip.src,
                                'destination': ip.dst,
                                'size': size
                            })
                
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
                                st.error(f"Error processing HTTP request: {e}")
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
                                st.error(f"Error processing HTTP response: {e}")
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
                            st.error(f"Error processing HTTPS packet: {e}")
                
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
                                st.error(f"Error processing DNS packet: {e}")
                
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
        
        return stats
