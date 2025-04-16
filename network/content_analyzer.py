"""Content extraction and analysis for NetWatch"""
import re
import json
from pathlib import Path
import logging

# Import scapy components
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

# Try to import optional components
# TLS support check
HAS_TLS = False
try:
    from scapy.layers.tls import TLS
    HAS_TLS = True
except ImportError:
    pass

# VoIP support check
HAS_VOIP = False
try:
    from scapy.contrib.sip import SIP
    from scapy.layers.rtp import RTP
    HAS_VOIP = True
except ImportError:
    pass

# Content type patterns
IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml']
AUDIO_TYPES = ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/aac', 'audio/webm']
VIDEO_TYPES = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime']
DOCUMENT_TYPES = ['application/pdf', 'application/msword', 'application/vnd.ms-excel']

# Adult site patterns (simplified for demo)
ADULT_SITE_PATTERNS = [
    r'adult', r'xxx', r'porn', r'sex', r'nsfw',
    # Add more patterns as needed
]

class ContentAnalyzer:
    def __init__(self, reports_dir='reports'):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.media_dir = self.reports_dir / 'media'
        self.media_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize content storage
        self.http_streams = {}
        self.file_downloads = []
        self.media_files = []
        self.plaintext_comms = []
        self.sip_calls = []
        self.websites = []
        
    def analyze_pcap(self, pcap_file):
        """Analyze PCAP file for content extraction"""
        logging.info(f"Analyzing PCAP for content extraction: {pcap_file}")
        
        # Read packets
        try:
            packets = scapy.rdpcap(str(pcap_file))
        except Exception as e:
            logging.error(f"Error reading PCAP file: {e}")
            return None
            
        # Process packets for content extraction
        self._process_packets(packets)
        
        # Prepare results
        results = {
            'file_downloads': self.file_downloads,
            'media_files': self.media_files,
            'plaintext': self.plaintext_comms,
            'sip_calls': self.sip_calls,
            'websites': self.websites
        }
        
        # Save results to JSON
        try:
            results_file = self.reports_dir / 'content_analysis.json'
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving content analysis results: {e}")
            
        return results
        
    def _process_packets(self, packets):
        """Process packets for content extraction"""
        # First pass: Collect TCP streams
        streams = {}
        
        for packet in packets:
            # HTTP Analysis
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                self._process_http(packet)
                
            # TCP stream collection for reassembly
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                stream_id = self._get_stream_id(packet)
                if stream_id not in streams:
                    streams[stream_id] = []
                streams[stream_id].append(packet)
                
            # SIP/VoIP Analysis
            if HAS_VOIP and packet.haslayer(SIP):
                self._process_sip(packet)
                
        # Second pass: Reassemble and analyze TCP streams
        for stream_id, stream_packets in streams.items():
            self._analyze_stream(stream_id, stream_packets)
    
    def _process_http(self, packet):
        """Process HTTP packets for content extraction"""
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            if hasattr(http_layer, 'Host') and hasattr(http_layer, 'Path'):
                host = http_layer.Host.decode() if isinstance(http_layer.Host, bytes) else http_layer.Host
                path = http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else http_layer.Path
                url = f"http://{host}{path}"
                
                # Check for adult content
                is_adult = any(re.search(pattern, url.lower()) for pattern in ADULT_SITE_PATTERNS)
                
                website = {
                    'url': url,
                    'timestamp': packet.time,
                    'is_adult': is_adult,
                    'method': http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else http_layer.Method
                }
                self.websites.append(website)
                
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            if hasattr(http_layer, 'Content_Type'):
                content_type = http_layer.Content_Type.decode() if isinstance(http_layer.Content_Type, bytes) else http_layer.Content_Type
                
                # Extract content based on type
                if any(media_type in content_type.lower() for media_type in IMAGE_TYPES + AUDIO_TYPES + VIDEO_TYPES):
                    self._extract_media(packet, content_type)
                elif any(doc_type in content_type.lower() for doc_type in DOCUMENT_TYPES):
                    self._extract_file(packet, content_type)
                elif 'text/plain' in content_type.lower() or 'text/html' in content_type.lower():
                    self._extract_text(packet)
    
    def _process_sip(self, packet):
        """Process SIP packets for call extraction"""
        sip_layer = packet[SIP]
        
        # Check if this is a SIP INVITE (call initiation)
        if hasattr(sip_layer, 'Method') and sip_layer.Method == b'INVITE':
            # Extract call details
            call_id = sip_layer.Call_ID.decode() if isinstance(sip_layer.Call_ID, bytes) else sip_layer.Call_ID
            from_uri = sip_layer.From.uri.decode() if isinstance(sip_layer.From.uri, bytes) else sip_layer.From.uri
            to_uri = sip_layer.To.uri.decode() if isinstance(sip_layer.To.uri, bytes) else sip_layer.To.uri
            
            # Create call record
            call = {
                'call_id': call_id,
                'from': from_uri,
                'to': to_uri,
                'timestamp': packet.time,
                'audio_file': None  # Will be populated if RTP audio is extracted
            }
            self.sip_calls.append(call)
    
    def _extract_media(self, packet, content_type):
        """Extract media content from packet"""
        if packet.haslayer(Raw):
            # Create a unique filename
            media_type = content_type.split('/')[1].split(';')[0]
            filename = f"media_{int(packet.time)}_{hash(str(packet))}.{media_type}"
            filepath = self.media_dir / filename
            
            # Save content
            try:
                with open(filepath, 'wb') as f:
                    f.write(packet[Raw].load)
                
                # Record media file
                media = {
                    'type': content_type,
                    'timestamp': packet.time,
                    'filename': str(filepath),
                    'size': len(packet[Raw].load)
                }
                self.media_files.append(media)
            except Exception as e:
                logging.error(f"Error saving media file: {e}")
    
    def _extract_file(self, packet, content_type):
        """Extract file download from packet"""
        if packet.haslayer(Raw):
            # Create a unique filename
            file_ext = content_type.split('/')[1].split(';')[0]
            filename = f"download_{int(packet.time)}_{hash(str(packet))}.{file_ext}"
            filepath = self.media_dir / filename
            
            # Save content
            try:
                with open(filepath, 'wb') as f:
                    f.write(packet[Raw].load)
                
                # Get source information
                src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                
                # Record file download
                download = {
                    'type': content_type,
                    'timestamp': packet.time,
                    'filename': str(filepath),
                    'size': len(packet[Raw].load),
                    'source': src_ip
                }
                self.file_downloads.append(download)
            except Exception as e:
                logging.error(f"Error saving downloaded file: {e}")
    
    def _extract_text(self, packet):
        """Extract plaintext communication from packet"""
        if packet.haslayer(Raw):
            try:
                # Try to decode as UTF-8
                text = packet[Raw].load.decode('utf-8', errors='replace')
                
                # Record plaintext communication
                comm = {
                    'timestamp': packet.time,
                    'content': text[:1000],  # Limit size for display
                    'size': len(text)
                }
                self.plaintext_comms.append(comm)
            except Exception as e:
                logging.error(f"Error extracting plaintext: {e}")
    
    def _get_stream_id(self, packet):
        """Generate a unique ID for a TCP stream"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Create bidirectional stream ID (same ID regardless of direction)
            if f"{src_ip}:{src_port}" < f"{dst_ip}:{dst_port}":
                return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            else:
                return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        return None
    
    def _analyze_stream(self, stream_id, packets):
        """Analyze a reassembled TCP stream for content"""
        # Sort packets by sequence number
        packets.sort(key=lambda p: p[TCP].seq)
        
        # Reassemble stream data
        stream_data = b''
        for packet in packets:
            if packet.haslayer(Raw):
                stream_data += packet[Raw].load
        
        # Skip empty streams
        if not stream_data:
            return
        
        # Check for HTTP data
        if stream_data.startswith(b'HTTP/') or b'HTTP/' in stream_data[:100]:
            self._analyze_http_stream(stream_id, stream_data)
        
        # Check for common file signatures
        self._check_file_signatures(stream_id, stream_data)
    
    def _analyze_http_stream(self, stream_id, data):
        """Analyze HTTP stream data"""
        # Simple HTTP response parsing
        if data.startswith(b'HTTP/'):
            # Find end of headers
            header_end = data.find(b'\r\n\r\n')
            if header_end > 0:
                headers = data[:header_end].decode('utf-8', errors='replace')
                body = data[header_end+4:]
                
                # Extract content type
                content_type_match = re.search(r'Content-Type: (.+?)(\r\n|\r|\n)', headers)
                if content_type_match:
                    content_type = content_type_match.group(1).lower()
                    
                    # Handle content based on type
                    if any(media_type in content_type for media_type in IMAGE_TYPES + AUDIO_TYPES + VIDEO_TYPES):
                        self._save_stream_media(stream_id, body, content_type)
                    elif any(doc_type in content_type for doc_type in DOCUMENT_TYPES):
                        self._save_stream_file(stream_id, body, content_type)
                    elif 'text/plain' in content_type or 'text/html' in content_type:
                        self._save_stream_text(stream_id, body, content_type)
    
    def _check_file_signatures(self, stream_id, data):
        """Check for known file signatures in stream data"""
        # Common file signatures (magic numbers)
        signatures = {
            b'\xFF\xD8\xFF': ('jpg', 'image/jpeg'),
            b'\x89\x50\x4E\x47': ('png', 'image/png'),
            b'\x47\x49\x46\x38': ('gif', 'image/gif'),
            b'\x25\x50\x44\x46': ('pdf', 'application/pdf'),
            b'\x50\x4B\x03\x04': ('zip', 'application/zip'),
            b'\x52\x49\x46\x46': ('wav/avi', 'audio/wav'),
            b'\x49\x44\x33': ('mp3', 'audio/mpeg')
        }
        
        # Check for signatures at the start of the data
        for sig, (_, mime_type) in signatures.items():
            if data.startswith(sig):
                if 'image' in mime_type:
                    self._save_stream_media(stream_id, data, mime_type)
                elif 'audio' in mime_type or 'video' in mime_type:
                    self._save_stream_media(stream_id, data, mime_type)
                else:
                    self._save_stream_file(stream_id, data, mime_type)
                return
    
    def _save_stream_media(self, stream_id, data, content_type):
        """Save media content from a stream"""
        media_type = content_type.split('/')[1].split(';')[0]
        filename = f"stream_{stream_id.replace(':', '_').replace('-', '_')}_{hash(data[:100])}.{media_type}"
        filepath = self.media_dir / filename
        
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
            
            # Record media file
            media = {
                'type': content_type,
                'timestamp': None,  # No packet timestamp available
                'filename': str(filepath),
                'size': len(data),
                'stream_id': stream_id
            }
            self.media_files.append(media)
        except Exception as e:
            logging.error(f"Error saving stream media: {e}")
    
    def _save_stream_file(self, stream_id, data, content_type):
        """Save file content from a stream"""
        file_ext = content_type.split('/')[1].split(';')[0]
        filename = f"file_{stream_id.replace(':', '_').replace('-', '_')}_{hash(data[:100])}.{file_ext}"
        filepath = self.media_dir / filename
        
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
            
            # Record file download
            download = {
                'type': content_type,
                'timestamp': None,  # No packet timestamp available
                'filename': str(filepath),
                'size': len(data),
                'source': stream_id.split('-')[1].split(':')[0],  # Extract destination IP
                'stream_id': stream_id
            }
            self.file_downloads.append(download)
        except Exception as e:
            logging.error(f"Error saving stream file: {e}")
    
    def _save_stream_text(self, stream_id, data, content_type):
        """Save plaintext content from a stream"""
        try:
            # Try to decode as UTF-8
            text = data.decode('utf-8', errors='replace')
            
            # Record plaintext communication
            comm = {
                'timestamp': None,  # No packet timestamp available
                'content': text[:1000],  # Limit size for display
                'size': len(text),
                'stream_id': stream_id
            }
            self.plaintext_comms.append(comm)
        except Exception as e:
            logging.error(f"Error extracting stream plaintext: {e}")
