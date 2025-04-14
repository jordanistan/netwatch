#!/usr/bin/env python3
from datetime import datetime
from typing import Dict, Any
from test_traffic import generate_voip_sample

def generate_simulated_stats() -> Dict[str, Any]:
    """Generate simulated statistics for testing"""
    voip_data = generate_voip_sample()
    
    return {
        'total_packets': 15783,
        'protocols': {'HTTP': 4521, 'HTTPS': 8945, 'DNS': 1254, 'Other': 1063, 'SIP/RTP': 1234},
        'packet_sizes': [64]*1000 + [1500]*500,  # Simulated packet sizes
        'timestamps': [datetime.now().timestamp() - i*60 for i in range(1000)],  # Last 1000 minutes
        'ips': {
            'src': {'10.0.0.100': 15783},
            'dst': {
                'adult-site.example.com': 4521,
                'torrent.example.net': 8945,
                'malware.example.org': 1254,
                'miner.example.com': 1063,
                '192.168.86.100': 1234  # VoIP destination
            }
        },
        'http_traffic': [
            {'method': 'GET', 'url': 'http://adult-site.example.com/video1.mp4', 'size': 1500000},
            {'method': 'GET', 'url': 'http://torrent.example.net/movie.mkv', 'size': 2500000},
            {'method': 'POST', 'url': 'http://miner.example.com/worker.js', 'size': 50000},
            {'method': 'GET', 'url': 'http://malware.example.org/payload.exe', 'size': 750000}
        ],
        'media_files': [
            {
                'type': 'video',
                'filename': 'video1.mp4',
                'mime_type': 'video/mp4',
                'size': 1500000,
                'src': '10.0.0.100',
                'dst': 'adult-site.example.com',
                'playable': True,
                'media_url': 'https://www.w3schools.com/html/mov_bbb.mp4'
            },
            {
                'type': 'video',
                'filename': 'movie.mkv',
                'mime_type': 'video/x-matroska',
                'size': 2500000,
                'src': '10.0.0.100',
                'dst': 'torrent.example.net',
                'playable': True,
                'media_url': 'https://www.w3schools.com/html/mov_bbb.mp4'
            },
            {
                'type': 'audio',
                'filename': 'voip_call.wav',
                'mime_type': 'audio/wav',
                'size': 245678,
                'src': '10.0.0.100',
                'dst': '192.168.86.100',
                'playable': True,
                'media_url': 'https://www.w3schools.com/html/horse.mp3',
                'voip_data': voip_data
            }
        ],
        'suspicious_activity': {
            'adult_content': [
                {'url': 'http://adult-site.example.com/video1.mp4', 'count': 47},
                {'url': 'http://adult-site.example.com/video2.mp4', 'count': 23}
            ],
            'piracy': [
                {'url': 'http://torrent.example.net/movie.mkv', 'count': 15},
                {'url': 'http://warez.example.com/software.iso', 'count': 8}
            ],
            'malware': [
                {'url': 'http://malware.example.org/payload.exe', 'count': 3}
            ],
            'crypto_mining': [
                {'url': 'http://miner.example.com/worker.js', 'count': 1254}
            ],
            'botnet': [
                {'url': 'http://botnet.example.org/command.php', 'count': 2}
            ]
        }
    }

def get_risk_assessment() -> Dict[str, Any]:
    """Generate a risk assessment report"""
    return {
        'risk_level': 'CRITICAL',
        'bandwidth_usage': '87%',
        'active_hours': '22:00 - 04:00',
        'connection_type': 'VPN/Proxy',
        'evasion_attempts': True,
        'total_incidents': {
            'adult_content': 47,
            'piracy': 23,
            'malware': 3,
            'crypto_mining': 1254,
            'botnet': 2
        }
    }
