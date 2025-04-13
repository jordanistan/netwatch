#!/usr/bin/env python3
from scapy.all import *
import time
import statistics
from collections import defaultdict

def analyze_latency():
    print("\n🔍 Testing connection latency and service response times...")
    
    # Track SYN-ACK latency and response times
    latencies = defaultdict(list)
    syn_times = {}
    
    def packet_callback(pkt):
        if TCP in pkt and IP in pkt:
            stream_id = f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
            rev_stream_id = f"{pkt[IP].dst}:{pkt[TCP].dport}-{pkt[IP].src}:{pkt[TCP].sport}"
            
            # Track SYN packets
            if pkt[TCP].flags & 0x02:  # SYN
                syn_times[stream_id] = pkt.time
            
            # Measure SYN-ACK latency
            elif pkt[TCP].flags & 0x12 and rev_stream_id in syn_times:  # SYN-ACK
                latency = (pkt.time - syn_times[rev_stream_id]) * 1000  # ms
                latencies["syn_ack"].append(latency)
                del syn_times[rev_stream_id]
            
            # Track request-response latency for established connections
            elif pkt[TCP].flags & 0x18:  # PSH-ACK
                if stream_id not in syn_times:
                    syn_times[stream_id] = pkt.time
                else:
                    latency = (pkt.time - syn_times[stream_id]) * 1000  # ms
                    latencies["response"].append(latency)
                    del syn_times[stream_id]
    
    print("Starting 10-second latency analysis...")
    sniff(iface="eth0", prn=packet_callback, timeout=10)
    
    # Calculate statistics
    stats = {}
    for metric, values in latencies.items():
        if values:
            stats[metric] = {
                "min": min(values),
                "max": max(values),
                "avg": statistics.mean(values),
                "median": statistics.median(values),
                "samples": len(values)
            }
    
    print("\nLatency Analysis Results:")
    print("=" * 50)
    
    if "syn_ack" in stats:
        print("\nTCP Handshake Latency (ms):")
        print(f"  Min: {stats['syn_ack']['min']:.2f}")
        print(f"  Max: {stats['syn_ack']['max']:.2f}")
        print(f"  Avg: {stats['syn_ack']['avg']:.2f}")
        print(f"  Median: {stats['syn_ack']['median']:.2f}")
        print(f"  Samples: {stats['syn_ack']['samples']}")
    
    if "response" in stats:
        print("\nService Response Time (ms):")
        print(f"  Min: {stats['response']['min']:.2f}")
        print(f"  Max: {stats['response']['max']:.2f}")
        print(f"  Avg: {stats['response']['avg']:.2f}")
        print(f"  Median: {stats['response']['median']:.2f}")
        print(f"  Samples: {stats['response']['samples']}")

if __name__ == "__main__":
    analyze_latency()
