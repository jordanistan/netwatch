import asyncio
import aiohttp
from pathlib import Path
from datetime import datetime, timedelta

def generate_voip_sample():
    """Generate a simulated VoIP call sample"""
    return {
        'type': 'voip_call',
        'protocol': 'SIP/RTP',
        'src_ip': '10.0.0.100',
        'dst_ip': '192.168.86.100',
        'start_time': datetime.now() - timedelta(minutes=5),
        'duration': 300,  # 5 minutes in seconds
        'codec': 'G.711',
        'sample_rate': '8kHz',
        'status': 'completed',
        'media_url': 'https://example.com/sample-call.wav',
        'call_id': 'CALL-001-2025',
        'participants': ['Alice <sip:alice@10.0.0.100>', 'Bob <sip:bob@192.168.86.100>'],
        'quality_metrics': {
            'jitter': '15ms',
            'latency': '50ms',
            'packet_loss': '0.1%',
            'mos': 4.2
        }
    }

async def generate_test_traffic():
    """Generate various types of network traffic for testing"""
    # Create captures directory if it doesn't exist
    Path('captures').mkdir(exist_ok=True)
    
    # Simulated URLs for testing (all safe, just for demonstration)
    urls = [
        # Simulated adult content (safe URLs, just for testing)
        "https://example-adult-site.com/video1.mp4",
        "https://adult-streaming.example.com/stream2.mp4",
        "https://adult-content.example.net/images/1.jpg",
        
        # Simulated movie downloads (safe URLs, just for testing)
        "https://torrent.example.com/movie1.mkv",
        "https://pirate-movies.example.net/latest.mp4",
        "https://warez.example.org/download.iso",
        
        # Simulated suspicious activity
        "https://malware.example.com/payload.exe",
        
        # Simulated VoIP traffic
        "sip:alice@10.0.0.100",
        "sip:bob@192.168.86.100",
        "https://cryptominer.example.net/worker.js",
        "https://botnet.example.org/command.php",
        
        # Regular traffic to mix in
        "https://example.com",
        "https://httpbin.org/get",
        "https://api.github.com/zen"
    ]
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            # Create multiple requests to each URL
            for _ in range(3):
                tasks.append(asyncio.create_task(fetch_url(session, url)))
        
        print("Generating test traffic...")
        await asyncio.gather(*tasks)
        print("Traffic generation complete!")

async def fetch_url(session, url):
    """Fetch a URL and handle the response"""
    try:
        async with session.get(url) as response:
            await response.read()
            print(f"Fetched: {url}")
    except Exception as e:
        print(f"Error fetching {url}: {e}")

if __name__ == "__main__":
    print("Starting traffic generation...")
    asyncio.run(generate_test_traffic())
    print("Test complete!")
