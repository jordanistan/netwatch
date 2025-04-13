import requests
import asyncio
import aiohttp
import time
from pathlib import Path

async def generate_test_traffic():
    """Generate various types of network traffic for testing"""
    # Create captures directory if it doesn't exist
    Path('captures').mkdir(exist_ok=True)
    
    # List of URLs to test (SFW content only)
    urls = [
        # Video content
        "https://download.samplelib.com/mp4/sample-5s.mp4",
        "https://download.samplelib.com/mp4/sample-10s.mp4",
        
        # Audio content
        "https://download.samplelib.com/mp3/sample-3s.mp3",
        "https://download.samplelib.com/mp3/sample-15s.mp3",
        
        # Image content
        "https://picsum.photos/200/300",
        "https://picsum.photos/300/400",
        
        # Regular HTTP/HTTPS traffic
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
