"""Device monitoring functionality for NetWatch"""
import time
from pathlib import Path
from datetime import datetime
import threading
import json

from .capture import TrafficCapture

class DeviceMonitor:
    def __init__(self, captures_dir='captures'):
        self.captures_dir = Path(captures_dir)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.traffic_capture = TrafficCapture(captures_dir)
        self.monitor_thread = None
        self.stop_monitoring = False

    def start_monitoring(self):
        """Start monitoring tracked devices"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
        
        self.stop_monitoring = False
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring tracked devices"""
        self.stop_monitoring = True
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_loop(self):
        """Main monitoring loop"""
        while not self.stop_monitoring:
            try:
                # Load tracked devices
                with open('data/tracked_devices.json', 'r') as f:
                    tracked_devices = json.load(f)['devices']
                
                # Get list of IPs to monitor
                target_ips = []
                for device in tracked_devices:
                    # Use last_known_ip if ip is not present
                    ip = device.get('ip', device.get('last_known_ip'))
                    if ip:
                        target_ips.append(ip)
                
                if target_ips:
                    # Generate timestamp for filename
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    
                    # Start a new capture for each device
                    for device in tracked_devices:
                        ip = device.get('ip', device.get('last_known_ip'))
                        if ip:
                            device_id = device.get('mac', '').replace(':', '')
                            if device_id:
                                # Create device-specific capture
                                self.traffic_capture.capture_traffic(
                                    target_ips=[ip],
                                    duration=60,  # 1 minute capture
                                )
                
                # Wait for 5 minutes before next check
                for _ in range(30):  # 30 x 10 seconds = 5 minutes
                    if self.stop_monitoring:
                        break
                    time.sleep(10)
                    
            except Exception as e:
                print(f"Error in monitor loop: {e}")
                time.sleep(60)  # Wait a minute before retrying on error
