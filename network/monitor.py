"""Device monitoring functionality for NetWatch"""
import time
from pathlib import Path
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

    def halt_monitoring(self):
        """Stop monitoring tracked devices"""
        self.stop_monitoring = True
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_loop(self):
        """Main monitoring loop"""
        while not self.stop_monitoring:
            try:
                # Load tracked devices
                with open('data/tracked_devices.json', 'r', encoding='utf-8') as f:
                    tracked_devices = json.load(f).get('devices', [])
                
                # Load device history for IP lookup
                history_path = Path('data') / 'device_history.json'
                try:
                    raw = history_path.read_text(encoding='utf-8')
                    history = json.loads(raw).get('devices', {})
                except Exception:
                    history = {}
                # Build list of IPs to monitor
                target_ips = []
                for entry in tracked_devices:
                    if isinstance(entry, str):
                        mac = entry.lower()
                        dev = history.get(mac, {})
                        ip = dev.get('ip_address') or (dev.get('ip_history', [])[-1] if dev.get('ip_history', []) else None)
                    elif isinstance(entry, dict):
                        ip = entry.get('ip')
                    else:
                        continue
                    if ip:
                        target_ips.append(ip)
                
                if target_ips:
                    # Start a new capture for each IP
                    for ip in target_ips:
                        self.traffic_capture.capture_traffic(
                            target_ips=[ip],
                            duration=60  # 1 minute capture
                        )
                
                # Wait for 5 minutes before next check
                for _ in range(30):  # 30 x 10 seconds = 5 minutes
                    if self.stop_monitoring:
                        break
                    time.sleep(10)
                    
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[Monitor] Error loading tracked devices: {e}")
                time.sleep(60)  # Wait a minute before retrying on error
            except Exception as e:
                print(f"[Monitor] Unexpected error: {e}")
                time.sleep(60)  # Wait a minute before retrying on error
