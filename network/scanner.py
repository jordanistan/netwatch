"""Network scanning functionality for NetWatch"""
import json
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
import scapy.all as scapy
import netifaces

class NetworkScanner:
    def __init__(self):
        from .models import NetworkDevice
        self.NetworkDevice = NetworkDevice  # Store for use in other methods
        self.cached_devices = []

        # Set up data directory
        self.data_dir = Path("data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Load device history
        self.device_history_file = self.data_dir / "device_history.json"
        if self.device_history_file.exists():
            history_data = json.loads(self.device_history_file.read_text())
            self.device_history = {
                "devices": {mac: NetworkDevice.from_dict(data) 
                          for mac, data in history_data.get("devices", {}).items()}
            }
        else:
            self.device_history = {"devices": {}}
            self.device_history_file.write_text(json.dumps({"devices": {}}, indent=4))

        # Initialize tracked devices
        self.tracked_devices_file = self.data_dir / "tracked_devices.json"
        if self.tracked_devices_file.exists():
            tracked_data = json.loads(self.tracked_devices_file.read_text())
            self.tracked_devices = {"devices": [mac for mac in tracked_data.get("devices", [])]}
        else:
            self.tracked_devices = {"devices": []}
            self.tracked_devices_file.write_text(json.dumps({"devices": []}, indent=4))
    def get_default_interface(self):
        """Get the default network interface that's connected to LAN"""
        try:
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                # Skip loopback and virtual interfaces
                if any(iface.startswith(x) for x in ['lo', 'docker', 'br-', 'vbox', 'vmnet']):
                    continue
                
                addrs = netifaces.ifaddresses(iface)
                
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    if not ip.startswith('169.254'):  # Exclude self-assigned IPs
                        print(f"[Scanner] Found active interface {iface} with IP {ip}")
                        return iface, ip
            
            print("[Scanner] No suitable network interface found")
            return None, None
        except Exception as e:
            print(f"[Scanner] Error finding network interface: {str(e)}")
            return None, None

    def get_network_range(self, interface, ip):
        """Get the network range for the given interface"""
        try:
            if not interface or not ip:
                raise ValueError("No interface or IP provided")
            
            if ip.startswith('127.'):
                raise ValueError(f"Interface {interface} is bound to loopback")
            
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                raise ValueError(f"Invalid IP format: {ip}")
            
            # Determine network class and range
            first_octet = int(ip_parts[0])
            if first_octet == 10:  # Class A private network
                return "10.0.0.0/8"
            elif first_octet == 172 and 16 <= int(ip_parts[1]) <= 31:  # Class B private network
                return f"172.{ip_parts[1]}.0.0/16"
            elif first_octet == 192 and ip_parts[1] == '168':  # Class C private network
                return f"192.168.{ip_parts[2]}.0/24"
            else:
                print(f"[Scanner] IP {ip} is not in a private network range")
                return f"{'.'.join(ip_parts[:3])}.0/24"
                
        except Exception as e:
            print(f"[Scanner] Error determining network range: {str(e)}")
            return None

    def scan_devices(self, interface, network_range):
        """Scan network for devices using ARP"""
        try:
            # Create and send ARP request
            arp = scapy.ARP(pdst=network_range)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send multiple ARP requests to ensure we catch all devices
            devices = []
            for attempt in range(2):  # Try twice
                ans, _ = scapy.srp(packet, timeout=2, verbose=0, iface=interface)
                
                # Process responses
                for _, received in ans:
                    try:
                        # Try to get hostname but don't fail if we can't
                        try:
                            hostname = socket.gethostbyaddr(received.psrc)[0]
                        except (socket.gaierror, socket.herror):
                            hostname = "N/A"
                        
                        # Check if device already found
                        device = {
                            'ip': received.psrc,
                            'mac': received.hwsrc,
                            'hostname': hostname
                        }
                        if not any(d['ip'] == device['ip'] for d in devices):
                            devices.append(device)
                            
                            # Update device history
                            mac = device['mac']
                            current_time = datetime.now().isoformat()
                            
                            if mac not in self.device_history["devices"]:
                                # New device
                                self.device_history["devices"][mac] = {
                                    "first_seen": current_time,
                                    "last_seen": current_time,
                                    "ip_history": [device['ip']],
                                    "hostname": device.get('hostname', 'N/A')
                                }
                            else:
                                # Update existing device
                                self.device_history["devices"][mac]["last_seen"] = current_time
                                if device['ip'] not in self.device_history["devices"][mac]["ip_history"]:
                                    self.device_history["devices"][mac]["ip_history"].append(device['ip'])
                                self.device_history["devices"][mac]["hostname"] = device.get('hostname', 'N/A')
                            
                            # Save device history
                            self.device_history_file.write_text(json.dumps(self.device_history, indent=4))
                    except Exception as e:
                        print(f"[Scanner] Could not process device {received.psrc}: {str(e)}")
                        continue
                
                # Small delay between attempts
                if attempt == 0:
                    time.sleep(0.5)
            
            # Cache the devices
            self.cached_devices = devices
            return devices
        except Exception as e:
            print(f"[Scanner] Error scanning network: {str(e)}")
            return []
    
    def _get_activity_status(self, device_info):
        """Get the activity status for a device
        Args:
            device_info: Device history info containing first_seen and last_seen
        Returns:
            Activity status string
        """
        if device_info["first_seen"] == device_info["last_seen"]:
            return "New Device"
        
        last_seen = datetime.fromisoformat(device_info["last_seen"])
        now = datetime.now()
        time_ago = now - last_seen
        
        if time_ago < timedelta(minutes=1):
            return "Rejoined just now"
        elif time_ago < timedelta(hours=1):
            minutes = int(time_ago.total_seconds() / 60)
            return f"Rejoined {minutes}m ago"
        elif time_ago < timedelta(days=1):
            hours = int(time_ago.total_seconds() / 3600)
            return f"Rejoined {hours}h ago"
        else:
            days = time_ago.days
            return f"Rejoined {days}d ago"
    
    def get_cached_devices(self):
        """Get the list of devices from the last scan, sorted by discovery time"""
        # Sort devices by first_seen time if available
        return sorted(
            self.cached_devices,
            key=lambda d: self.device_history["devices"].get(d["mac"], {}).get("first_seen", ""),
            reverse=True  # Newest first
        )
    
    def is_device_tracked(self, mac):
        """Check if a device is being tracked
        Args:
            mac: MAC address of the device
        Returns:
            bool: True if device is tracked, False otherwise
        """
        # Ensure we're comparing string MAC addresses
        mac_str = str(mac)
        return mac_str in self.tracked_devices["devices"]

    def track_device(self, mac):
        """Add a device to tracked devices
        Args:
            mac: MAC address of the device to track
        """
        mac_str = str(mac).lower()
        if mac_str not in self.tracked_devices["devices"]:
            # Update device history to mark as tracked
            if mac_str in self.device_history["devices"]:
                self.device_history["devices"][mac_str].tracked = True
                self._save_device_history()
            
            self.tracked_devices["devices"].append(mac_str)
            self.tracked_devices_file.write_text(json.dumps(self.tracked_devices, indent=4))

    def untrack_device(self, mac):
        """Remove a device from tracked devices
        Args:
            mac: MAC address of the device to untrack
        """
        mac_str = str(mac).lower()
        if mac_str in self.tracked_devices["devices"]:
            # Update device history to mark as untracked
            if mac_str in self.device_history["devices"]:
                self.device_history["devices"][mac_str].tracked = False
                self._save_device_history()
                
            self.tracked_devices["devices"].remove(mac_str)
            self.tracked_devices_file.write_text(json.dumps(self.tracked_devices, indent=4))
    
    def get_tracked_devices(self):
        """Get all tracked devices that are currently active
        Returns:
            List of NetworkDevice objects that are being tracked
        """
        tracked = []
        for mac_addr in self.tracked_devices["devices"]:
            if mac_addr in self.device_history["devices"]:
                device = self.device_history["devices"][mac_addr]
                device.tracked = True  # Ensure tracked status is set
                device.update_activity()  # Update activity status
                tracked.append(device)
        return tracked
    def get_new_devices(self, limit=10, include_tracked=False):
        """Get recently active devices (new or rejoining)
        Args:
            limit: Maximum number of devices to return
        Returns:
            List of NetworkDevice objects sorted by most recent activity (newest first)
        """
        if not self.device_history["devices"]:
            return []

        # Get devices sorted by most recent activity
        devices = [
            device for device in self.device_history["devices"].values()
            if include_tracked or not device.tracked
        ]

        # Sort by last_seen
        sorted_devices = sorted(
            devices,
            key=lambda d: d.last_seen if d.last_seen else datetime.min,
            reverse=True  # Newest first
        )

        # Update activity status for each device
        for device in sorted_devices[:limit]:
            device.update_activity()

        return sorted_devices[:limit]
