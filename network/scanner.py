"""Network scanning functionality for NetWatch"""
import json
import logging
from datetime import datetime
from pathlib import Path
import scapy.all as scapy
import netifaces
from .models import NetworkDevice

class NetworkScanner:
    def __init__(self):
        self.cached_devices = []

        # Set up data directory
        self.data_dir = Path("data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize tracked devices first
        self.tracked_devices_file = self.data_dir / "tracked_devices.json"
        if self.tracked_devices_file.exists():
            tracked_data = json.loads(self.tracked_devices_file.read_text())
            self.tracked_devices = {"devices": set()}
            for device in tracked_data.get("devices", []):
                if isinstance(device, str):
                    # If it's just a MAC address string
                    self.tracked_devices["devices"].add(device.lower())
                elif isinstance(device, dict) and "mac" in device:
                    # If it's a device object with a MAC address
                    self.tracked_devices["devices"].add(device["mac"].lower())
        else:
            self.tracked_devices = {"devices": set()}
            self.tracked_devices_file.write_text(json.dumps({"devices": []}, indent=4))

        # Load device history
        self.device_history_file = self.data_dir / "device_history.json"
        if self.device_history_file.exists():
            history_data = json.loads(self.device_history_file.read_text())
            self.device_history = {"devices": {}}
            for mac, data in history_data.get("devices", {}).items():
                mac = mac.lower()  # Normalize MAC address
                device = NetworkDevice(
                    mac_address=mac,
                    ip_address=data.get("ip_address") or data.get("ip_history", ["N/A"])[-1],
                    hostname=data.get("hostname", "Unknown"),
                    tracked=mac in self.tracked_devices["devices"],
                    first_seen=datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None,
                    last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
                    activity=data.get("activity", "Unknown")
                )
                device.ip_history = data.get("ip_history", [])
                device.update_activity()
                self.device_history["devices"][mac] = device
        else:
            self.device_history = {"devices": {}}
            self.device_history_file.write_text(json.dumps({"devices": {}}, indent=4))
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
        except (netifaces.NetifacesError, KeyError, IndexError) as e:
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
        """Scan the network for devices using ARP only (restored to previous working state)."""
        logging.debug(f"Starting network scan on {interface} for range {network_range}")
        devices_found = []
        try:
            # ARP Scan only
            logging.debug("Performing ARP scan...")
            arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=network_range)
            answered, _ = scapy.srp(arp_request, timeout=2, iface=interface, verbose=False)
            logging.debug(f"ARP scan finished. {len(answered)} devices responded.")

            for _, received in answered:
                mac = received.hwsrc
                ip = received.psrc
                device = NetworkDevice(ip_address=ip, mac_address=mac)
                devices_found.append(device)
                logging.debug(f"ARP found: IP={ip}, MAC={mac}")

            # Update device history
            now = datetime.now()
            logging.debug("Updating device history...")
            for device in devices_found:
                self._update_device_entry(device.mac_address, device.ip_address, getattr(device, 'hostname', None), now)
            self.save_device_history()
            logging.debug("Device history updated and saved.")

        except PermissionError:
            logging.error("Permission denied for raw socket access. Try running with sudo.")
        except OSError as e:
            if "No such device" in str(e):
                logging.error(f"Network interface '{interface}' not found.")
            else:
                logging.exception("An OS error occurred during scanning")
        except Exception:
            logging.exception("An unexpected error occurred during network scan")

        logging.debug(f"Network scan completed. Found {len(devices_found)} devices.")
        return devices_found

    def get_cached_devices(self):
        """Get the list of devices from the last scan, sorted by discovery time"""
        # Sort devices by first_seen time if available
        return sorted(
            self.cached_devices,
            key=lambda d: getattr(self.device_history["devices"].get(d.mac_address, {}), 'first_seen', ''),
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
            
            self.tracked_devices["devices"].add(mac_str)
            # Convert set to list for JSON serialization
            tracked_json = {"devices": list(self.tracked_devices["devices"])}
            self.tracked_devices_file.write_text(json.dumps(tracked_json, indent=4))

    def _save_device_history(self):
        """Save device history to file"""
        try:
            # Convert NetworkDevice objects to dictionaries
            history_data = {
                "devices": {mac: dev.to_dict() for mac, dev in self.device_history["devices"].items()}
            }
            self.device_history_file.write_text(json.dumps(history_data, indent=4))
        except Exception as e:
            print(f"[Scanner] Error saving device history: {str(e)}")
    
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
            tracked_json = {"devices": list(self.tracked_devices["devices"])}
            self.tracked_devices_file.write_text(json.dumps(tracked_json, indent=4))

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
            include_tracked: Whether to include tracked devices in results
        Returns:
            List of NetworkDevice objects sorted by most recent activity (newest first)
        """
        if not self.device_history["devices"]:
            return []

        # Get devices sorted by most recent activity
        devices = []
        for _, device in self.device_history["devices"].items():
            if include_tracked or not device.tracked:
                devices.append(device)

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

    def _get_activity_status(self, device_history):
        """Get activity status for a device based on its history
        Args:
            device_history: Device history dictionary
        Returns:
            str: Activity status
        """
        if not device_history:
            return "New Device"

        # Get last seen time
        last_seen = device_history.get('last_seen')
        if not last_seen:
            return "Unknown"

        now = datetime.now()
        time_ago = now - last_seen

        # Determine activity status based on time since last seen
        if time_ago.days > 7:
            return "Inactive"
        elif time_ago.days > 1:
            return f"Last seen {time_ago.days} days ago"
        elif time_ago.seconds > 3600:
            hours = time_ago.seconds // 3600
            return f"Last seen {hours} hours ago"
        elif time_ago.seconds > 60:
            minutes = time_ago.seconds // 60
            return f"Last seen {minutes} minutes ago"
        else:
            return "Active"
