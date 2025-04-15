from dataclasses import dataclass
from typing import Optional, List
from datetime import datetime

@dataclass
class NetworkDevice:
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    tracked: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    activity: str = "Unknown"
    ip_history: List[str] = None

    def __post_init__(self):
        # Ensure MAC address is standardized
        if self.mac_address:
            self.mac_address = str(self.mac_address).lower()
        
        # Initialize empty IP history if None
        if self.ip_history is None:
            self.ip_history = [self.ip_address] if self.ip_address else []

    def update_activity(self, now: Optional[datetime] = None):
        """Update device activity status based on last seen time"""
        if not now:
            now = datetime.now()
        
        if not self.last_seen:
            self.activity = "New"
        else:
            delta = now - self.last_seen
            if delta.total_seconds() < 300:  # 5 minutes
                self.activity = "Active"
            elif delta.total_seconds() < 3600:  # 1 hour
                self.activity = "Recent"
            else:
                self.activity = "Inactive"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            "mac": self.mac_address,
            "ip": self.ip_address,
            "hostname": self.hostname or "Unknown",
            "tracked": self.tracked,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "activity": self.activity,
            "ip_history": self.ip_history
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'NetworkDevice':
        """Create NetworkDevice from dictionary"""
        return cls(
            mac_address=data["mac"],
            ip_address=data["ip"],
            hostname=data.get("hostname", "Unknown"),
            tracked=data.get("tracked", False),
            first_seen=datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            activity=data.get("activity", "Unknown"),
            ip_history=data.get("ip_history", [])
        )
