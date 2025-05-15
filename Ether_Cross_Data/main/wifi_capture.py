import os
import time
import threading
from scapy.all import sniff
import json
from datetime import datetime
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11Disas, Dot11Deauth, Dot11Action

class WifiCapture:
    def __init__(self, iface, log_file=None, filter_type=None):
        self.iface = iface
        self.socket = None
        self.log_file = log_file
        self.filter_type = filter_type
        self.stats = {
            'BEACON': 0, 'PROBE_REQ': 0, 'PROBE_RES': 0,
            'AUTH': 0, 'ASSOC_REQ': 0, 'ASSOC_RES': 0,
            'REASSOC_REQ': 0, 'REASSOC_RES': 0,
            'DISASSOC': 0, 'DEAUTH': 0, 'ACTION': 0
        }

    def channel_hopper(self):
        """Hop through WiFi channels to capture frames on all channels"""
        while True:
            for channel in range(1, 14):
                os.system(f"iwconfig {self.iface} channel {channel}")
                time.sleep(0.5)  # Adjust delay as needed

    def packet_handler(self, packet):
        """Handle captured packets"""
        if not packet.haslayer(Dot11):
            return

        frame_type = self.get_frame_type(packet)
        if not frame_type:
            return

        # Update statistics
        self.stats[frame_type] += 1

        # Extract packet details
        frame_info = {
            'type': frame_type,
            'src': packet.addr2 if packet.addr2 else 'N/A',
            'dst': packet.addr1 if packet.addr1 else 'N/A',
            'rssi': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A',
            'timestamp': datetime.now().isoformat()
        }

        # Filter packets if a filter is set
        if self.filter_type and frame_info['type'] != self.filter_type:
            return

        # Log packet to file
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(frame_info) + '\n')

        # Print packet details
        print(frame_info)

    def get_frame_type(self, packet):
        """Determine 802.11 frame type"""
        if packet.haslayer(Dot11Beacon):
            return 'BEACON'
        elif packet.haslayer(Dot11ProbeReq):
            return 'PROBE_REQ'
        elif packet.haslayer(Dot11ProbeResp):
            return 'PROBE_RES'
        elif packet.haslayer(Dot11Auth):
            return 'AUTH'
        elif packet.haslayer(Dot11AssoReq):
            return 'ASSOC_REQ'
        elif packet.haslayer(Dot11AssoResp):
            return 'ASSOC_RES'
        elif packet.haslayer(Dot11ReassoReq):
            return 'REASSOC_REQ'
        elif packet.haslayer(Dot11ReassoResp):
            return 'REASSOC_RES'
        elif packet.haslayer(Dot11Disas):
            return 'DISASSOC'
        elif packet.haslayer(Dot11Deauth):
            return 'DEAUTH'
        elif packet.haslayer(Dot11Action):
            return 'ACTION'
        return None

    def print_summary(self):
        """Print a summary of captured packets"""
        print("\nPacket Capture Summary:")
        for frame_type, count in self.stats.items():
            print(f"{frame_type}: {count}")

    def start_capture(self):
        """Start capturing packets with channel hopping"""
        try:
            print(f"Starting capture on interface {self.iface}")
            hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
            hopper_thread.start()
            sniff(iface=self.iface, prn=self.packet_handler, store=0)
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            if self.socket:
                self.socket.close()
            self.print_summary()