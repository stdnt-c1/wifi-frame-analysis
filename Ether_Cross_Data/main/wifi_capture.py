#!/usr/bin/env python3
"""
Ubuntu WiFi Frame Capture Script
Captures 802.11 frames in monitor mode and streams them to Windows display
"""

from scapy.all import *
import socket
import json
from datetime import datetime
import argparse

class WifiCapture:
    def __init__(self, iface, server_ip, server_port=5000):
        self.iface = iface
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stats = {
            'BEACON': 0, 'PROBE_REQ': 0, 'PROBE_RES': 0,
            'AUTH': 0, 'ASSOC_REQ': 0, 'ASSOC_RES': 0,
            'REASSOC_REQ': 0, 'REASSOC_RES': 0,
            'DISASSOC': 0, 'DEAUTH': 0, 'ACTION': 0
        }
        
    def start_server(self):
        """Start TCP server for streaming data"""
        self.socket.bind((self.server_ip, self.server_port))
        self.socket.listen(1)
        print(f"Waiting for connection on {self.server_ip}:{self.server_port}")
        self.client, addr = self.socket.accept()
        print(f"Connected to {addr}")
        # Send initial connection message
        self.send_data("START|")

    def send_data(self, data):
        """Send data to the Windows client"""
        try:
            self.client.send((data + '\n').encode())
        except:
            print("Error sending data, attempting to reconnect...")
            self.start_server()

    def send_stats(self):
        """Send current statistics"""
        stats_str = 'STATS|' + ','.join(str(v) for v in self.stats.values())
        self.send_data(stats_str)

    def get_frame_type(self, pkt):
        """Determine 802.11 frame type"""
        if pkt.haslayer(Dot11Beacon):
            self.stats['BEACON'] += 1
            return 'BEACON'
        elif pkt.haslayer(Dot11ProbeReq):
            self.stats['PROBE_REQ'] += 1
            return 'PROBE_REQ'
        elif pkt.haslayer(Dot11ProbeResp):
            self.stats['PROBE_RES'] += 1
            return 'PROBE_RES'
        elif pkt.haslayer(Dot11Auth):
            self.stats['AUTH'] += 1
            return 'AUTH'
        elif pkt.haslayer(Dot11AssoReq):
            self.stats['ASSOC_REQ'] += 1
            return 'ASSOC_REQ'
        elif pkt.haslayer(Dot11AssoResp):
            self.stats['ASSOC_RES'] += 1
            return 'ASSOC_RES'
        elif pkt.haslayer(Dot11ReassoReq):
            self.stats['REASSOC_REQ'] += 1
            return 'REASSOC_REQ'
        elif pkt.haslayer(Dot11ReassoResp):
            self.stats['REASSOC_RES'] += 1
            return 'REASSOC_RES'
        elif pkt.haslayer(Dot11Disas):
            self.stats['DISASSOC'] += 1
            return 'DISASSOC'
        elif pkt.haslayer(Dot11Deauth):
            self.stats['DEAUTH'] += 1
            return 'DEAUTH'
        elif pkt.haslayer(Dot11Action):
            self.stats['ACTION'] += 1
            return 'ACTION'
        return None

    def packet_handler(self, pkt):
        """Process captured packets"""
        if not pkt.haslayer(Dot11):
            return

        frame_type = self.get_frame_type(pkt)
        if not frame_type:
            return

        # Extract basic frame information
        frame_info = {
            'type': frame_type,
            'src': pkt.addr2 if pkt.addr2 else 'N/A',
            'dst': pkt.addr1 if pkt.addr1 else 'N/A',
            'rssi': pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 'N/A'
        }

        # Extract SSID from beacons and probe responses
        if frame_type in ['BEACON', 'PROBE_RES']:
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                frame_info['SSID'] = pkt[Dot11Elt].info.decode(errors='replace')

        # Format frame data
        frame_str = f"[{frame_type}] "
        frame_str += ' '.join(f"{k}:{v}" for k, v in frame_info.items())
        
        # Send frame data
        self.send_data(frame_str)
        
        # Send updated stats every 10 frames
        if sum(self.stats.values()) % 10 == 0:
            self.send_stats()

    def start_capture(self):
        """Start capturing packets"""
        try:
            print(f"Starting capture on interface {self.iface}")
            sniff(iface=self.iface, prn=self.packet_handler, store=0)
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(description='Ubuntu WiFi Frame Capture')
    parser.add_argument('interface', help='Wireless interface in monitor mode')
    parser.add_argument('--ip', default='0.0.0.0', help='IP address to bind server (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind server (default: 5000)')
    
    args = parser.parse_args()
    
    capture = WifiCapture(args.interface, args.ip, args.port)
    capture.start_server()
    capture.start_capture()

if __name__ == '__main__':
    main()
