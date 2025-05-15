#!/usr/bin/env python3
"""
WiFi Packet Capture and Analysis Tool
For Ubuntu/Linux systems with monitor mode support
Requires: scapy
To install requirements: pip install scapy
"""

import os
import time
import threading
import socket
import argparse
from datetime import datetime
from scapy.all import sniff, Dot11, RadioTap, Raw, Dot11Auth, Dot11Deauth

class WifiCapture:
    def __init__(self, iface):
        self.iface = iface
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket = None
        self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_port = 5000
        self.frame_counts = {
            'auth': 0,
            'deauth': 0,
            'total': 0
        }

    def channel_hopper(self):
        """Hop through WiFi channels to capture frames on all channels"""
        while True:
            for channel in range(1, 14):
                os.system(f"iwconfig {self.iface} channel {channel}")
                time.sleep(0.5)  # Adjust delay as needed

    def start_server(self):
        """Start the server and wait for a connection"""
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(1)
        print(f"Server started on {self.server_ip}:{self.server_port}")
        print("Waiting for a connection...")
        self.client_socket, addr = self.server_socket.accept()
        print(f"Connected to {addr}")

    def send_data(self, data):
        """Send data to the connected client"""
        if self.client_socket:
            try:
                self.client_socket.sendall((data + '\n').encode())
            except Exception as e:
                print(f"Error sending data: {e}")

    def analyze_frame(self, packet):
        """Analyze 802.11 frame details"""
        if not packet.haslayer(Dot11):
            return None

        frame_type = packet.type
        frame_subtype = packet.subtype
        result = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'type': frame_type,
            'subtype': frame_subtype,
            'channel': None,
            'rssi': None,
            'src': None,
            'dst': None,
            'bssid': None,
        }

        # Extract RadioTap info if present
        if packet.haslayer(RadioTap):
            if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                result['rssi'] = packet[RadioTap].dBm_AntSignal
            if hasattr(packet[RadioTap], 'Channel'):
                result['channel'] = packet[RadioTap].Channel

        # Extract addresses
        if hasattr(packet[Dot11], 'addr1'):
            result['dst'] = packet[Dot11].addr1
        if hasattr(packet[Dot11], 'addr2'):
            result['src'] = packet[Dot11].addr2
        if hasattr(packet[Dot11], 'addr3'):
            result['bssid'] = packet[Dot11].addr3

        return result

    def packet_handler(self, packet):
        """Handle captured packets and send them to the client"""
        self.frame_counts['total'] += 1
        
        if packet.haslayer(Dot11Auth):
            self.frame_counts['auth'] += 1
            frame_info = self.analyze_frame(packet)
            if frame_info:
                frame_info['frame_type'] = 'Authentication'
                self.send_data(f"AUTH: {frame_info}")
                
        elif packet.haslayer(Dot11Deauth):
            self.frame_counts['deauth'] += 1
            frame_info = self.analyze_frame(packet)
            if frame_info:
                frame_info['frame_type'] = 'Deauthentication'
                if packet.haslayer(Dot11Deauth):
                    frame_info['reason_code'] = packet[Dot11Deauth].reason
                self.send_data(f"DEAUTH: {frame_info}")

    def start_capture(self):
        """Start capturing packets and streaming them to the client"""
        try:
            self.start_server()
            print(f"Starting capture on interface {self.iface}")
            print("Frame analysis for Authentication and Deauthentication frames")
            
            hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
            hopper_thread.start()
            
            # Start packet capture with filter for Auth and Deauth frames
            sniff(iface=self.iface, 
                 prn=self.packet_handler, 
                 store=0,
                 lfilter=lambda p: p.haslayer(Dot11Auth) or p.haslayer(Dot11Deauth))
                 
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
            self.server_socket.close()

def main():
    parser = argparse.ArgumentParser(description='WiFi Frame Capture Tool')
    parser.add_argument('interface', help='Network interface in monitor mode')
    args = parser.parse_args()

    # Check if running on Linux
    if os.name != 'posix':
        print("This script requires Linux with a monitor mode capable wireless interface")
        return

    # Start capture
    capture = WifiCapture(args.interface)
    capture.start_capture()

if __name__ == '__main__':
    main()