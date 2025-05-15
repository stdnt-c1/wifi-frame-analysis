#!/usr/bin/env python3
"""
Windows client for displaying captured WiFi frames
Compatible with wifi_capture.py running on Ubuntu/Linux
"""

import socket
import argparse
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

class FrameDisplay:
    def __init__(self, server_ip, server_port=5000):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        colorama.init()  # Initialize colorama for Windows color support
        
    def connect(self):
        """Connect to the capture server"""
        try:
            print(f"Connecting to {self.server_ip}:{self.server_port}...")
            self.client_socket.connect((self.server_ip, self.server_port))
            print("Connected successfully!")
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
        return True
        
    def format_frame(self, frame_data):
        """Format frame data for display"""
        try:
            # Strip "AUTH: " or "DEAUTH: " prefix and parse the rest as a dictionary
            if frame_data.startswith("AUTH: ") or frame_data.startswith("DEAUTH: "):
                frame_type = frame_data.split(":")[0]
                data_str = frame_data[frame_data.index("{"):].replace("'", '"')
                data = json.loads(data_str)
                
                # Format output with colors
                if frame_type == "AUTH":
                    color = Fore.GREEN
                else:  # DEAUTH
                    color = Fore.RED
                    
                output = [
                    f"{color}[{frame_type}]{Style.RESET_ALL}",
                    f"Time: {data.get('timestamp', 'N/A')}",
                    f"Channel: {data.get('channel', 'N/A')}",
                    f"RSSI: {data.get('rssi', 'N/A')} dBm",
                    f"Source: {data.get('src', 'N/A')}",
                    f"Destination: {data.get('dst', 'N/A')}",
                    f"BSSID: {data.get('bssid', 'N/A')}"
                ]
                
                if 'reason_code' in data:
                    output.append(f"Reason Code: {data['reason_code']}")
                    
                return " | ".join(output)
            return frame_data
        except Exception as e:
            return f"Error formatting frame: {e}\nRaw data: {frame_data}"
    
    def start_display(self):
        """Start receiving and displaying frames"""
        print("Waiting for frames... Press Ctrl+C to stop")
        print("\nColor codes:")
        print(f"{Fore.GREEN}Green{Style.RESET_ALL}: Authentication frames")
        print(f"{Fore.RED}Red{Style.RESET_ALL}: Deauthentication frames\n")
        
        try:
            while True:
                data = self.client_socket.recv(4096).decode()
                if not data:
                    break
                    
                # Handle multiple lines in received data
                for line in data.strip().split('\n'):
                    if line:
                        formatted = self.format_frame(line)
                        print(formatted)
                        
        except KeyboardInterrupt:
            print("\nStopping frame display...")
        except Exception as e:
            print(f"Error receiving data: {e}")
        finally:
            self.client_socket.close()

def main():
    parser = argparse.ArgumentParser(description='WiFi Frame Display Client (Windows)')
    parser.add_argument('server_ip', help='IP address of the capture server')
    parser.add_argument('--port', type=int, default=5000, help='Server port (default: 5000)')
    args = parser.parse_args()
    
    display = FrameDisplay(args.server_ip, args.port)
    if display.connect():
        display.start_display()

if __name__ == '__main__':
    main()
