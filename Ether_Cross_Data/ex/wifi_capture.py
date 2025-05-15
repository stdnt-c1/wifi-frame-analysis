import os
import time
import threading
import socket
from scapy.all import sniff

class WifiCapture:
    def __init__(self, iface):
        self.iface = iface
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket = None
        self.server_ip = socket.gethostbyname(socket.gethostname())  # Automatically get local IP
        self.server_port = 5000  # Default port

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

    def packet_handler(self, packet):
        """Handle captured packets and send them to the client"""
        # Example: Send raw packet summary
        self.send_data(str(packet.summary()))

    def start_capture(self):
        """Start capturing packets and streaming them to the client"""
        try:
            self.start_server()
            print(f"Starting capture on interface {self.iface}")
            hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
            hopper_thread.start()
            sniff(iface=self.iface, prn=self.packet_handler, store=0)
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.server_socket.close()