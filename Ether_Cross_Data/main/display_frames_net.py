from rich.console import Console
from rich.live import Live
import socket

class FrameAnalyzer:
    def __init__(self, log_file=None, filter_type=None, refresh_rate=4):
        self.console = Console()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log_file = log_file
        self.filter_type = filter_type
        self.refresh_rate = refresh_rate
        self.stats = {
            'BEACON': 0, 'PROBE_REQ': 0, 'PROBE_RES': 0,
            'AUTH': 0, 'ASSOC_REQ': 0, 'ASSOC_RES': 0,
            'REASSOC_REQ': 0, 'REASSOC_RES': 0,
            'DISASSOC': 0, 'DEAUTH': 0, 'ACTION': 0
        }
        self.recent_frames = []
        self.max_recent = 10
        self.buffer = ""

    def connect(self, host, port):
        """Connect to the Ubuntu capture server"""
        try:
            self.socket.connect((host, port))
            print(f"Connected to server at {host}:{port}")
        except Exception as e:
            self.console.print(f"[red]Error connecting to server: {e}[/red]")

    def run(self, host, port):
        """Main loop to display live data"""
        self.connect(host, port)
        with Live(refresh_per_second=self.refresh_rate) as live:
            while True:
                try:
                    data = self.socket.recv(4096).decode('utf-8')
                    if not data:
                        break

                    self.buffer += data
                    while '\n' in self.buffer:
                        line, self.buffer = self.buffer.split('\n', 1)
                        print(line)  # Display raw data for now

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
                    continue

        self.socket.close()