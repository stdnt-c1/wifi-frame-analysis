#!/usr/bin/env python3
"""
Network WiFi Frame Analyzer Display Script
Displays captured frames from Ubuntu machine in a live CLI table format
"""

import socket
import sys
from datetime import datetime
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich import box
import argparse
import json
from pathlib import Path

class FrameAnalyzer:
    def __init__(self, host, port=5000, log_file=None, filter_type=None, refresh_rate=4):
        self.console = Console()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
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

    def connect(self):
        """Connect to the Ubuntu capture server"""
        try:
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            self.console.print(f"[red]Error connecting to server: {e}[/red]")
            return False

    def update_stats(self, stats_str):
        """Update statistics from capture server stats string"""
        values = stats_str.split(',')
        if len(values) == 11:
            keys = list(self.stats.keys())
            self.stats = dict(zip(keys, map(int, values)))

    def add_frame(self, frame_data):
        """Add a new frame to recent frames list"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.recent_frames.append((timestamp, frame_data))
        if len(self.recent_frames) > self.max_recent:
            self.recent_frames.pop(0)

    def generate_table(self) -> Table:
        """Generate rich table with current data"""
        table = Table(box=box.ROUNDED, title="Live Frame Data")
        
        # Add columns
        table.add_column("Time", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("RSSI", justify="right", style="yellow")
        table.add_column("Source MAC", style="blue")
        table.add_column("Dest MAC", style="magenta")
        table.add_column("SSID", style="red")

        # Add recent frames
        for timestamp, frame in self.recent_frames:
            if self.filter_type and frame['type'] != self.filter_type:
                continue
            ssid = frame.get('SSID', '')
            table.add_row(
                timestamp,
                frame['type'],
                frame['rssi'],
                frame['src'],
                frame['dst'],
                ssid
            )

        # Add statistics
        stats_table = Table(title="Statistics", box=box.SIMPLE)
        stats_table.add_column("Frame Type", style="cyan")
        stats_table.add_column("Count", justify="right", style="green")
        
        for frame_type, count in self.stats.items():
            stats_table.add_row(frame_type, str(count))

        return table, stats_table

    def parse_frame(self, line):
        """Parse a frame line from capture server"""
        try:
            if line.startswith('START|'):
                self.console.print("[green]Connected to Ubuntu Frame Capture Server[/green]")
                return None

            if line.startswith('STATS|'):
                self.update_stats(line.split('|')[1])
                return None

            # Parse frame data
            parts = line.strip('[]').split('] ')
            if len(parts) < 2:
                return None

            frame_type = parts[0]
            details = {}
            for item in parts[1].split(' '):
                if ':' in item:
                    key, value = item.split(':', 1)
                    details[key] = value.strip('"')

            frame_data = {
                'type': frame_type,
                'rssi': details.get('RSSI', 'N/A'),
                'src': details.get('SRC', 'N/A'),
                'dst': details.get('DST', 'N/A')
            }

            if 'SSID' in details:
                frame_data['SSID'] = details['SSID']

            return frame_data

        except Exception as e:
            self.console.print(f"[red]Error parsing frame: {e}[/red]")
            return None

    def run(self):
        """Main loop to display live data"""
        if not self.connect():
            return

        with Live(refresh_per_second=self.refresh_rate) as live:
            while True:
                try:
                    # Receive data from server
                    data = self.socket.recv(4096).decode('utf-8')
                    if not data:
                        break

                    # Process received data
                    self.buffer += data
                    while '\n' in self.buffer:
                        line, self.buffer = self.buffer.split('\n', 1)
                        
                        # Log raw data if requested
                        if self.log_file:
                            with open(self.log_file, 'a') as f:
                                f.write(f"{datetime.now().isoformat()}: {line}\n")

                        frame_data = self.parse_frame(line.strip())
                        if frame_data:
                            self.add_frame(frame_data)

                    # Update display
                    main_table, stats_table = self.generate_table()
                    live.update(main_table)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
                    continue

        self.socket.close()

def main():
    parser = argparse.ArgumentParser(description='Network WiFi Frame Analyzer Display')
    parser.add_argument('host', help='Ubuntu capture server IP address')
    parser.add_argument('--port', type=int, default=5000, help='Server port (default: 5000)')
    parser.add_argument('--log', help='Log file path for raw data')
    parser.add_argument('--filter', help='Filter by frame type (e.g., BEACON, PROBE_REQ)')
    parser.add_argument('--refresh', type=int, default=4, help='Refresh rate for live display (default: 4 Hz)')
    
    args = parser.parse_args()

    if args.log:
        log_path = Path(args.log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    analyzer = FrameAnalyzer(args.host, args.port, args.log, args.filter, args.refresh)
    analyzer.run()

if __name__ == '__main__':
    main()
