#!/usr/bin/env python3
import scapy.all as scapy
import subprocess

# Global variable for interface name
interface = "wlan0"  # Replace with your network interface name (e.g., wlan0, wlan1)

# Function to enable monitor mode
def enable_monitor_mode(interface):
    try:
        # Bring the interface down
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        # Set the interface to monitor mode
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "monitor"], check=True)
        # Bring the interface back up
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"Monitor mode enabled on {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Error enabling monitor mode: {e}")
        exit(1)

# Function to revert to managed mode (normal mode)
def disable_monitor_mode(interface):
    try:
        # Bring the interface down
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        # Set the interface to managed mode
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "managed"], check=True)
        # Bring the interface back up
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"Monitor mode disabled, interface reverted to managed mode on {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Error disabling monitor mode: {e}")

# Capturing: SSID, Signal Strength, and Encryption Types (e.g. WEP, WPA2/WPA3)
def packet_handler(pkt):
    if pkt.haslayer(scapy.Dot11Beacon):  # Check for Beacon Frames
        # This retrieves the SSID from the frame
        ssid = pkt[scapy.Dot11Elt].info.decode() if pkt[scapy.Dot11Elt].info else "Hidden"

        # This gets the signal strength in dBm (decibels)
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -100

        # Default encryption type for no encryption
        encryption_type = "Open"

        # Check if WPA/WPA2/WPA3 encryption is in the frame's information
        if pkt.haslayer(scapy.Dot11Elt) and pkt[scapy.Dot11Elt].ID == 48:  # WPA/WPA2/WPA3
            encryption_type = "WPA2/WPA3"
        elif pkt.haslayer(scapy.Dot11WEP):
            encryption_type = "WEP"

        print(f"SSID: {ssid}, Signal Strength: {signal_strength} dBm, Encryption: {encryption_type}")

# Function to listen for packets on wlan0 interface
def sniff_packets():
    enable_monitor_mode(interface)  # Enable monitor mode

    # Capture the packets
    scapy.sniff(iface=interface, prn=packet_handler, store=0, timeout=10)  # Capture for 10 seconds

    disable_monitor_mode(interface)  # Revert back to managed mode when done

# Main function to run the script
if __name__ == "__main__":
    sniff_packets()
