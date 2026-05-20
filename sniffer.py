
# CodeAlpha Internship Project

from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

# This function runs every time a packet is caught
def show_packet(packet):

    # Only process packets that have an IP layer
    if IP in packet:
        
        src = packet[IP].src
        dst = packet[IP].dst
        time = datetime.datetime.now().strftime("%H:%M:%S")

        print("\n----------------------------")
        print(f"  Time     : {time}")
        print(f"  From     : {src}")
        print(f"  To       : {dst}")

        # Check what type of packet it is
        if TCP in packet:
            print(f"  Type     : TCP")
            print(f"  Port     : {packet[TCP].sport} --> {packet[TCP].dport}")

        elif UDP in packet:
            print(f"  Type     : UDP")
            print(f"  Port     : {packet[UDP].sport} --> {packet[UDP].dport}")

        elif ICMP in packet:
            print(f"  Type     : ICMP (Ping)")

        print("----------------------------")

# Start capturing packets
print("Starting network sniffer...")
print("Capturing 20 packets. Please wait...\n")

sniff(prn=show_packet, store=0, count=20)

print("\nDone! 20 packets captured.")