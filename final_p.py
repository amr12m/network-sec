from scapy.all import *
from scapy.all import sniff
import socket
import struct
import psutil

def get_network_interface():
    interfaces = psutil.net_if_addrs().keys()
    for interface in interfaces:
        if "Loopback" not in interface:
            return interface

def sniff_traffic(packet, target_ip):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if dst_ip == target_ip:
            if protocol == 6 and packet.haslayer(TCP):  # TCP
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"Detected TCP packet: Source IP - {src_ip}, Source Port - {src_port}, Destination IP - {dst_ip}, Destination Port - {dst_port}")
                print(packet.summary())  # Print entire packet summary
                print(packet.show())  # Print detailed packet fields
            elif protocol == 17 and packet.haslayer(UDP):  # UDP
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"Detected UDP packet: Source IP - {src_ip}, Source Port - {src_port}, Destination IP - {dst_ip}, Destination Port - {dst_port}")
                print(packet.summary())
                print(packet.show())
            elif protocol == 1 and packet.haslayer(ICMP):  # ICMP
                print(f"Detected ICMP packet: Source IP - {src_ip}, Destination IP - {dst_ip}")
                print(packet.summary())
                print(packet.show())
            else:
                print(f"Detected IP packet with unknown protocol ({protocol}): Source IP - {src_ip}, Destination IP - {dst_ip}")
                print(packet.summary())
                print(packet.show())


def get_local_ips(network):
    # Create ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    # Send and receive ARP packets
    result = srp(arp_request, timeout=3, verbose=1)[0]
    
    #  and the second element is the response or the answer associated with that packet.
    IPs_in_network = []
    for i in result:
        IPs_in_network.append(i[1].psrc)

    return IPs_in_network


if __name__ == "__main__":

    subnet="192.168.1.0/24"
    local_ips = get_local_ips(subnet)
    print("IP addresses in the local network:")
    for ip in local_ips:
        print(ip)
#-------------------------------------------------------------------------------------#

#-------------------------------------------------------------------------------------#
    # Automatically detect network interface
# Replace 'target_ip_to_sniff' with the specific IP address you want to target
    target_ip_to_sniff = input()

    # Start sniffing packets
    sniff(prn=lambda x: sniff_traffic(x, target_ip_to_sniff), store=False)
