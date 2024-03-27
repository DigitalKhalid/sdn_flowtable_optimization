from scapy.all import Ether, IP, TCP, Raw, ICMP
import pandas as pd
import random
import warnings
from vn_settings import *


warnings.filterwarnings("ignore")

def load_trace_file():
    packets = pd.read_csv(TRACE_FILE)

    return packets


def gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size):
    # Generate packet
    packet = Ether(type=0x0800) / IP(src=src_ip, dst=dst_ip, proto=protocol) / TCP(sport=src_port, dport=dst_port) / ICMP()

    # Create a packet with padding to achieve the desired size
    padding_size = pkt_size - len(packet)
    padding_size = padding_size if padding_size > 0 else 0
    padding = b'\x00' * padding_size

    packet = packet / Raw(load=padding)
   
    return packet, padding_size


def get_packet_random(packets, host_ips):
    # Generate a random index within the range of available packets
    random_index = random.randint(0, len(packets) - 1)

    # Get the random packet at the generated index
    packet_info = packets.iloc[random_index]

    protocol = packet_info[5]
    src_port = packet_info[3]
    dst_port = packet_info[4]
    pkt_size = packet_info[6]

    random_ips = random.sample(host_ips, 2)
    src_ip = random_ips[0]
    dst_ip = random_ips[1]
    
    packet, data_load = gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size)

    return packet, data_load, 'random'


def get_packet_sequential(packets, host_ips, packet_count):
    # Get the random packet at the generated index
    packet_info = packets.iloc[packet_count]

    protocol = packet_info[5]
    src_port = packet_info[3]
    dst_port = packet_info[4]
    pkt_size = packet_info[6]

    random_ips = random.sample(host_ips, 2)
    src_ip = random_ips[0]
    dst_ip = random_ips[1]
    
    packet, data_load = gen_packet(src_ip, dst_ip, src_port, dst_port, protocol, pkt_size)

    return packet, data_load, 'sequential'


if __name__ == '__main__':
    host_ips = [
        '10.0.0.1',
        '10.0.0.2',
        '10.0.0.3',
        '10.0.0.4',
        '10.0.0.5',
    ]

    packets = load_trace_file()
    packet = get_packet_random(packets, host_ips)

    # Access packet information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    # Print packet information
    print("Source IP:", src_ip)
    print("Destination IP:", dst_ip)
    print("Source Port:", src_port)
    print("Destination Port:", dst_port)
    print("Protocol:", protocol)
    print("Packet Size:", pkt_size)
    print(packet)
