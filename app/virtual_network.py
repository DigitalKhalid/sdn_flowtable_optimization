from scapy.all import IP, TCP
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import info, setLogLevel
from mininet.link import TCLink
import warnings
import time
import datetime
from packet_injection import load_trace_file, get_packet_random, get_packet_sequential
from topology import SimpleTopology
import random
import csv
from vn_settings import *


warnings.filterwarnings("ignore")
setLogLevel( 'info' )
        
def inject_packets(net, start_time, network_duration, packets, host_ips):
    packet_count = 0

    while time.time() < start_time + network_duration:
        if fixed_injection_time == True:
            time.sleep(pkt_injection_time)
        else:
            pkt_iat = random.uniform(0, pkt_injection_time)
            time.sleep(pkt_iat)

        if pkt_injection_type == 'sequential':
            packet, data_size, injection_order = get_packet_sequential(packets, host_ips, packet_count)

        elif pkt_injection_type == 'random':
            packet, data_size, injection_order = get_packet_random(packets, host_ips)

        packet_count = packet_count + 1
        
        send_packet(net, packet, data_size, host_ips)
        

    return packet_count, injection_order


def send_packet(net, packet, data_size, host_ips):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    protocol = packet[IP].proto
    pkt_size = len(packet)

    proto = '' if protocol == 6 else ' -1' if protocol == 17 else ' -2'
    data_size = f' -d {data_size}' if data_size > 0 else ''

    hostA = net.get(f'h{host_ips.index(src_ip) + 1}')

    cmd = f'hping3 -c 1 -s {src_port} -p {dst_port}{data_size}{proto} {dst_ip}'
    hostA.cmd(cmd)
    
    # Add Log
    log = [time.time(), src_ip, dst_ip, src_port, dst_port, protocol, pkt_size]
    info(f'\nInjection Log: {log}\n')
    add_log(log, injection_log_file)


def add_log(log, log_file):   
    with open(log_file, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


def write_summary(hosts_ips, start_time, packet_count, injection_order):
    summary = open(simulation_summary_file, "w")

    summary.write(f'\nVirtual Network Simulation Summary\n')
    summary.write('\n==============================================================================================================\n')
    summary.write('Network Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write('Virtual Network: Mininet\n')
    summary.write('Controller: Ryu\n')
    summary.write('No. of Switches: 1\n')
    summary.write(f'No. of Hosts: {len(hosts_ips)}\n')
    summary.write(f'Host IP Addresses: {hosts_ips}\n')
    summary.write('\n==============================================================================================================\n')
    summary.write('Packet Injection Overview:\n')
    summary.write('==============================================================================================================\n')
    summary.write(f'Start Time: {get_time(start_time)}\n')
    summary.write(f'End Time: {get_time(time.time())}\n')
    summary.write(f'Total Packets Injected: {packet_count}\n')
    summary.write(f'Packets injected using the packet trace file from the MAWI dataset.\n')
    summary.write(f'The packets injected from the trace file in {injection_order} order.\n')
    summary.close()


def get_time(timestamp):
    datetime_obj = datetime.datetime.fromtimestamp(timestamp)
    dt = datetime_obj.strftime("%d-%m-%Y %H:%M:%S")

    return dt
    

def main(hosts, network_duration, cli=False):
    topo = SimpleTopology(hosts)
    controller = RemoteController('ryu', ip='127.0.0.1', port=6633, protocols="OpenFlow13")
    net = Mininet(topo, controller=controller, link=TCLink)

    # Start the network
    net.start()

    # set host IP addresses
    host_ips = topo.set_ip_addresses(net, hosts)
    info(f'host ips: {host_ips}\n')

    print('Loading packet trace file.....')
    packets = load_trace_file()

    start_time = time.time()

    info(f'Packet injection starts at {datetime.datetime.fromtimestamp(start_time).strftime("%d-%m-%Y %H:%M:%S")}')
    info(f' and will stop at {datetime.datetime.fromtimestamp(start_time + network_duration).strftime("%d-%m-%Y %H:%M:%S")}\n')

    if cli == False:
        columns = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'pkt_size']
        with open(injection_log_file, 'w', newline = '') as logs:
            writer = csv.writer(logs)
            writer.writerow(columns)

        packet_count, injection_order = inject_packets(net, start_time, network_duration, packets, host_ips)

        write_summary(host_ips, start_time, packet_count, injection_order)

        # Stop the network
        net.stop()

    else:
        net.interact()


if __name__ == '__main__':
    main(vn_hosts, vn_duration)