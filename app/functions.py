import ipaddress

def encode_ip(ip_address):
    ip_integer = int(ipaddress.IPv4Address(ip_address))
    return ip_integer

def decode_ip(ip_integer):
    ip_address = ipaddress.IPv4Address(ip_integer)
    return str(ip_address)

def encode_mac(mac_address):
    mac_parts = mac_address.split(':')
    mac_int = int(''.join(mac_parts), 16)
    return mac_int

def decode_mac(mac_integer):
    mac_hex = format(mac_integer, '012x')
    mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))
    return mac_address