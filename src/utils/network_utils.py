import os
import socket
import ipaddress

def get_hostname(ip):
    """Return the hostname for a given IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def ping_host(ip):
    """Ping a host to check if it is reachable."""
    response = os.system(f"ping -c 1 {ip}")
    return response == 0

def get_local_ip():
    """Return the local IP address of the machine."""
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)