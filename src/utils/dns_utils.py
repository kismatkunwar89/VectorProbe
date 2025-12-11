import socket

def resolve_hostname(hostname):
    """Resolve a hostname to an IP address."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error resolving hostname {hostname}: {e}")
        return None

def is_valid_ip(ip):
    """Check if the provided string is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def get_dns_info(domain):
    """Get DNS information for a given domain."""
    try:
        dns_info = socket.gethostbyname_ex(domain)
        return dns_info
    except socket.error as e:
        print(f"Error retrieving DNS info for {domain}: {e}")
        return None