import socket

def resolve_hostname(hostname):
    """Resolve a hostname to an IP address."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.error as e:
        print(f"Error resolving hostname {hostname}: {e}")
        return None

def get_dns_info(domain):
    """Get DNS information for a given domain."""
    try:
        dns_info = socket.gethostbyname_ex(domain)
        return dns_info
    except socket.error as e:
        print(f"Error retrieving DNS info for {domain}: {e}")
        return None