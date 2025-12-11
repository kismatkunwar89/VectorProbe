import re
import ipaddress

def validate_ip(ip):
    """Validate an IPv4 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_cidr(cidr):
    """Validate a CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_dns_record(dns_record):
    """Validate a DNS record format."""
    dns_regex = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
    return re.match(dns_regex, dns_record) is not None

def validate_excluded_hosts(excluded_hosts):
    """Validate a list of excluded hosts."""
    hosts = excluded_hosts.split(',')
    for host in hosts:
        host = host.strip()
        if not (validate_ip(host) or validate_dns_record(host) or validate_cidr(host)):
            return False
    return True