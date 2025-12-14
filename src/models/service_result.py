
class ServiceResult:
    """
    Represents a discovered network service on a host.
    """

    def __init__(
        self,
        ip_address,
        service_name,
        port,
        protocol,
        os_type=None,
        additional_info=None,
        exploits=None,  
    ):
        self.ip_address = ip_address
        self.service_name = service_name
        self.port = port
        self.protocol = protocol
        self.os_type = os_type
        self.additional_info = additional_info or {}

        #Store correlated vulnerabilities (Searchsploit results)
        self.exploits = exploits or []

    def to_dict(self):
        """
        Convert service result to dictionary (used for reporting).
        """
        return {
            "ip_address": self.ip_address,
            "service_name": self.service_name,
            "port": self.port,
            "protocol": self.protocol,
            "os_type": self.os_type,
            "additional_info": self.additional_info,
            "exploits": self.exploits, 
        }

    def __repr__(self):
        return (
            f"<ServiceResult("
            f"ip_address={self.ip_address}, "
            f"service_name={self.service_name}, "
            f"port={self.port}, "
            f"protocol={self.protocol}"
            f")>"
        )
