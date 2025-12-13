class ServiceResult:
    def __init__(self, ip_address, service_name, port, protocol, os_type=None, additional_info=None):
        self.ip_address = ip_address
        self.service_name = service_name
        self.port = port
        self.protocol = protocol
        self.os_type = os_type
        self.additional_info = additional_info or {}

    def to_dict(self):
        return {
            "ip_address": self.ip_address,
            "service_name": self.service_name,
            "port": self.port,
            "protocol": self.protocol,
            "os_type": self.os_type,
            "additional_info": self.additional_info,
        }

    def __repr__(self):
        return f"<ServiceResult(ip_address={self.ip_address}, service_name={self.service_name}, port={self.port}, protocol={self.protocol})>"