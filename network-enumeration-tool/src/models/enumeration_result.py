class EnumerationResult:
    def __init__(self):
        self.hosts = {}
        self.services = {}
        self.vulnerabilities = []

    def add_host(self, ip_address, host_data):
        self.hosts[ip_address] = host_data

    def add_service(self, ip_address, service_data):
        if ip_address not in self.services:
            self.services[ip_address] = []
        self.services[ip_address].append(service_data)

    def add_vulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)

    def generate_report(self):
        report = {
            "hosts": self.hosts,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities
        }
        return report