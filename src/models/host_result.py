"""
Host Result Data Model

This module defines the HostResult class, which stores all information
about a single network host discovered during enumeration.
"""


class HostResult:
    """
    Represents a single network host and all discovered information about it.

    This class acts as a container for all data gathered about a host,
    including verified info, unverified info, and raw command outputs.

    Attributes:
        ip_address (str): The IP address of the host (required)
        hostname (str): The hostname/DNS name (optional)
        domain (str): The domain name if AD-joined (optional)
        os_type (str): Operating system type (Windows/Linux/Unix/Unknown)
        services (list): List of discovered services
        windows_info (dict): Windows-specific information (SMB, NetBIOS, etc.)
        unverified_info (list): Probable but unconfirmed details
        command_outputs (list): Raw output from all commands executed
    """

    def __init__(self, ip_address, hostname=None, domain=None, os_type=None, services=None):
        """
        Initialize a new HostResult object.

        Args:
            ip_address (str): The IP address (required)
            hostname (str, optional): The hostname. Defaults to None.
            domain (str, optional): The domain name. Defaults to None.
            os_type (str, optional): Operating system type. Defaults to None.
            services (list, optional): List of services. Defaults to empty list.

        Example:
            >>> host = HostResult("192.168.1.100", hostname="server1.local")
            >>> host.add_service("HTTP", 80, "TCP")
        """
        # Basic host information
        self.ip_address = ip_address
        self.hostname = hostname
        self.domain = domain
        self.os_type = os_type
        self.services = services if services is not None else []

        # Windows-specific information (empty dict by default)
        self.windows_info = {
            'netbios_name': None,
            'workgroup': None,
            'smb_version': None,
            'smb_shares': [],
            'ad_info': None
        }

        # Unverified information (list of probable details)
        self.unverified_info = []

        # Raw command outputs (list of dictionaries)
        # Each entry: {'command': 'nmap -sV ...', 'output': '...'}
        self.command_outputs = []

    def add_service(self, service_name, port, protocol,
                    state=None, product=None, version=None,
                    exploits=None):
        """
        Add a discovered service to this host.

        Args:
            service_name (str): Name of the service (e.g., "HTTP", "SSH")
            port (int): Port number (e.g., 80, 22)
            protocol (str): Protocol type (e.g., "TCP", "UDP")

        Example:
            >>> host.add_service("HTTP", 80, "TCP")
            >>> host.add_service("DNS", 53, "UDP")
        """
        service_info = {
            'service_name': service_name,
            'port': port,
            'protocol': protocol
        }

        if state:
            service_info['state'] = state
        if product:
            service_info['product'] = product
        if version:
            service_info['version'] = version

        service_info['exploits'] = exploits or []
        self.services.append(service_info)

    def add_unverified_info(self, info):
        """
        Add unverified but probable information about the host.

        Args:
            info (str): Unverified information string

        Example:
            >>> host.add_unverified_info("OS version likely Windows Server 2012 R2 or newer")
        """
        self.unverified_info.append(info)

    def add_command_output(self, command, output):
        """
        Store the raw output from a command executed against this host.

        Args:
            command (str): The command that was executed
            output (str): The raw text output from the command

        Example:
            >>> host.add_command_output("nmap -sV 192.168.1.100", "Starting Nmap...")
        """
        self.command_outputs.append({
            'command': command,
            'output': output
        })

    def set_windows_info(self, **kwargs):
        """
        Set Windows-specific information.

        Args:
            **kwargs: Keyword arguments for Windows info fields
                     (netbios_name, workgroup, smb_version, etc.)

        Example:
            >>> host.set_windows_info(netbios_name="SERVER1", workgroup="WORKGROUP")
        """
        for key, value in kwargs.items():
            if key in self.windows_info:
                self.windows_info[key] = value

    def to_markdown(self):
        """
        Convert this host's information to Markdown format.

        This generates a formatted section for the final report,
        including verified info table, unverified info, and command outputs.

        Returns:
            str: Markdown-formatted string

        Example:
            >>> print(host.to_markdown())
        """
        markdown = f"## Host: {self.ip_address}\n\n"

        # Verified Information Table
        markdown += "### Verified Information\n\n"
        markdown += "| Field | Value |\n"
        markdown += "|-------|-------|\n"
        markdown += f"| IP Address | {self.ip_address} |\n"
        markdown += f"| Hostname | {self.hostname or 'N/A'} |\n"
        markdown += f"| Domain | {self.domain or 'N/A'} |\n"
        markdown += f"| Operating System | {self.os_type or 'Unknown'} |\n"

        # Services
        if self.services:
            services_str = "<br>".join([
                f"{s['service_name']} ({s['protocol']}/{s['port']})"
                for s in self.services
            ])
            markdown += f"| Active Services | {services_str} |\n"
        else:
            markdown += "| Active Services | None detected |\n"

        markdown += "\n"

        # Unverified Information Section
        if self.unverified_info:
            markdown += "### Unverified Information\n\n"
            for info in self.unverified_info:
                markdown += f"- {info}\n"
            markdown += "\n"

        # Command Outputs Section
        if self.command_outputs:
            markdown += "### Command Outputs\n\n"
            for cmd_output in self.command_outputs:
                markdown += f"**Command:** `{cmd_output['command']}`\n\n"
                markdown += "```\n"
                markdown += cmd_output['output']
                markdown += "\n```\n\n"

        return markdown
