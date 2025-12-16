# Contributions

## Kismat Kunwar

- **Project Setup**: Initial structure, modular design, virtual environment
- **CLI**: Argument parsing (`-t`, `-x`, `-o`, `--scan-type`, `--no-prompt`)
- **DNS Safety Feature**: Confirmation prompt with DNS server display
- **Host Discovery**: CIDR expansion, target/exclusion parsing
- **Nmap Integration**: Handler enhancements, scan type modes (default/quick/full/udp)
- **SMB Enumeration**: Handler and parser for enum4linux-ng integration
- **NetBIOS Enumeration**: Handler and parser using nmblookup
- **AD Enumeration**: LDAP Base DSE queries, DNS SRV lookups, DC detection logic
- **Utilities**: `shell.py`, `tool_checker.py`, `decorators.py`, `validation.py`
- **Bug Fixes**: SMB null session detection, exploit deduplication, NetBIOS rendering

## Gamvirta Poudel

- **Nmap Handler**: Initial implementation of nmap scanning functions
- **SMB Handler**: Initial SMB enumeration implementation
- **OS Detection**: Fingerprinting module and integration
- **Vulnerability Correlation**: searchsploit handler, parser, and query builder
- **AD Enumeration**: SMB security mode parsing, NetBIOS role detection, report section
- **Data Models**: HostResult and ServiceResult with exploit storage
- **Testing**: pytest framework setup, fixtures, 205 unit tests
- **Report Generator**: Markdown output, UTC timestamps, verified/unverified sections
- **UX**: ASCII banner, logging configuration, command output formatting
