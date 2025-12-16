# Contributions

## Kismat Kunwar

- **Project Setup**: Initial structure, modular design, virtual environment
- **CLI**: Argument parsing (`-t`, `-x`, `-o`, `--scan-type`, `--no-prompt`)
- **Host Discovery**: CIDR expansion, target/exclusion parsing
- **Nmap Handler**: Initial implementation of nmap scanning functions
- **Nmap Integration**: Handler enhancements, scan type modes (default/quick/full/udp)
- **SMB Enumeration**: Handler and parser for enum4linux-ng integration
- **AD Enumeration**: LDAP Base DSE queries, DNS SRV lookups, DC detection logic
- **Utilities**: `shell.py`, `tool_checker.py`, `decorators.py`, `validation.py`


## Gamvirta Poudel

- **OS Detection**: Fingerprinting module and integration
- **DNS Safety Feature**: Confirmation prompt with DNS server display
- **SMB Handler**: Initial SMB enumeration implementation
- **NetBIOS Enumeration**: Handler and parser using nmblookup
- **AD Enumeration**: SMB security mode parsing, NetBIOS role detection, report section
- **Data Models**: HostResult and ServiceResult with exploit storage
- **Testing**: pytest framework setup, fixtures, 205 unit tests
- **UX**: ASCII banner, logging configuration, command output formatting

## Both

- **Report Generator**: Markdown output, UTC timestamps, verified/unverified sections

## outofscope

- **Vulnerability Correlation**: searchsploit handler, parser, and query builder



