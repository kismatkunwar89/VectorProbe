# User Guide for Network Enumeration Tool

## Introduction

The Network Enumeration Tool is designed to automate the discovery and documentation of network hosts, services, and vulnerabilities. This guide provides detailed instructions on how to use the tool effectively.

## Installation

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd network-enumeration-tool
   ```

2. **Set up a virtual environment:**
   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

## Usage

### Running the Tool

To run the network enumeration tool, use the following command:

```
python src/main.py [options] <targets>
```

### Command-Line Options

- **-h, --help**: Display help information and usage examples.
- **-o <path>**: Override the default output file name and location.
- **<targets>**: Specify the target hosts. This can include:
  - Individual IPv4 addresses (e.g., 192.168.1.1)
  - DNS records (e.g., server.example.com)
  - Subnets in CIDR notation (e.g., 192.168.1.0/24)
  - Comma-separated lists of any combination of the above

### Excluding Hosts

To exclude specific hosts from the enumeration, use the following format:

```
--exclude <excluded_targets>
```

Where `<excluded_targets>` can be specified in the same formats as the targets.

### DNS Safety Feature

When providing DNS records, the tool will:
- Display the currently configured DNS server.
- Prompt for confirmation before proceeding. Default is "No" if no input is provided.

## Report Generation

The tool generates a report in Markdown format, which includes:

1. **Verified Information Table**: Contains details such as IP Address, Hostname, Domain, Active Services, and Operating System Type.
2. **Unverified Information Section**: Lists probable but unconfirmed details and potential vulnerabilities.
3. **Command Outputs Section**: Displays commands executed and their raw outputs.

The report is saved in the current working directory with the default naming format:
```
host_enumeration_report_YYYYMMDD_HHMM_UTC.md
```

## Examples

### Basic Usage Example

To enumerate a single host:

```
python src/main.py 192.168.1.1
```

### Excluding Hosts Example

To enumerate a subnet while excluding specific hosts:

```
python src/main.py 192.168.1.0/24 --exclude 192.168.1.5,192.168.1.10
```

## Conclusion

This user guide provides an overview of how to use the Network Enumeration Tool effectively. For further assistance, please refer to the README.md or contact the project maintainers.