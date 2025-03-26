# IoT Security Scanner

A network security tool for identifying and assessing vulnerabilities in IoT devices on local networks.

## Overview

This tool scans your network to discover connected devices, identify potential IoT devices, check for common security vulnerabilities, and provide a risk assessment report. It's designed to help users identify security issues in their IoT infrastructure.

## Features

- **Device Discovery**: Automatically finds devices on your local network
- **IoT Identification**: Recognizes IoT devices using vendor identification
- **Port Scanning**: Detects open ports and potentially vulnerable services
- **Vulnerability Assessment**: Identifies common security issues such as:
  - Telnet enabled
  - Unencrypted HTTP
  - UPnP services
  - Non-standard HTTP ports
- **Risk Assessment**: Assigns risk scores to prioritize remediation efforts
- **Reporting**: Generates detailed security reports for documentation

## Installation

```bash
# Clone the repository
git clone https://github.com/YashKantheti/simple-iot-scanner.git

# Navigate to the directory
cd simple-iot-scanner

# Run the scanner (requires admin privileges)
sudo python3 main.py
```

## Quick Start

One-command execution:
```bash
curl -s https://raw.githubusercontent.com/YashKantheti/simple-iot-scanner/main/run.sh | bash
```

## Usage Options

```bash
# Run with default settings
sudo python3 main.py

# Specify a different IP address/network
sudo python3 main.py --ip 192.168.0.1

# Custom output filename
sudo python3 main.py --output custom_report.json
```

## Example Output

```
=== IoT SECURITY SCAN RESULTS ===
+---------------+-------------+-----------+------------+------------------+----------------+
| IP            | Hostname    | Vendor    | Risk Score | Open Ports       | Vulnerabilities|
+---------------+-------------+-----------+------------+------------------+----------------+
| 192.168.1.15  | device-a    | Vendor-A  | 7          | 80, 23, 1900     | 3 issues       |
| 192.168.1.22  | device-b    | Vendor-B  | 5          | 80, 8080         | 2 issues       |
+---------------+-------------+-----------+------------+------------------+----------------+
```

## Security Considerations

This tool performs network scanning operations that require administrative privileges. It's designed for use on networks you own or have permission to scan.

## Requirements

- Python 3.6+
- Network admin privileges
- Dependencies (automatically installed):
  - prettytable

## Future Enhancements

- Default credential testing
- Firmware version checking
- Web-based reporting dashboard
- Network segmentation recommendations

## License

MIT License

## Contact

- GitHub: @YashKantheti
