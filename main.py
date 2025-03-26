#!/usr/bin/env python3
"""
Simple IoT Security Scanner (Standalone Version)
A beginner-friendly tool to scan your network for IoT devices and basic security issues.
"""

import argparse
import datetime
import json
import socket
import subprocess
import sys
import time

# Try to import required libraries, install if not available
try:
    from prettytable import PrettyTable
except ImportError:
    print("Required packages not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "prettytable"])
    from prettytable import PrettyTable

# Common IoT device ports to check
IOT_PORTS = [80, 443, 8080, 8443, 23, 2323, 22, 1883, 8883, 5683, 1900]

# Common IoT device manufacturers identified by MAC prefixes
IOT_MAC_PREFIXES = {
    "ECF": "Amazon",
    "B82": "Raspberry Pi",
    "001": "Philips",
    "A4C": "Google",
    "F4F": "TP-Link",
    "70E": "Netatmo",
    "74D": "Edimax",
    "949": "Sonos"
}

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        # Create a socket to determine the IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Error determining local IP: {e}")
        return "127.0.0.1"

def scan_network(base_ip):
    """Scan the local network using simple ping commands"""
    print(f"Scanning network for devices...")
    devices = []
    
    # Extract the network prefix from the IP
    ip_parts = base_ip.split('.')
    network_prefix = '.'.join(ip_parts[0:3])
    
    # Ping scan the first 20 addresses (for quicker results)
    for i in range(1, 21):
        target_ip = f"{network_prefix}.{i}"
        print(f"Scanning {target_ip}...", end='\r')
        
        # Skip our own IP
        if target_ip == base_ip:
            continue
        
        # Use ping to check if host is up
        try:
            # Adjust command based on operating system
            if sys.platform.startswith('win'):
                ping_cmd = ['ping', '-n', '1', '-w', '500', target_ip]
            else:
                ping_cmd = ['ping', '-c', '1', '-W', '1', target_ip]
                
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                # If ping successful, add to devices
                hostname = get_hostname(target_ip)
                mac = get_mac_address(target_ip)
                vendor = identify_vendor(mac)
                
                devices.append({
                    'ip': target_ip,
                    'hostname': hostname,
                    'mac': mac,
                    'vendor': vendor,
                    'open_ports': [],
                    'vulnerabilities': []
                })
                print(f"Found device: {target_ip} ({vendor if vendor else 'Unknown'})")
        except Exception as e:
            print(f"Error scanning {target_ip}: {e}")
    
    print(f"Discovered {len(devices)} devices")
    return devices

def get_hostname(ip):
    """Try to get the hostname of a device"""
    try:
        hostname = socket.getfqdn(ip)
        if hostname != ip:
            return hostname
    except:
        pass
    return "Unknown"

def get_mac_address(ip):
    """Try to get the MAC address of a device using ARP"""
    try:
        if sys.platform.startswith('win'):
            # Windows
            result = subprocess.run(['arp', '-a', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if '-' in part:  # Windows ARP shows MAC with dashes
                            return part.replace('-', ':').upper()
        else:
            # Linux/Mac
            result = subprocess.run(['arp', '-n', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part:  # Linux/Mac ARP shows MAC with colons
                            return part.upper()
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
    
    return "Unknown"

def identify_vendor(mac):
    """Identify the device vendor based on MAC address prefix"""
    if mac and mac != "Unknown":
        # Remove colons and take first 3 chars (OUI)
        prefix = mac.replace(':', '')[:3]
        return IOT_MAC_PREFIXES.get(prefix, "Unknown")
    return "Unknown"

def scan_ports(ip, ports=None):
    """Scan for open ports on the target IP"""
    if ports is None:
        ports = IOT_PORTS
    
    print(f"Scanning ports on {ip}...")
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Short timeout for quick results
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    
    return open_ports

def check_vulnerabilities(device):
    """Check for basic vulnerabilities based on open ports"""
    vulnerabilities = []
    open_ports = device['open_ports']
    
    # Check for telnet
    if 23 in open_ports:
        vulnerabilities.append({
            'type': 'Telnet Enabled',
            'severity': 'High',
            'description': 'Telnet uses unencrypted communications which can expose credentials'
        })
    
    # Check for HTTP without HTTPS
    if 80 in open_ports and 443 not in open_ports:
        vulnerabilities.append({
            'type': 'HTTP without HTTPS',
            'severity': 'Medium',
            'description': 'Device has web interface without encryption'
        })
    
    # Check for UPnP
    if 1900 in open_ports:
        vulnerabilities.append({
            'type': 'UPnP Enabled',
            'severity': 'Medium',
            'description': 'Universal Plug and Play can expose the device to attacks'
        })
    
    # Check for non-standard HTTP ports
    if 8080 in open_ports or 8443 in open_ports:
        vulnerabilities.append({
            'type': 'Alternative HTTP Port',
            'severity': 'Low',
            'description': 'Device has web server on non-standard port'
        })
    
    return vulnerabilities

def calculate_risk_score(device):
    """Calculate a simple risk score based on vulnerabilities"""
    score = 0
    
    for vuln in device['vulnerabilities']:
        if vuln['severity'] == 'High':
            score += 3
        elif vuln['severity'] == 'Medium':
            score += 2
        else:
            score += 1
    
    # Add points for suspicious ports
    risky_ports = [23, 2323, 8080]
    for port in device['open_ports']:
        if port in risky_ports:
            score += 1
    
    # Cap at 10
    return min(10, score)

def print_results(devices):
    """Print scan results in a formatted table"""
    if not devices:
        print("No devices found!")
        return
    
    # Create a table for device summary
    table = PrettyTable()
    table.field_names = ["IP", "Hostname", "Vendor", "Risk Score", "Open Ports", "Vulnerabilities"]
    
    for device in sorted(devices, key=lambda d: d.get('risk_score', 0), reverse=True):
        ports_str = ", ".join(str(p) for p in device['open_ports']) if device['open_ports'] else "None"
        vuln_count = len(device['vulnerabilities'])
        vuln_str = f"{vuln_count} issues" if vuln_count > 0 else "None"
        
        table.add_row([
            device['ip'],
            device['hostname'],
            device['vendor'],
            device.get('risk_score', 0),
            ports_str,
            vuln_str
        ])
    
    print("\n=== IoT SECURITY SCAN RESULTS ===")
    print(table)
    
    # Print vulnerability details
    print("\n=== VULNERABILITY DETAILS ===")
    for device in devices:
        if device['vulnerabilities']:
            print(f"\nDevice: {device['ip']} ({device['vendor']})")
            for i, vuln in enumerate(device['vulnerabilities'], 1):
                print(f"  {i}. {vuln['type']} - {vuln['severity']} Risk")
                print(f"     {vuln['description']}")

def save_report(devices, filename="iot_security_report.json"):
    """Save scan results to a JSON file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"{timestamp}_{filename}"
    
    report = {
        "scan_time": timestamp,
        "devices": devices,
        "summary": {
            "total_devices": len(devices),
            "vulnerable_devices": sum(1 for d in devices if d['vulnerabilities']),
            "high_risk_devices": sum(1 for d in devices if d.get('risk_score', 0) >= 7)
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=4)
    
    print(f"\nReport saved to {report_file}")
    return report_file

def main():
    """Main function to run the scanner"""
    parser = argparse.ArgumentParser(description="Simple IoT Security Scanner")
    parser.add_argument("-i", "--ip", help="Target IP address or network (defaults to auto-detection)")
    parser.add_argument("-o", "--output", default="iot_security_report.json", help="Output filename for the report")
    args = parser.parse_args()
    
    print("=== Simple IoT Security Scanner ===")
    print("Scanning your network for potentially vulnerable IoT devices...")
    
    # Get the local IP
    local_ip = args.ip if args.ip else get_local_ip()
    print(f"Using IP address: {local_ip}")
    
    # Scan the network
    devices = scan_network(local_ip)
    
    # Scan each device for open ports and vulnerabilities
    for device in devices:
        # Scan ports
        device['open_ports'] = scan_ports(device['ip'])
        
        # Check vulnerabilities
        device['vulnerabilities'] = check_vulnerabilities(device)
        
        # Calculate risk score
        device['risk_score'] = calculate_risk_score(device)
    
    # Print results
    print_results(devices)
    
    # Save report
    save_report(devices, args.output)
    
    print("\nScan completed!")
    print("Next steps:")
    print("1. Review vulnerable devices")
    print("2. Consider updating firmware on high-risk devices")
    print("3. Disable unnecessary services like Telnet and UPnP")
    print("4. Place IoT devices on a separate network if possible")

if __name__ == "__main__":
    main()
