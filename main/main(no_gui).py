# Network scanner made with Python. ICMP? 

# Importing necessary libraries
import socket
import subprocess
import ipaddress
import concurrent.futures
import platform
import re
import time
import sys
from typing import List, Dict, Any, Optional, Tuple

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Common IoT device ports to scan
COMMON_PORTS = [
    22,    # SSH
    23,    # Telnet
    80,    # HTTP
    443,   # HTTPS
    554,   # RTSP (cameras)
    1883,  # MQTT
    8080,  # Alternative HTTP
    8443,  # Alternative HTTPS
    8883,  # Secure MQTT
    9000   # Common IoT web interface
]

# Common IoT vulnerabilities to check
VULNERABILITIES = [
    {
        "name": "Telnet Enabled",
        "description": "Telnet is an unencrypted protocol that can expose credentials and commands.",
        "severity": "High",
        "check": lambda ports, banners: 23 in ports,
        "port": 23,
        "recommendation": "Disable Telnet and use SSH instead."
    },
    {
        "name": "HTTP Without HTTPS",
        "description": "Device offers HTTP service without secure HTTPS alternative.",
        "severity": "Medium",
        "check": lambda ports, banners: 80 in ports and 443 not in ports,
        "port": 80,
        "recommendation": "Enable HTTPS and redirect HTTP to HTTPS."
    },
    {
        "name": "Default Credentials in Banner",
        "description": "Device may be exposing default credentials in service banners.",
        "severity": "Critical",
        "check": lambda ports, banners: any("default" in banner.lower() and "password" in banner.lower() for banner in banners.values()),
        "port": "Multiple",
        "recommendation": "Change default passwords immediately."
    }
]

def print_banner():
    """Print the tool banner"""
    banner = f"""
{Colors.BLUE}╔═══════════════════════════════════════════════════════════╗
║ {Colors.YELLOW}Network IoT Security Scanner{Colors.BLUE}                             ║
║ {Colors.GREEN}A tool for identifying vulnerable IoT devices{Colors.BLUE}             ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)
    print(f"{Colors.RED}{Colors.BOLD}IMPORTANT: This tool should only be used on networks you own or have permission to scan.{Colors.ENDC}\n")

def get_local_ip() -> str:
    """Get the local IP address of the machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_range(ip: str, cidr: int = 24) -> List[str]:
    """Convert IP and CIDR to a list of IPs in that range"""
    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
    return [str(ip) for ip in network.hosts()]

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open on the target IP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def get_service_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to get service banner from the specified port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send a generic request to trigger a response
        if port == 80 or port == 8080:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 23 or port == 22:
            # Just wait for the banner
            pass
        else:
            sock.send(b"\r\n")
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except:
        return ""

def get_hostname(ip: str) -> str:
    """Try to get the hostname of the IP address"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_mac_address(ip: str) -> Tuple[str, str]:
    """Try to get the MAC address of the IP using ARP"""
    mac = "Unknown"
    vendor = "Unknown"
    
    os_type = platform.system().lower()
    
    try:
        if os_type == "windows":
            # Windows
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
            matches = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
            if matches:
                mac = matches.group(1)
        else:
            # Linux/Mac
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
            matches = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", output)
            if matches:
                mac = matches.group(1)
                
        # In a real implementation, you would look up the vendor from the MAC OUI
        # For simplicity, we'll just use the first 3 octets
        if mac != "Unknown":
            vendor = f"Vendor-{mac.split(':')[0:3]}"
    except:
        pass
        
    return mac, vendor

def determine_device_type(open_ports: List[int]) -> str:
    """Determine the likely device type based on open ports"""
    if 554 in open_ports:
        return "IP Camera"
    elif 1883 in open_ports or 8883 in open_ports:
        return "IoT Hub/Gateway"
    elif 80 in open_ports or 443 in open_ports:
        return "Web-enabled Device"
    elif 23 in open_ports:
        return "Telnet-enabled Device"
    elif 22 in open_ports:
        return "SSH-enabled Device"
    else:
        return "Unknown IoT Device"

def check_vulnerabilities(open_ports: List[int], banners: Dict[int, str]) -> List[Dict[str, Any]]:
    """Check for vulnerabilities based on open ports and service banners"""
    vulnerabilities = []
    
    for vuln in VULNERABILITIES:
        if vuln["check"](open_ports, banners):
            vulnerabilities.append({
                "name": vuln["name"],
                "description": vuln["description"],
                "severity": vuln["severity"],
                "port": vuln["port"],
                "recommendation": vuln["recommendation"]
            })
            
    return vulnerabilities

def scan_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Scan a single IP address for IoT devices and vulnerabilities"""
    print(f"Scanning {ip}...", end="\r")
    
    # Check which ports are open
    open_ports = []
    for port in COMMON_PORTS:
        if is_port_open(ip, port):
            open_ports.append(port)
    
    if not open_ports:
        return None
    
    # Get service banners
    banners = {}
    for port in open_ports:
        banner = get_service_banner(ip, port)
        if banner:
            banners[port] = banner
    
    # Get hostname
    hostname = get_hostname(ip)
    
    # Get MAC address and vendor
    mac, vendor = get_mac_address(ip)
    
    # Determine device type
    device_type = determine_device_type(open_ports)
    
    # Check for vulnerabilities
    vulnerabilities = check_vulnerabilities(open_ports, banners)
    
    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "device_type": device_type,
        "open_ports": open_ports,
        "banners": banners,
        "vulnerabilities": vulnerabilities
    }

def scan_network(ip_range: str) -> List[Dict[str, Any]]:
    """Scan a network range for IoT devices and vulnerabilities"""
    try:
        # Parse the IP range (e.g., 192.168.1.0/24)
        if "/" in ip_range:
            ip, cidr = ip_range.split("/")
            ips = get_network_range(ip, int(cidr))
        else:
            # Single IP
            ips = [ip_range]
        
        results = []
        total_ips = len(ips)
        
        print(f"Starting scan of {total_ips} IP addresses...")
        start_time = time.time()
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(scan_ip, ip): ip for ip in ips}
            completed = 0
            
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                progress = (completed / total_ips) * 100
                print(f"Progress: {progress:.1f}% ({completed}/{total_ips})", end="\r")
                
                result = future.result()
                if result:
                    results.append(result)
        
        duration = time.time() - start_time
        print(f"\nScan completed in {duration:.2f} seconds. Found {len(results)} devices.")
        
        return results
    
    except Exception as e:
        print(f"Error scanning network: {str(e)}")
        return []

def print_device_info(device: Dict[str, Any]):
    """Print information about a discovered device"""
    vuln_count = len(device["vulnerabilities"])
    if vuln_count > 0:
        status = f"{Colors.RED}Vulnerable ({vuln_count}){Colors.ENDC}"
    else:
        status = f"{Colors.GREEN}Secure{Colors.ENDC}"
    
    print(f"\n{Colors.BOLD}{device['ip']}{Colors.ENDC} - {status}")
    print(f"  Hostname: {device['hostname']}")
    print(f"  MAC: {device['mac']}")
    print(f"  Vendor: {device['vendor']}")
    print(f"  Device Type: {device['device_type']}")
    print(f"  Open Ports: {', '.join(map(str, device['open_ports']))}")
    
    if device["vulnerabilities"]:
        print(f"\n  {Colors.YELLOW}{Colors.BOLD}Vulnerabilities:{Colors.ENDC}")
        for vuln in device["vulnerabilities"]:
            severity_color = Colors.RED if vuln["severity"] == "Critical" else Colors.YELLOW if vuln["severity"] == "High" else Colors.BLUE
            print(f"    - {Colors.BOLD}{vuln['name']}{Colors.ENDC} ({severity_color}{vuln['severity']}{Colors.ENDC})")
            print(f"      {vuln['description']}")
            print(f"      Port: {vuln['port']}")
            print(f"      Recommendation: {vuln['recommendation']}")

def main():
    """Main function to run the scanner"""
    print_banner()
    
    # Get the local IP to suggest a default scan range
    local_ip = get_local_ip()
    default_range = ".".join(local_ip.split(".")[:3]) + ".0/24"
    
    print(f"Your IP address appears to be: {local_ip}")
    ip_range = input(f"Enter IP range to scan [default: {default_range}]: ").strip()
    
    if not ip_range:
        ip_range = default_range
    
    print("\nStarting scan. This may take a few minutes depending on the network size...")
    results = scan_network(ip_range)
    
    if not results:
        print("No devices found or all devices are secure.")
        return
    
    # Count vulnerabilities
    total_vulns = sum(len(device["vulnerabilities"]) for device in results)
    vulnerable_devices = sum(1 for device in results if device["vulnerabilities"])
    
    print(f"\n{Colors.BOLD}Scan Summary:{Colors.ENDC}")
    print(f"  Total devices found: {len(results)}")
    print(f"  Vulnerable devices: {vulnerable_devices}")
    print(f"  Total vulnerabilities: {total_vulns}")
    
    # Print detailed results
    print(f"\n{Colors.BOLD}Detailed Results:{Colors.ENDC}")
    for device in results:
        print_device_info(device)
    
    print(f"\n{Colors.BOLD}Scan completed.{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)