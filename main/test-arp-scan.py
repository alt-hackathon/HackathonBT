# iot_vuln_scanner.py

from scapy.all import ARP, Ether, srp
import nmap

def arp_scan(ip_range):
    print(f"Scanning IP range: {ip_range} with ARP...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def scan_ports(ip):
    print(f"Scanning {ip} for open ports...")
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV --host-timeout 30s')

    if ip in scanner.all_hosts():
        ports_info = scanner[ip]['tcp'] if 'tcp' in scanner[ip] else {}
        return ports_info
    return {}

def analyze_ports(ports_info):
    vulnerabilities = []
    for port, info in ports_info.items():
        service = info.get('name', 'unknown')
        version = info.get('version', '')
        product = info.get('product', '')
        # Simple vulnerability detection
        if 'telnet' in service.lower():
            vulnerabilities.append((port, service, "Insecure protocol (Telnet)"))
        if 'ftp' in service.lower() and "vsftpd 2.3.4" in version:
            vulnerabilities.append((port, service, "Backdoored vsftpd 2.3.4"))
        if 'http' in service.lower() and 'lighttpd' in product.lower() and '1.4.28' in version:
            vulnerabilities.append((port, service, "DoS vulnerability in Lighttpd 1.4.28"))
    return vulnerabilities

def main():
    ip_range = "192.168.1.0/24"  # Update to match your network range
    devices = arp_scan(ip_range)

    if not devices:
        print("No devices found.")
        return

    print(f"\nFound {len(devices)} device(s):")
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        print(f"\nDevice: {ip} ({mac})")
        
        ports_info = scan_ports(ip)
        if ports_info:
            vulnerabilities = analyze_ports(ports_info)
            if vulnerabilities:
                print("⚠️ Vulnerabilities found:")
                for port, service, issue in vulnerabilities:
                    print(f" - Port {port} ({service}): {issue}")
            else:
                print("✅ No known vulnerabilities found.")
        else:
            print("No open ports or host down.")

if __name__ == "__main__":
    main()