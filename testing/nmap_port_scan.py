import subprocess
import re
from scapy.all import ARP, Ether, srp

# Simple list of known vulnerable/default services
vulnerable_services = {
    'telnet': 'Insecure protocol - credentials sent in plain text',
    'ftp': 'Unencrypted file transfer - vulnerable to sniffing',
    'http': 'Unencrypted web traffic - use HTTPS instead',
    'smb': 'Can be vulnerable to exploits (e.g., EternalBlue)',
    'rdp': 'Common brute-force target',
    'snmp': 'Often misconfigured and exposes sensitive info',
    'ssh': 'Check for weak/default passwords'
}

def get_alive_ips(ip_range):
    print(f"\n[+] Performing ARP scan on {ip_range}...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=2, verbose=0)
    ips = [recv.psrc for _, recv in answered]
    print(f"[+] Found {len(ips)} active devices.")
    return ips

def run_nmap(ip):
    try:
        print(f"\n[+] Scanning {ip} with Nmap...")
        result = subprocess.run(
            ['nmap', '-sS', '-Pn', ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap scan failed for {ip}")
        return ""

def parse_nmap_output(output):
    devices = {}
    current_ip = None

    for line in output.splitlines():
        ip_match = re.search(r"Nmap scan report for ([\d\.]+)", line)
        if ip_match:
            current_ip = ip_match.group(1)
            devices[current_ip] = []
            continue

        port_match = re.match(r"(\d+/tcp)\s+open\s+(\S+)", line)
        if port_match and current_ip:
            port = port_match.group(1)
            service = port_match.group(2)
            devices[current_ip].append((port, service))

    return devices

def check_vulnerabilities(ports):
    vulns = []
    for port, service in ports:
        if service.lower() in vulnerable_services:
            reason = vulnerable_services[service.lower()]
            vulns.append((service, reason))
    return vulns

def display_results(devices):
    print("\nScan Results:\n" + "-"*30)
    for ip, ports in devices.items():
        print(f"\nDevice: {ip}")
        if ports:
            for port, service in ports:
                print(f"  Port: {port}, Service: {service}")
        else:
            print("  No open ports found.")
    for port, service in ports:
        print(f"  Port: {port}, Service: {service}")
    vulns = check_vulnerabilities(ports)
    if vulns:
        print("  ⚠️  Potential Vulnerabilities Found:")
        for service, reason in vulns:
            print(f"    - {service}: {reason}")


if __name__ == "__main__":
    target = input("Enter target IP range (e.g., 192.168.1.0/24): ")
    alive_ips = get_alive_ips(target)
    all_results = {}

    for ip in alive_ips:
        output = run_nmap(ip)
        parsed = parse_nmap_output(output)
        all_results.update(parsed)

    display_results(all_results)
