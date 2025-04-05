from scapy.all import ARP, Ether, srp
import nmap

def get_active_hosts(network_range):
    """Returns list of IPs with active devices using ARP scan."""
    print(f"📡 Running ARP scan on {network_range} ...")
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=False)

    active_ips = [res.psrc for res in answered]
    print(f"✅ Found {len(active_ips)} active host(s): {active_ips}")
    return active_ips

def scan_hosts(ip_list):
    """Scans the given list of IPs using Nmap for open ports and services."""
    scanner = nmap.PortScanner()
    results = {}

    for ip in ip_list:
        print(f"\n🔍 Scanning host {ip} ...")
        scanner.scan(hosts=ip, arguments='-sS -sV -T4')

        if scanner[ip].state() == "up":
            results[ip] = {}

            for proto in scanner[ip].all_protocols():
                ports = scanner[ip][proto].keys()
                for port in sorted(ports):
                    service = scanner[ip][proto][port]
                    name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    print(f"  - {proto.upper()} Port {port}: {name} {product} {version}")

                    results[ip][port] = {
                        'protocol': proto,
                        'name': name,
                        'product': product,
                        'version': version
                    }

    return results

if __name__ == "__main__":
    # Update this to your subnet
    network_range = "192.168.1.0/24"

    active_ips = get_active_hosts(network_range)
    if active_ips:
        scan_results = scan_hosts(active_ips)
    else:
        print("❌ No active hosts found.")