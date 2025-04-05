from scapy.all import ARP, Ether, srp
import nmap

def get_active_hosts(network_range):
    """Returns list of IPs with active devices using ARP scan."""
    print(f"📡 Running ARP scan on {network_range} ...")
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # srp returns (answered, unanswered)
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    active_ips = []
    for sent, received in answered_list:
        active_ips.append(received.psrc)

    print(f"✅ Found {len(active_ips)} active host(s): {active_ips}")
    return active_ips

def scan_hosts(ip_list):
    """Scans the given list of IPs using Nmap for open ports and services."""
    scanner = nmap.PortScanner()
    results = {}

    for ip in ip_list:
        print(f"\n🔍 Scanning host {ip} ...")
        try:
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
        except Exception as e:
            print(f"❌ Failed to scan {ip}: {e}")

    return results

if __name__ == "__main__":
    # Change this to match your local network
    network_range = "192.168.1.0/24"

    active_ips = get_active_hosts(network_range)
    if active_ips:
        scan_results = scan_hosts(active_ips)
    else:
        print("❌ No active hosts found.")
