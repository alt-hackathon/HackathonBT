from scapy.all import ARP, Ether, srp
from nmap_scan import NmapScan

def get_active_hosts(network_range):
    """ARP scan to get devices actually present on the network."""
    print(f"📡 Running ARP scan on {network_range} ...")
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)

    active_ips = [rcv.psrc for snd, rcv in answered]
    print(f"✅ Found {len(active_ips)} active host(s): {active_ips}")
    return active_ips

def scan_with_nmap(ip_list):
    """Scan each IP with nmap_scan and show open ports/services."""
    scanner = NmapScan()

    for ip in ip_list:
        print(f"\n🔍 Scanning {ip} ...")
        try:
            result = scanner.scan(ip, arguments='-sS -sV')

            if not result.hosts:
                print(f"  ❌ No scan results for {ip}")
                continue

            for host in result.hosts:
                print(f"  Host: {host.address}")
                for port in host.ports:
                    print(f"    ➤ Port {port.portid}/{port.protocol}: {port.name} {port.product or ''} {port.version or ''}")
        except Exception as e:
            print(f"  ❌ Error scanning {ip}: {e}")

if __name__ == "__main__":
    network_range = "192.168.1.0/24"  # Change as needed
    active_ips = get_active_hosts(network_range)

    if active_ips:
        scan_with_nmap(active_ips)
    else:
        print("❌ No active devices found.")