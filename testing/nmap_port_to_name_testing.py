from scapy.all import ARP, Ether, srp
from nmap_scan.scanner import NmapScanner

def get_active_hosts(network_range):
    """ARP scan to get devices that are actually present on the network."""
    print(f"📡 Running ARP scan on {network_range} ...")
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = [rcv.psrc for snd, rcv in result]
    print(f"✅ Found {len(devices)} active device(s): {devices}")
    return devices

def scan_devices(ips):
    """Use nmap_scan to check for open ports/services."""
    scanner = NmapScanner()

    for ip in ips:
        print(f"\n🔍 Scanning {ip} ...")
        try:
            result = scanner.scan(ip, arguments='-sS -sV')

            for host in result.hosts:
                print(f"  Host: {host.address}")
                for port in host.ports:
                    print(f"    ➤ {port.portid}/{port.protocol}: {getattr(port, 'name', 'unknown')} "
                          f"{getattr(port, 'product', '')} {getattr(port, 'version', '')}")
        except Exception as e:
            print(f"  ❌ Error scanning {ip}: {e}")

if __name__ == "__main__":
    network_cidr = "192.168.1.0/24"  # Change if needed
    active_ips = get_active_hosts(network_cidr)

    if active_ips:
        scan_devices(active_ips)
    else:
        print("❌ No active devices found.")
