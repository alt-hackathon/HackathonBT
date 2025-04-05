import subprocess
import re

def run_nmap(ip_range):
    try:
        print(f"\nScanning {ip_range}...\n")
        result = subprocess.run(
            ['nmap', '-sS', '-Pn', ip_range],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Nmap scan failed:")
        print(e.stderr)
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

def display_results(devices):
    print("\nScan Results:\n" + "-"*30)
    for ip, ports in devices.items():
        print(f"\nDevice: {ip}")
        if ports:
            for port, service in ports:
                print(f"  Port: {port}, Service: {service}")
        else:
            print("  No open ports found.")

if __name__ == "__main__":
    target = input("Enter target IP range (e.g., 192.168.1.0/24): ")
    raw_output = run_nmap(target)
    parsed = parse_nmap_output(raw_output)
    display_results(parsed)