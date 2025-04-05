import socket
import subprocess
import os

def ping_sweep(network_range):
    ip_list = []
    base_ip = ".".join(network_range.split(".")[:3])  # Extract base IP (e.g., 192.168.1)
    
    for i in range(1, 255):  # Iterate over possible host addresses
        ip = f"{base_ip}.{i}"
        try:
            # Use ping to check if the IP is active
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
            if result.returncode == 0:
                ip_list.append(ip)
        except Exception as e:
            print(f"Error pinging {ip}: {e}")
    
    return ip_list

def scan_ports(ip_list):
    vulnerable_ports = []
    common_ports = [21, 23, 80, 443, 445]  # Example of common ports to scan

    for ip in ip_list:
        for port in common_ports:
            try:
                # Attempt to connect to the port
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip, port))
                    if result == 0:  # Port is open
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except socket.herror:
                            hostname = "Unknown"
                        vulnerable_ports.append((ip, port, hostname))
            except Exception as e:
                print(f"Error scanning {ip}:{port} - {e}")
    
    return vulnerable_ports

def main():
    print("Scanning network for active devices...")
    network_range = "192.168.1.0/24"
    ip_list = ping_sweep(network_range)
    print(f"Found {len(ip_list)} active IP addresses.")

    print("Scanning for open and vulnerable ports...")
    vulnerable_ports = scan_ports(ip_list)

    if vulnerable_ports:
        print("Vulnerable devices found:")
        for ip, port, hostname in vulnerable_ports:
            print(f"IP: {ip}, Port: {port}, Hostname: {hostname}")
            print(f"Recommendation: Close port {port} or secure the service.")
    else:
        print("No vulnerable devices found.")

if __name__ == "__main__":
    main()
