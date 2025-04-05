import subprocess
import re

def run_nmap_scan(target_network):
    print(f"Scanning network: {target_network}...\n")
    
    try:
        result = subprocess.check_output(['nmap', '-p', '1-1024', '--open', target_network], text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error during nmap scan: {e}")
        return
    
    current_host = None
    open_ports = []

    for line in result.splitlines():
        if line.startswith("Nmap scan report for"):
            if current_host and open_ports:
                print(f"{current_host} - Open ports: {open_ports}")
            current_host = line.split()[-1]
            open_ports = []
        elif re.match(r'^\d+/tcp\s+open', line):
            port = line.split('/')[0]
            open_ports.append(int(port))
    
    # Print last host
    if current_host and open_ports:
        print(f"{current_host} - Open ports: {open_ports}")

if __name__ == "__main__":
    target_network = "192.168.1.0/24"  # Update to match your actual network
    run_nmap_scan(target_network)