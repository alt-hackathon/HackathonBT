import subprocess

def run_nmap(ip_range):
    try:
        print(f"Running scan on {ip_range}...\n")
        result = subprocess.run(
            ['nmap', '-sS', '-Pn', ip_range],
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error running Nmap:")
        print(e.stderr)

if __name__ == "__main__":
    target = input("Enter target IP or CIDR range (e.g., 192.168.1.0/24): ")
    run_nmap(target)