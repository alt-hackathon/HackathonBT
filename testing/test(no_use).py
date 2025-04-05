import nmap

# Vulnerable services with explanations and fixes
vulnerable_services = {
    "telnet": {
        "reason": "Transmits data in plaintext, allowing attackers to intercept credentials.",
        "recommendation": "Disable Telnet and use SSH instead for secure remote access."
    },
    "ftp": {
        "reason": "FTP sends data unencrypted, exposing usernames and passwords.",
        "recommendation": "Use SFTP or FTPS instead for secure file transfers."
    },
    "smb": {
        "reason": "Older versions of SMB are vulnerable to remote code execution (e.g. EternalBlue).",
        "recommendation": "Update to SMBv3 and block SMB traffic over the internet."
    },
    "rdp": {
        "reason": "RDP is a common target for brute-force and ransomware attacks.",
        "recommendation": "Use a VPN and enable Network Level Authentication (NLA)."
    },
    "vnc": {
        "reason": "VNC is often exposed without encryption or strong passwords.",
        "recommendation": "Tunnel VNC over SSH or use a secure alternative like Guacamole with MFA."
    },
    "mysql": {
        "reason": "Exposing MySQL to the network can allow database access if not properly secured.",
        "recommendation": "Bind MySQL to localhost and use firewalls to restrict access."
    },
    "mongodb": {
        "reason": "Old MongoDB setups often have no authentication, allowing public read/write access.",
        "recommendation": "Enable authentication and firewall off external access."
    },
    "http": {
        "reason": "Unencrypted HTTP can leak sensitive data and session tokens.",
        "recommendation": "Redirect HTTP to HTTPS using SSL certificates."
    }
}
#added in above, working on compatability with below
def is_vulnerable(service_name):
    """Check if a service is known to be vulnerable"""
    return service_name.lower() in vulnerable_services

def scan_network(ip_range="192.168.1.0/24"):
    nm = nmap.PortScanner()
    print(f"📡 Scanning network {ip_range} for devices and open ports...\n")

    nm.scan(hosts=ip_range, arguments='-p 1-1000 -sV')

    for host in nm.all_hosts():
        print(f"\n🖥️ Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"\n🔍 Protocol: {proto.upper()}")
            ports = nm[host][proto].keys()

            for port in sorted(ports):
                service = nm[host][proto][port]
                name = service.get('name', 'unknown')
                product = service.get('product', '')
                version = service.get('version', '')

                print(f"🔓 Port {port}: {name} ({product} {version})")

                if is_vulnerable(name):
                    info = vulnerable_services[name.lower()]
                    print("⚠️  Vulnerable service detected!")
                    print(f"   🛑 Reason: {info['reason']}")
                    print(f"   ✅ Recommendation: {info['recommendation']}")

if __name__ == "__main__":
    # Adjust to your subnet
    scan_network("192.168.1.0/24")
