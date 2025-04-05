
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import subprocess
import ipaddress
import platform
import re
import time
import sys
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import ARP, Ether, srp

class NetworkScanner:
    """Network scanner class that handles the scanning logic"""
    
    # Common IoT device ports to scan
    COMMON_PORTS = [
        22,    # SSH
        23,    # Telnet
        80,    # HTTP
        443,   # HTTPS
        554,   # RTSP (cameras)
        1883,  # MQTT
        8080,  # Alternative HTTP
        8443,  # Alternative HTTPS
        8883,  # Secure MQTT
        9000   # Common IoT web interface
    ]
    
    # Common IoT vulnerabilities to check
    VULNERABILITIES = [
        {
            "name": "Telnet Enabled",
            "description": "Telnet is an unencrypted protocol that can expose credentials and commands.",
            "severity": "High",
            "check": lambda ports, banners: 23 in ports,
            "port": 23,
            "recommendation": "Disable Telnet and use SSH instead."
        },
        {
            "name": "HTTP Without HTTPS",
            "description": "Device offers HTTP service without secure HTTPS alternative.",
            "severity": "Medium",
            "check": lambda ports, banners: 80 in ports and 443 not in ports,
            "port": 80,
            "recommendation": "Enable HTTPS and redirect HTTP to HTTPS."
        },
        {
            "name": "Default Credentials in Banner",
            "description": "Device may be exposing default credentials in service banners.",
            "severity": "Critical",
            "check": lambda ports, banners: any("default" in banner.lower() and "password" in banner.lower() for banner in banners.values()),
            "port": "Multiple",
            "recommendation": "Change default passwords immediately."
        },
        {
            "name": "Open MQTT Broker",
            "description": "MQTT broker is accessible and may allow unauthorized publishing/subscribing.",
            "severity": "Medium",
            "check": lambda ports, banners: 1883 in ports,
            "port": 1883,
            "recommendation": "Secure MQTT broker with authentication and encryption."
        }
    ]
    
    def __init__(self):
        """Initialize the scanner"""
        self.results = []
        self.scanning = False
        self.progress_callback = None
        self.log_callback = None
    
    def get_local_ip(self) -> str:
        """Get the local IP address of the machine"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()
        return local_ip

    def get_active_ips(self, ip_range): #Perform ARP scan to find active IPs in the network."""
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=False)[0]

        active_ips = [received.psrc for sent, received in result]
        return active_ips

    
    def get_network_range(self, ip: str, cidr: int = 24) -> List[str]:
        """Convert IP and CIDR to a list of IPs in that range"""
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return [str(ip) for ip in network.hosts()]

    def is_port_open(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a port is open on the target IP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    
    def get_service_banner(self, ip: str, port: int, timeout: float = 2.0) -> str:
        """Try to get service banner from the specified port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send a generic request to trigger a response
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 23 or port == 22:
                # Just wait for the banner
                pass
            else:
                sock.send(b"\r\n")
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return ""
    
    def get_hostname(self, ip: str) -> str:
        """Try to get the hostname of the IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def get_mac_address(self, ip: str) -> Tuple[str, str]:
        """Try to get the MAC address of the IP using ARP"""
        mac = "Unknown"
        vendor = "Unknown"
        
        os_type = platform.system().lower()
        
        try:
            if os_type == "windows":
                # Windows
                output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
                matches = re.search(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
                if matches:
                    mac = matches.group(1)
            else:
                # Linux/Mac
                output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
                matches = re.search(r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})", output)
                if matches:
                    mac = matches.group(1)
                    
            # In a real implementation, you would look up the vendor from the MAC OUI
            # For simplicity, we'll just use the first 3 octets
            if mac != "Unknown":
                vendor = f"Vendor-{mac.split(':')[0:3]}"
        except:
            pass
            
        return mac, vendor
    
    def determine_device_type(self, open_ports: List[int]) -> str:
        """Determine the likely device type based on open ports"""
        if 554 in open_ports:
            return "IP Camera"
        elif 1883 in open_ports or 8883 in open_ports:
            return "IoT Hub/Gateway"
        elif 80 in open_ports or 443 in open_ports:
            return "Web-enabled Device"
        elif 23 in open_ports:
            return "Telnet-enabled Device"
        elif 22 in open_ports:
            return "SSH-enabled Device"
        else:
            return "Unknown IoT Device"
    
    def check_vulnerabilities(self, open_ports: List[int], banners: Dict[int, str]) -> List[Dict[str, Any]]:
        """Check for vulnerabilities based on open ports and service banners"""
        vulnerabilities = []
        
        for vuln in self.VULNERABILITIES:
            if vuln["check"](open_ports, banners):
                vulnerabilities.append({
                    "name": vuln["name"],
                    "description": vuln["description"],
                    "severity": vuln["severity"],
                    "port": vuln["port"],
                    "recommendation": vuln["recommendation"]
                })
                
        return vulnerabilities
    
    def scan_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Scan a single IP address for IoT devices and vulnerabilities"""
        if self.log_callback:
            self.log_callback(f"Scanning {ip}...")
        
        # Check which ports are open
        open_ports = []
        for port in self.COMMON_PORTS:
            if self.is_port_open(ip, port):
                open_ports.append(port)
        
        if not open_ports:
            return None
        
        # Get service banners
        banners = {}
        for port in open_ports:
            banner = self.get_service_banner(ip, port)
            if banner:
                banners[port] = banner
        
        # Get hostname
        hostname = self.get_hostname(ip)
        
        # Get MAC address and vendor
        mac, vendor = self.get_mac_address(ip)
        
        # Determine device type
        device_type = self.determine_device_type(open_ports)
        
        # Check for vulnerabilities
        vulnerabilities = self.check_vulnerabilities(open_ports, banners)
        
        return {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "open_ports": open_ports,
            "banners": banners,
            "vulnerabilities": vulnerabilities
        }
    
    
    def scan_network(self, ip_range: str): #"""Scan a network range for IoT devices and vulnerabilities (only active devices via ARP)"""
        self.scanning = True
        self.results = []

        try:
            # 🔍 Use ARP to find active devices only
            ips = self.get_active_ips(ip_range)
            total_ips = len(ips)

            if self.log_callback:
                self.log_callback(f"Found {total_ips} active devices.\n\n{ips}\n\nStarting vulnerability scan...")

            start_time = time.time()
            completed = 0

            for ip in ips:
                if not self.scanning:
                    if self.log_callback:
                        self.log_callback("Scan cancelled by user.")
                    break

                result = self.scan_ip(ip)
                if result:
                    self.results.append(result)

                completed += 1
                if self.progress_callback:
                    progress = (completed / total_ips) * 100
                    self.progress_callback(progress, completed, total_ips)

            duration = time.time() - start_time
            if self.log_callback:
                self.log_callback(f"Scan completed in {duration:.2f} seconds. Found {len(self.results)} devices.")

        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error scanning network: {str(e)}")

        self.scanning = False
        return self.results
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False

# Make scanner app more user-friendly
class ScannerApp:
    """GUI application for the Network Scanner"""

    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.scanner = NetworkScanner()
        self.scanner.log_callback = self.log_message
        self.scanner.progress_callback = self.update_progress

        # Create GUI components
        self.create_widgets()

    def create_widgets(self):
        """Create the GUI layout"""
        # Network Range Input
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Network Range (CIDR):").grid(row=0, column=0, sticky="w")
        self.network_entry = ttk.Entry(frame, width=30)
        self.network_entry.grid(row=0, column=1, sticky="w")
        self.network_entry.insert(0, f"{self.scanner.get_local_ip()}/24")

        # Buttons
        self.scan_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5)

        self.stop_button = ttk.Button(frame, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=0, column=3, padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(frame, length=400, mode="determinate")
        self.progress.grid(row=1, column=0, columnspan=4, pady=10)

        # Results Table
        self.tree = ttk.Treeview(self.root, columns=("IP", "Hostname", "MAC", "Vendor", "Device Type", "Vulnerabilities"), show="headings")
        self.tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)

        # Log Output
        self.log_output = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=10)
        self.log_output.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)

    def start_scan(self):
        """Start the network scan"""
        ip_range = self.network_entry.get()
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.log_output.delete(1.0, tk.END)
        self.tree.delete(*self.tree.get_children())

        # Run the scan in a separate thread
        threading.Thread(target=self.run_scan, args=(ip_range,), daemon=True).start()

    def run_scan(self, ip_range):
        """Run the scan and update the GUI with results"""
        results = self.scanner.scan_network(ip_range)
        for result in results:
            vulnerabilities = "\n".join([f"{v['name']} ({v['severity']})" for v in result["vulnerabilities"]])
            self.tree.insert("", "end", values=(
                result["ip"],
                result["hostname"],
                result["mac"],
                result["device_type"],
                vulnerabilities
            ))

        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def stop_scan(self):
        """Stop the ongoing scan"""
        self.scanner.stop_scan()
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def update_progress(self, progress, completed, total):
        """Update the progress bar"""
        self.progress["value"] = progress
        self.log_message(f"Progress: {completed}/{total} devices scanned.")

    def log_message(self, message):
        """Log messages to the output box"""
        self.log_output.insert(tk.END, message + "\n")
        self.log_output.see(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()