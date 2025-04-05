
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
    
    def scan_network(self, ip_range: str):
        """Scan a network range for IoT devices and vulnerabilities"""
        self.scanning = True
        self.results = []
        
        try:
            # Parse the IP range (e.g., 192.168.1.0/24)
            if "/" in ip_range:
                ip, cidr = ip_range.split("/")
                ips = self.get_network_range(ip, int(cidr))
            else:
                # Single IP
                ips = [ip_range]
            
            total_ips = len(ips)
            
            if self.log_callback:
                self.log_callback(f"Starting scan of {total_ips} IP addresses...")
            
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

class ScannerApp:
    """GUI application for the network scanner"""
    
    def __init__(self, root):
        """Initialize the GUI application"""
        self.root = root
        self.root.title("IoT Network Security Scanner")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        self.scanner = NetworkScanner()
        self.scan_thread = None
        
        self.create_widgets()
        self.setup_styles()
        
        # Get the local IP to suggest a default scan range
        local_ip = self.scanner.get_local_ip()
        default_range = ".".join(local_ip.split(".")[:3]) + ".0/24"
        self.ip_range_var.set(default_range)
        
        self.log(f"Your IP address appears to be: {local_ip}")
        self.log("Ready to scan. Enter an IP range and click 'Start Scan'.")
        self.log("IMPORTANT: Only scan networks you own or have permission to scan.")
    
    def setup_styles(self):
        """Set up ttk styles"""
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#ccc")
        style.configure("Accent.TButton", background="#007bff", foreground="white")
        style.configure("Danger.TButton", background="#dc3545", foreground="white")
        style.map('Accent.TButton', background=[('active', '#0069d9')])
        style.map('Danger.TButton', background=[('active', '#c82333')])
    
    def create_widgets(self):
        """Create the GUI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for controls
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # IP range input
        ttk.Label(top_frame, text="IP Range:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_range_var = tk.StringVar()
        ip_entry = ttk.Entry(top_frame, textvariable=self.ip_range_var, width=20)
        ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Scan buttonh
        self.scan_button = ttk.Button(top_frame, text="Start Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Stop button
        self.stop_button = ttk.Button(top_frame, text="Stop", style="Danger.TButton", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        # Progress bar
        ttk.Label(top_frame, text="Progress:").pack(side=tk.LEFT, padx=(10, 5))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(top_frame, variable=self.progress_var, length=150)
        self.progress_bar.pack(side=tk.LEFT, padx=(0, 5))
        
        self.progress_label = ttk.Label(top_frame, text="0%")
        self.progress_label.pack(side=tk.LEFT)
        
        # Notebook for results and logs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results tab
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        
        # Results tree view
        columns = ("ip", "hostname", "device_type", "open_ports", "vulnerabilities")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Define headings
        self.results_tree.heading("ip", text="IP Address")
        self.results_tree.heading("hostname", text="Hostname")
        self.results_tree.heading("device_type", text="Device Type")
        self.results_tree.heading("open_ports", text="Open Ports")
        self.results_tree.heading("vulnerabilities", text="Vulnerabilities")
        
        # Define columns
        self.results_tree.column("ip", width=100)
        self.results_tree.column("hostname", width=150)
        self.results_tree.column("device_type", width=120)
        self.results_tree.column("open_ports", width=150)
        self.results_tree.column("vulnerabilities", width=150)
        
        # Scrollbar for results
        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        
        # Pack the results tree and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to show details
        self.results_ll=tk.Y
        
        # Bind double-click event to show details
        self.results_tree.bind("<Double-1>", self.show_device_details)
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Log")
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Details frame
        self.details_frame = ttk.LabelFrame(main_frame, text="Device Details", padding="10")
        self.details_frame.pack(fill=tk.X, pady=10)
        
        # Details text
        self.details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, height=10)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Set callbacks
        self.scanner.progress_callback = self.update_progress
        self.scanner.log_callback = self.log
    
    def start_scan(self):
        """Start the network scan in a separate thread"""
        ip_range = self.ip_range_var.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Please enter an IP range to scan.")
            return
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.details_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        
        # Update UI
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(ip_range,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def run_scan(self, ip_range):
        """Run the scan in a separate thread"""
        results = self.scanner.scan_network(ip_range)
        
        # Update UI with results
        self.root.after(0, self.update_results, results)
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner.scanning:
            self.scanner.stop_scan()
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def update_progress(self, progress, completed, total):
        """Update the progress bar"""
        self.progress_var.set(progress)
        self.progress_label.config(text=f"{progress:.1f}% ({completed}/{total})")
    
    def update_results(self, results):
        """Update the results tree with scan results"""
        for result in results:
            vuln_count = len(result["vulnerabilities"])
            vuln_text = f"{vuln_count} issues" if vuln_count > 0 else "Secure"
            
            # Add to tree view
            item_id = self.results_tree.insert("", tk.END, values=(
                result["ip"],
                result["hostname"],
                result["device_type"],
                ", ".join(map(str, result["open_ports"])),
                vuln_text
            ))
            
            # Set tag for vulnerable devices
            if vuln_count > 0:
                self.results_tree.item(item_id, tags=("vulnerable",))
        
        # Configure tag colors
        self.results_tree.tag_configure("vulnerable", background="#ffcccc")
        
        # Update UI
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # Show summary
        self.log(f"Scan completed. Found {len(results)} devices.")
        vulnerable_count = sum(1 for r in results if r["vulnerabilities"])
        self.log(f"Vulnerable devices: {vulnerable_count}")
        total_vulns = sum(len(r["vulnerabilities"]) for r in results)
        self.log(f"Total vulnerabilities: {total_vulns}")
    
    def show_device_details(self, event):
        """Show details for the selected device"""
        item_id = self.results_tree.focus()
        if not item_id:
            return
        
        # Get the IP of the selected device
        ip = self.results_tree.item(item_id, "values")[0]
        
        # Find the device in results
        device = next((r for r in self.scanner.results if r["ip"] == ip), None)
        if not device:
            return
        
        # Clear details text
        self.details_text.delete(1.0, tk.END)
        
        # Add device details
        self.details_text.insert(tk.END, f"IP Address: {device['ip']}\n")
        self.details_text.insert(tk.END, f"Hostname: {device['hostname']}\n")
        self.details_text.insert(tk.END, f"MAC Address: {device['mac']}\n")
        self.details_text.insert(tk.END, f"Vendor: {device['vendor']}\n")
        self.details_text.insert(tk.END, f"Device Type: {device['device_type']}\n")
        self.details_text.insert(tk.END, f"Open Ports: {', '.join(map(str, device['open_ports']))}\n\n")
        
        # Add vulnerabilities
        if device["vulnerabilities"]:
            self.details_text.insert(tk.END, "Vulnerabilities:\n", "header")
            for vuln in device["vulnerabilities"]:
                self.details_text.insert(tk.END, f"- {vuln['name']} ", "vuln_title")
                self.details_text.insert(tk.END, f"({vuln['severity']})\n", "vuln_severity")
                self.details_text.insert(tk.END, f"  {vuln['description']}\n")
                self.details_text.insert(tk.END, f"  Port: {vuln['port']}\n")
                self.details_text.insert(tk.END, f"  Recommendation: {vuln['recommendation']}\n\n")
        else:
            self.details_text.insert(tk.END, "No vulnerabilities detected.\n", "secure")
        
        # Configure text tags
        self.details_text.tag_configure("header", font=("TkDefaultFont", 10, "bold"))
        self.details_text.tag_configure("vuln_title", font=("TkDefaultFont", 9, "bold"))
        self.details_text.tag_configure("vuln_severity", foreground="red")
        self.details_text.tag_configure("secure", foreground="green")
    
    def log(self, message):
        """Add a message to the log"""
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)

def main():
    """Main function to run the GUI application"""
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()