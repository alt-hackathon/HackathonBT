    def discover_hosts_via_arp(self, ip_range):
        """Discover active hosts on the network using ARP"""
        if self.log_callback:
            self.log_callback("Discovering active hosts via ARP...")
        
        active_hosts = []
        
        try:
            # Parse the IP range
            if "/" in ip_range:
                ip, cidr = ip_range.split("/")
                ips = self.get_network_range(ip, int(cidr))
            else:
                # Single IP
                ips = [ip_range]
            
            # Determine the OS and choose the appropriate ARP command
            os_type = platform.system().lower()
            
            if os_type == "windows":
                # Windows: Use ARP -a to get the ARP table
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8')
                # Extract IP addresses from the output
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, output)
                
                # Filter to only include IPs in our target range
                for ip in found_ips:
                    if ip in ips:
                        active_hosts.append(ip)
                
                # If we found very few or no hosts, try pinging the broadcast address
                if len(active_hosts) < 3:
                    subnet = ".".join(ip.split(".")[:3]) + ".255"
                    subprocess.call(f"ping -n 1 -w 100 {subnet}", shell=True, stdout=subprocess.DEVNULL)
                    # Try ARP again
                    output = subprocess.check_output("arp -a", shell=True).decode('utf-8')
                    found_ips = re.findall(ip_pattern, output)
                    active_hosts = [ip for ip in found_ips if ip in ips]
            
            else:
                # Linux/macOS: Use a combination of ping and arp-scan if available
                try:
                    # Try arp-scan if available (more reliable)
                    subnet = ip_range
                    output = subprocess.check_output(f"sudo arp-scan {subnet}", shell=True).decode('utf-8')
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    found_ips = re.findall(ip_pattern, output)
                    active_hosts = [ip for ip in found_ips if ip in ips]
                except:
                    # Fallback to ping sweep
                    for ip in ips:
                        # Use ping with timeout to quickly check if host is up
                        response = subprocess.call(
                            f"ping -c 1 -W 1 {ip}", 
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        if response == 0:
                            active_hosts.append(ip)
                        
                        # Update progress
                        if self.progress_callback:
                            progress = (ips.index(ip) + 1) / len(ips) * 50  # Use first 50% for discovery
                            self.progress_callback(progress, ips.index(ip) + 1, len(ips))
            
            # If we found no hosts, fall back to scanning common IPs
            if not active_hosts:
                if self.log_callback:
                    self.log_callback("No hosts discovered via ARP. Falling back to scanning common IPs...")
                
                # Add gateway (usually .1)
                gateway = ".".join(ips[0].split(".")[:3]) + ".1"
                if gateway in ips:
                    active_hosts.append(gateway)
                
                # Add some common IPs (often used for servers, routers, etc.)
                common_suffixes = [1, 100, 254]
                for suffix in common_suffixes:
                    common_ip = ".".join(ips[0].split(".")[:3]) + f".{suffix}"
                    if common_ip in ips and common_ip not in active_hosts:
                        active_hosts.append(common_ip)
            
            if self.log_callback:
                self.log_callback(f"Discovered {len(active_hosts)} active hosts")
            
            return active_hosts
        
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"Error during host discovery: {str(e)}")
            return ips  # Fall back to scanning all IPs in case of error