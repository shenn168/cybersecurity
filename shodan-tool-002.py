#!/usr/bin/env python3
"""
Shodan Threat Intelligence CLI Tool
A command-line interface for performing threat intelligence operations using Shodan API
"""

import shodan
import sys
import os
from getpass import getpass

class ShodanThreatIntelTool:
    def __init__(self):
        self.api = None
        self.api_key = None
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def login(self):
        """Prompt for API key and authenticate with Shodan"""
        self.clear_screen()
        print("=" * 60)
        print("  SHODAN THREAT INTELLIGENCE TOOL")
        print("=" * 60)
        print()
        
        # Prompt for API key (hidden input)
        self.api_key = getpass("Enter your Shodan API Key: ")
        
        if not self.api_key:
            print("\n[ERROR] API Key cannot be empty!")
            return False
        
        try:
            # Initialize Shodan API
            self.api = shodan.Shodan(self.api_key)
            
            # Test API key by fetching account info
            info = self.api.info()
            
            print("\
" + "=" * 60)
            print("  LOGIN SUCCESSFUL!")
            print("=" * 60)
            print(f"\nPlan: {info.get('plan', 'N/A')}")
            print(f"Query Credits: {info.get('query_credits', 0)}")
            print(f"Scan Credits: {info.get('scan_credits', 0)}")
            print(f"Monitored IPs: {info.get('monitored_ips', 0)}")
            print("\nPress Enter to continue...")
            input()
            
            return True
            
        except shodan.APIError as e:
            print(f"\
[ERROR] Authentication failed: {e}")
            print("\nPress Enter to continue...")
            input()
            return False
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
            print("\
Press Enter to continue...")
            input()
            return False
    
    def display_menu(self):
        """Display the main menu with Shodan capabilities"""
        self.clear_screen()
        print("=" * 60)
        print("  SHODAN THREAT INTELLIGENCE MENU")
        print("=" * 60)
        print()
        print("1.  Host Lookup - Get all available information on an IP")
        print("2.  Search Shodan - Search Shodan database")
        print("3.  Search Exploits - Search for exploits (Advanced Module)")
        print("4.  Count Search Results - Count results for a search query")
        print("5.  DNS Lookup - Get IP from domain")
        print("6.  DNS Reverse - Get domains for an IP")
        print("7.  Get Ports - List all ports Shodan is crawling")
        print("8.  Get Protocols - List protocols that can be filtered")
        print("9.  Get Services - List services that can be filtered")
        print("10. Account Info - View your account information")
        print("11. API Plan Info - View API plan details")
        print("12. Search Facets - Get available search facets")
        print("13. Search Filters - Get available search filters")
        print("14. Honeypot Score - Check if IP is a honeypot")
        print("15. Query Tags - Get popular query tags")
        print("16. Scan Internet - Submit IP for scanning")
        print("17. Scan Status - Check scan status")
        print("18. Network Alerts - List network alerts")
        print("19. Create Alert - Create a network alert")
        print("20. Notifier List - List available notifiers")
        print()
        print("0.  Quit - Exit the tool")
        print()
        print("=" * 60)
    
    def host_lookup(self):
        """Option 1: Host IP Lookup"""
        self.clear_screen()
        print("=" * 60)
        print("  HOST LOOKUP")
        print("=" * 60)
        print()
        
        ip = input("Enter IP address: ").strip()
        
        if not ip:
            print("\n[ERROR] IP address cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print("\n[INFO] Fetching host information...")
            host = self.api.host(ip)
            
            print(f"\n{'=' * 60}")
            print(f"IP: {host.get('ip_str', 'N/A')}")
            print(f"Organization: {host.get('org', 'N/A')}")
            print(f"Operating System: {host.get('os', 'N/A')}")
            print(f"Country: {host.get('country_name', 'N/A')}")
            print(f"City: {host.get('city', 'N/A')}")
            print(f"ISP: {host.get('isp', 'N/A')}")
            print(f"Hostnames: {', '.join(host.get('hostnames', []))}")
            print(f"Domains: {', '.join(host.get('domains', []))}")
            print(f"Ports: {', '.join(map(str, host.get('ports', [])))}")
            print(f"Vulnerabilities: {', '.join(host.get('vulns', [])) if host.get('vulns') else 'None'}")
            print(f"\nServices found: {len(host.get('data', []))}")
            
            # Display service details
            if host.get('data'):
                print(f"\
{'=' * 60}")
                print("SERVICE DETAILS:")
                for i, item in enumerate(host['data'], 1):
                    print(f"\n--- Service {i} ---")
                    print(f"Port: {item.get('port', 'N/A')}")
                    print(f"Transport: {item.get('transport', 'N/A')}")
                    print(f"Product: {item.get('product', 'N/A')}")
                    print(f"Version: {item.get('version', 'N/A')}")
                    if item.get('vulns'):
                        print(f"Vulnerabilities: {', '.join(item['vulns'])}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\nPress Enter to continue...")
    
    def search_shodan(self):
        """Option 2: Search Shodan Database"""
        self.clear_screen()
        print("=" * 60)
        print("  SEARCH SHODAN")
        print("=" * 60)
        print()
        
        query = input("Enter search query (e.g., 'apache country:US'): ").strip()
        
        if not query:
            print("\
[ERROR] Query cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            limit = input("Number of results (default 10, max 100): ").strip()
            limit = int(limit) if limit else 10
            limit = min(limit, 100)
            
            print(f"\n[INFO] Searching for: {query}")
            results = self.api.search(query, limit=limit)
            
            print(f"\
{'=' * 60}")
            print(f"Total results: {results['total']}")
            print(f"Showing: {len(results['matches'])} results")
            print(f"{'=' * 60}")
            
            for i, result in enumerate(results['matches'], 1):
                print(f"\n--- Result {i} ---")
                print(f"IP: {result.get('ip_str', 'N/A')}")
                print(f"Port: {result.get('port', 'N/A')}")
                print(f"Organization: {result.get('org', 'N/A')}")
                print(f"Location: {result.get('location', {}).get('city', 'N/A')}, {result.get('location', {}).get('country_name', 'N/A')}")
                print(f"Hostnames: {', '.join(result.get('hostnames', []))}")
                print(f"Domains: {', '.join(result.get('domains', []))}")
                
                if result.get('vulns'):
                    print(f"Vulnerabilities: {', '.join(result['vulns'])}")
                
                # Show banner snippet
                if result.get('data'):
                    banner = result['data'][:200]
                    print(f"Banner: {banner}...")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except ValueError:
            print("\
[ERROR] Invalid number format!")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\nPress Enter to continue...")
    
    def search_exploits(self):
        """Option 3: Search for Exploits - Calls dedicated exploit search module"""
        self.clear_screen()
        print("=" * 60)
        print("  SEARCH EXPLOITS (ADVANCED MODULE)")
        print("=" * 60)
        print()
        
        try:
            # Import the exploit search module
            from shodan_exploit_search import interactive_search
            
            print("[INFO] Loading advanced exploit search module...")
            print()
            
            # Call the dedicated exploit search module
            interactive_search(self.api_key)
            
        except ImportError as e:
            print("[ERROR] Exploit search module not found!")
            print("Please ensure 'shodan_exploit_search.py' is in the same directory.")
            print(f"Details: {e}")
        except Exception as e:
            print(f"[ERROR] {e}")
        
        input("\
Press Enter to return to main menu...")
    
    def count_search(self):
        """Option 4: Count Search Results"""
        self.clear_screen()
        print("=" * 60)
        print("  COUNT SEARCH RESULTS")
        print("=" * 60)
        print()
        
        query = input("Enter search query: ").strip()
        
        if not query:
            print("\
[ERROR] Query cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Counting results for: {query}")
            result = self.api.count(query)
            
            print(f"\
{'=' * 60}")
            print(f"Total results: {result['total']:,}")
            print(f"{'=' * 60}")
            
            # Show facets if available
            if result.get('facets'):
                print("\nTop Countries:")
                for country in result['facets'].get('country', [])[:5]:
                    print(f"  {country['value']}: {country['count']:,}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def dns_lookup(self):
        """Option 5: DNS Lookup"""
        self.clear_screen()
        print("=" * 60)
        print("  DNS LOOKUP")
        print("=" * 60)
        print()
        
        domain = input("Enter domain name (e.g., google.com): ").strip()
        
        if not domain:
            print("\
[ERROR] Domain cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Looking up: {domain}")
            result = self.api.dns.resolve(domain)
            
            print(f"\
{'=' * 60}")
            print(f"Domain: {domain}")
            print(f"IP Address: {result.get(domain, 'N/A')}")
            print(f"{'=' * 60}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def dns_reverse(self):
        """Option 6: Reverse DNS Lookup"""
        self.clear_screen()
        print("=" * 60)
        print("  REVERSE DNS LOOKUP")
        print("=" * 60)
        print()
        
        ip = input("Enter IP address: ").strip()
        
        if not ip:
            print("\
[ERROR] IP address cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Reverse lookup for: {ip}")
            result = self.api.dns.reverse(ip)
            
            print(f"\
{'=' * 60}")
            print(f"IP: {ip}")
            print(f"Domains: {', '.join(result.get(ip, [])) if result.get(ip) else 'None'}")
            print(f"{'=' * 60}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def get_ports(self):
        """Option 7: Get Ports List"""
        self.clear_screen()
        print("=" * 60)
        print("  SHODAN CRAWLED PORTS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching ports list...")
            ports = self.api.ports()
            
            print(f"\
{'=' * 60}")
            print(f"Total ports: {len(ports)}")
            print(f"{'=' * 60}")
            print(f"\nPorts: {', '.join(map(str, ports))}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def get_protocols(self):
        """Option 8: Get Protocols List"""
        self.clear_screen()
        print("=" * 60)
        print("  SHODAN PROTOCOLS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching protocols...")
            protocols = self.api.protocols()
            
            print(f"\
{'=' * 60}")
            print(f"Available Protocols:")
            print(f"{'=' * 60}")
            
            for protocol, description in protocols.items():
                print(f"{protocol}: {description}")
            
        except shodan.APIError as e:
            print(f"\n[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def get_services(self):
        """Option 9: Get Services List"""
        self.clear_screen()
        print("=" * 60)
        print("  SHODAN SERVICES")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching services...")
            services = self.api.services()
            
            print(f"\
{'=' * 60}")
            print(f"Available Services:")
            print(f"{'=' * 60}")
            
            for service, description in services.items():
                print(f"{service}: {description}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def account_info(self):
        """Option 10: Account Information"""
        self.clear_screen()
        print("=" * 60)
        print("  ACCOUNT INFORMATION")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching account info...")
            info = self.api.info()
            
            print(f"\
{'=' * 60}")
            print(f"Plan: {info.get('plan', 'N/A')}")
            print(f"Query Credits: {info.get('query_credits', 0)}")
            print(f"Scan Credits: {info.get('scan_credits', 0)}")
            print(f"Monitored IPs: {info.get('monitored_ips', 0)}")
            print(f"Unlocked: {info.get('unlocked', False)}")
            print(f"Unlocked Left: {info.get('unlocked_left', 0)}")
            print(f"{'=' * 60}")
            
        except shodan.APIError as e:
            print(f"\n[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def api_plan_info(self):
        """Option 11: API Plan Information"""
        self.clear_screen()
        print("=" * 60)
        print("  API PLAN INFORMATION")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching API plan info...")
            info = self.api.info()
            
            print(f"\
{'=' * 60}")
            print("PLAN DETAILS:")
            print(f"{'=' * 60}")
            print(f"Current Plan: {info.get('plan', 'N/A')}")
            print(f"\nCREDITS:")
            print(f"  Query Credits: {info.get('query_credits', 0)}")
            print(f"  Scan Credits: {info.get('scan_credits', 0)}")
            print(f"\nFEATURES:")
            print(f"  Monitored IPs: {info.get('monitored_ips', 0)}")
            print(f"  HTTPS API Access: {info.get('https', True)}")
            print(f"  Unlocked Features: {info.get('unlocked', False)}")
            
            if info.get('usage_limits'):
                print(f"\
USAGE LIMITS:")
                for key, value in info['usage_limits'].items():
                    print(f"  {key}: {value}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def search_facets(self):
        """Option 12: Get Search Facets"""
        self.clear_screen()
        print("=" * 60)
        print("  SEARCH FACETS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Available search facets for filtering results:")
            
            facets = [
                "country", "city", "org", "isp", "domain", "port",
                "asn", "os", "product", "version", "link", "bitcoin.ip"
            ]
            
            print(f"\
{'=' * 60}")
            print("Available Facets:")
            print(f"{'=' * 60}")
            
            for facet in facets:
                print(f"  - {facet}")
            
            print(f"\
Usage: Add facets to your search query")
            print(f"Example: apache country:US city:Chicago")
            
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def search_filters(self):
        """Option 13: Get Search Filters"""
        self.clear_screen()
        print("=" * 60)
        print("  SEARCH FILTERS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Available search filters:")
            
            print(f"\
{'=' * 60}")
            print("Common Filters:")
            print(f"{'=' * 60}")
            
            filters = {
                "city": "City name",
                "country": "2-letter country code",
                "geo": "latitude,longitude,radius (km)",
                "hostname": "Hostname",
                "net": "IP or CIDR range",
                "os": "Operating system",
                "port": "Port number",
                "before/after": "Date format DD/MM/YYYY",
                "hash": "Banner hash",
                "has_screenshot": "true/false",
                "has_ssl": "true/false",
                "http.component": "Web technology",
                "http.status": "HTTP status code",
                "http.title": "HTTP title",
                "link": "Link protocol",
                "org": "Organization name",
                "product": "Product name",
                "version": "Product version",
                "vuln": "CVE ID"
            }
            
            for filter_name, description in filters.items():
                print(f"  {filter_name:20} - {description}")
            
            print(f"\
Example queries:")
            print(f"  apache port:443 country:US")
            print(f"  vuln:CVE-2021-44228")
            print(f"  product:MySQL version:5.7")
            
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\nPress Enter to continue...")
    
    def honeypot_score(self):
        """Option 14: Check Honeypot Score"""
        self.clear_screen()
        print("=" * 60)
        print("  HONEYPOT SCORE CHECK")
        print("=" * 60)
        print()
        
        ip = input("Enter IP address: ").strip()
        
        if not ip:
            print("\
[ERROR] IP address cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Checking honeypot score for: {ip}")
            score = self.api.labs.honeyscore(ip)
            
            print(f"\
{'=' * 60}")
            print(f"IP: {ip}")
            print(f"Honeypot Score: {score}")
            print(f"{'=' * 60}")
            
            if score >= 0.8:
                print("\n[WARNING] High probability this is a honeypot!")
            elif score >= 0.5:
                print("\
[CAUTION] Moderate probability this is a honeypot.")
            else:
                print("\n[INFO] Low probability this is a honeypot.")
            
            print(f"\
Score range: 0.0 (not a honeypot) to 1.0 (definitely a honeypot)")
            
        except shodan.APIError as e:
            print(f"\n[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def query_tags(self):
        """Option 15: Get Popular Query Tags"""
        self.clear_screen()
        print("=" * 60)
        print("  POPULAR QUERY TAGS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching popular query tags...")
            
            size = input("Number of tags to show (default 10): ").strip()
            size = int(size) if size else 10
            
            tags = self.api.search_cursor(facets={'tag': size})
            
            print(f"\
{'=' * 60}")
            print("Popular Tags:")
            print(f"{'=' * 60}")
            
            if hasattr(tags, 'facets') and tags.facets.get('tag'):
                for i, tag in enumerate(tags.facets['tag'], 1):
                    print(f"{i}. {tag['value']}: {tag['count']:,} results")
            else:
                print("\nNo tags available at this time.")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except ValueError:
            print("\
[ERROR] Invalid number format!")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def scan_internet(self):
        """Option 16: Submit IP for Scanning"""
        self.clear_screen()
        print("=" * 60)
        print("  SCAN INTERNET (Submit IP)")
        print("=" * 60)
        print()
        
        ip = input("Enter IP address to scan: ").strip()
        
        if not ip:
            print("\
[ERROR] IP address cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Submitting {ip} for scanning...")
            scan = self.api.scan(ip)
            
            print(f"\n{'=' * 60}")
            print(f"Scan submitted successfully!")
            print(f"Scan ID: {scan.get('id', 'N/A')}")
            print(f"Credits Left: {scan.get('credits_left', 'N/A')}")
            print(f"{'=' * 60}")
            print(f"\nUse option 17 (Scan Status) to check scan progress.")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def scan_status(self):
        """Option 17: Check Scan Status"""
        self.clear_screen()
        print("=" * 60)
        print("  SCAN STATUS")
        print("=" * 60)
        print()
        
        scan_id = input("Enter Scan ID: ").strip()
        
        if not scan_id:
            print("\
[ERROR] Scan ID cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Checking status for scan: {scan_id}")
            status = self.api.scan_status(scan_id)
            
            print(f"\
{'=' * 60}")
            print(f"Scan ID: {scan_id}")
            print(f"Status: {status.get('status', 'N/A')}")
            print(f"Count: {status.get('count', 0)}")
            print(f"{'=' * 60}")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def network_alerts(self):
        """Option 18: List Network Alerts"""
        self.clear_screen()
        print("=" * 60)
        print("  NETWORK ALERTS")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching network alerts...")
            alerts = self.api.alerts()
            
            print(f"\
{'=' * 60}")
            
            if alerts:
                print(f"Total Alerts: {len(alerts)}")
                print(f"{'=' * 60}")
                
                for i, alert in enumerate(alerts, 1):
                    print(f"\n--- Alert {i} ---")
                    print(f"ID: {alert.get('id', 'N/A')}")
                    print(f"Name: {alert.get('name', 'N/A')}")
                    print(f"Networks: {', '.join(alert.get('filters', {}).get('ip', []))}")
                    print(f"Created: {alert.get('created', 'N/A')}")
                    print(f"Expires: {alert.get('expires', 'N/A')}")
            else:
                print("No alerts configured.")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\nPress Enter to continue...")
    
    def create_alert(self):
        """Option 19: Create Network Alert"""
        self.clear_screen()
        print("=" * 60)
        print("  CREATE NETWORK ALERT")
        print("=" * 60)
        print()
        
        name = input("Enter alert name: ").strip()
        if not name:
            print("\
[ERROR] Alert name cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        ip_range = input("Enter IP or CIDR range (e.g., 192.168.1.0/24): ").strip()
        if not ip_range:
            print("\
[ERROR] IP range cannot be empty!")
            input("\
Press Enter to continue...")
            return
        
        try:
            print(f"\
[INFO] Creating alert...")
            alert = self.api.create_alert(name, ip_range)
            
            print(f"\
{'=' * 60}")
            print(f"Alert created successfully!")
            print(f"Alert ID: {alert.get('id', 'N/A')}")
            print(f"Name: {alert.get('name', 'N/A')}")
            print(f"{'=' * 60}")
            
        except shodan.APIError as e:
            print(f"\n[ERROR] {e}")
        except Exception as e:
            print(f"\
[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def notifier_list(self):
        """Option 20: List Available Notifiers"""
        self.clear_screen()
        print("=" * 60)
        print("  NOTIFIER LIST")
        print("=" * 60)
        print()
        
        try:
            print("[INFO] Fetching available notifiers...")
            notifiers = self.api.notifiers()
            
            print(f"\
{'=' * 60}")
            
            if notifiers:
                print(f"Available Notifiers: {len(notifiers)}")
                print(f"{'=' * 60}")
                
                for i, notifier in enumerate(notifiers, 1):
                    print(f"\
--- Notifier {i} ---")
                    print(f"ID: {notifier.get('id', 'N/A')}")
                    print(f"Provider: {notifier.get('provider', 'N/A')}")
                    print(f"Description: {notifier.get('description', 'N/A')}")
            else:
                print("No notifiers configured.")
            
        except shodan.APIError as e:
            print(f"\
[ERROR] {e}")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")
        
        input("\
Press Enter to continue...")
    
    def run(self):
        """Main application loop"""
        # Login first
        if not self.login():
            print("\
Exiting due to authentication failure.")
            sys.exit(1)
        
        # Menu loop
        while True:
            self.display_menu()
            
            choice = input("Enter your choice (0-20): ").strip()
            
            if choice == '0':
                self.clear_screen()
                print("\n" + "=" * 60)
                print("  Thank you for using Shodan Threat Intelligence Tool!")
                print("=" * 60)
                print()
                sys.exit(0)
            elif choice == '1':
                self.host_lookup()
            elif choice == '2':
                self.search_shodan()
            elif choice == '3':
                self.search_exploits()
            elif choice == '4':
                self.count_search()
            elif choice == '5':
                self.dns_lookup()
            elif choice == '6':
                self.dns_reverse()
            elif choice == '7':
                self.get_ports()
            elif choice == '8':
                self.get_protocols()
            elif choice == '9':
                self.get_services()
            elif choice == '10':
                self.account_info()
            elif choice == '11':
                self.api_plan_info()
            elif choice == '12':
                self.search_facets()
            elif choice == '13':
                self.search_filters()
            elif choice == '14':
                self.honeypot_score()
            elif choice == '15':
                self.query_tags()
            elif choice == '16':
                self.scan_internet()
            elif choice == '17':
                self.scan_status()
            elif choice == '18':
                self.network_alerts()
            elif choice == '19':
                self.create_alert()
            elif choice == '20':
                self.notifier_list()
            else:
                print("\
[ERROR] Invalid choice! Please select 0-20.")
                input("\nPress Enter to continue...")

def main():
    """Entry point for the application"""
    try:
        tool = ShodanThreatIntelTool()
        tool.run()
    except KeyboardInterrupt:
        print("\
\n[INFO] Program interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\
[FATAL ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()