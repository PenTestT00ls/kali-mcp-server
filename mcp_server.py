#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, List, Optional
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://192.168.20.130:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner.
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    # 信息收集工具 - 网络发现和端口扫描
    @mcp.tool()
    def masscan_scan(target: str, ports: str = "1-1000", rate: str = "1000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute masscan with the provided parameters.
        
        Args:
            target: The IP address or hostname to scan
            ports: Port range to scan (default: 1-1000)
            rate: Packets per second rate (default: 1000)
            additional_args: Additional masscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/masscan", data)

    @mcp.tool()
    def zmap_scan(target: str, port: str = "80", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute zmap with the provided parameters.
        
        Args:
            target: The IP address or hostname to scan
            port: Port to scan (default: 80)
            additional_args: Additional zmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "port": port,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/zmap", data)

    @mcp.tool()
    def unicornscan_scan(target: str, ports: str = "1-1000", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute unicornscan with the provided parameters.
        
        Args:
            target: The IP address or hostname to scan
            ports: Port range to scan (default: 1-1000)
            additional_args: Additional unicornscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/unicornscan", data)

    @mcp.tool()
    def netdiscover_scan(range: str = "192.168.1.0/24", interface: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute netdiscover with the provided parameters.
        
        Args:
            range: IP range to scan (default: 192.168.1.0/24)
            interface: Network interface to use
            additional_args: Additional netdiscover arguments
            
        Returns:
            Scan results
        """
        data = {
            "range": range,
            "interface": interface,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/netdiscover", data)

    @mcp.tool()
    def naabu_scan(target: str, ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute naabu with the provided parameters.
        
        Args:
            target: The IP address or hostname to scan
            ports: Ports to scan
            additional_args: Additional naabu arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/naabu", data)

    @mcp.tool()
    def rustscan_scan(target: str, ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute rustscan with the provided parameters.
        
        Args:
            target: The IP address or hostname to scan
            ports: Ports to scan
            additional_args: Additional rustscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/rustscan", data)

    # 信息收集工具 - DNS和域名分析
    @mcp.tool()
    def subfinder_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute subfinder with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional subfinder arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def amass_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute amass with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional amass arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/amass", data)

    @mcp.tool()
    def dnsrecon_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsrecon with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional dnsrecon arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dnsrecon", data)

    @mcp.tool()
    def dnsenum_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dnsenum with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional dnsenum arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dnsenum", data)

    @mcp.tool()
    def fierce_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute fierce with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional fierce arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/fierce", data)

    @mcp.tool()
    def findomain_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute findomain with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional findomain arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/findomain", data)

    @mcp.tool()
    def whois_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute whois with the provided parameters.
        
        Args:
            domain: Domain name to query
            additional_args: Additional whois arguments
            
        Returns:
            Whois query results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/whois", data)

    # 信息收集工具 - 网络服务识别
    @mcp.tool()
    def whatweb_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute whatweb with the provided parameters.
        
        Args:
            target: Target URL or IP address
            additional_args: Additional whatweb arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/whatweb", data)

    @mcp.tool()
    def wafw00f_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wafw00f with the provided parameters.
        
        Args:
            target: Target URL or IP address
            additional_args: Additional wafw00f arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wafw00f", data)

    # 信息收集工具 - Web目录和文件扫描
    @mcp.tool()
    def dirsearch_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute dirsearch with the provided parameters.
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            extensions: File extensions to scan
            additional_args: Additional dirsearch arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "extensions": extensions,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirsearch", data)

    @mcp.tool()
    def feroxbuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute feroxbuster with the provided parameters.
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            additional_args: Additional feroxbuster arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/feroxbuster", data)

    @mcp.tool()
    def katana_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute katana with the provided parameters.
        
        Args:
            url: Target URL
            additional_args: Additional katana arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/katana", data)

    @mcp.tool()
    def meg_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute meg with the provided parameters.
        
        Args:
            url: Target URL
            wordlist: Path to wordlist file
            additional_args: Additional meg arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/meg", data)

    @mcp.tool()
    def arjun_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arjun with the provided parameters.
        
        Args:
            url: Target URL
            additional_args: Additional arjun arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/arjun", data)

    @mcp.tool()
    def paramspider_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute paramspider with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional paramspider arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/paramspider", data)

    @mcp.tool()
    def waybackurls_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute waybackurls with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional waybackurls arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/waybackurls", data)

    @mcp.tool()
    def gau_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute gau with the provided parameters.
        
        Args:
            domain: Domain name to scan
            additional_args: Additional gau arguments
            
        Returns:
            Scan results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gau", data)

    # 漏洞分析工具
    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute nuclei with the provided parameters.
        
        Args:
            target: Target URL or IP address
            templates: Nuclei templates to use
            additional_args: Additional nuclei arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "templates": templates,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nuclei", data)

    @mcp.tool()
    def vulmap_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute vulmap with the provided parameters.
        
        Args:
            target: Target URL or IP address
            additional_args: Additional vulmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/vulmap", data)

    @mcp.tool()
    def lynis_scan(target: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute lynis with the provided parameters.
        
        Args:
            target: Target system (optional)
            additional_args: Additional lynis arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/lynis", data)

    @mcp.tool()
    def chkrootkit_scan(target: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute chkrootkit with the provided parameters.
        
        Args:
            target: Target system (optional)
            additional_args: Additional chkrootkit arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/chkrootkit", data)

    @mcp.tool()
    def rkhunter_scan(target: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute rkhunter with the provided parameters.
        
        Args:
            target: Target system (optional)
            additional_args: Additional rkhunter arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/rkhunter", data)

    @mcp.tool()
    def clamav_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute clamav with the provided parameters.
        
        Args:
            target: Target file or directory
            additional_args: Additional clamav arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/clamav", data)

    # Web应用分析工具
    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute sqlmap with the provided parameters.
        
        Args:
            url: Target URL
            data: POST data string
            additional_args: Additional sqlmap arguments
            
        Returns:
            Scan results
        """
        data_params = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", data_params)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wpscan with the provided parameters.
        
        Args:
            url: Target WordPress URL
            additional_args: Additional wpscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def joomscan_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute joomscan with the provided parameters.
        
        Args:
            url: Target Joomla URL
            additional_args: Additional joomscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/joomscan", data)

    @mcp.tool()
    def droopescan_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute droopescan with the provided parameters.
        
        Args:
            url: Target Drupal URL
            additional_args: Additional droopescan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/droopescan", data)

    @mcp.tool()
    def cmsmap_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute cmsmap with the provided parameters.
        
        Args:
            url: Target CMS URL
            additional_args: Additional cmsmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/cmsmap", data)

    @mcp.tool()
    def wapiti_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wapiti with the provided parameters.
        
        Args:
            url: Target URL
            additional_args: Additional wapiti arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wapiti", data)

    @mcp.tool()
    def arachni_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute arachni with the provided parameters.
        
        Args:
            url: Target URL
            additional_args: Additional arachni arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/arachni", data)

    @mcp.tool()
    def skipfish_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute skipfish with the provided parameters.
        
        Args:
            url: Target URL
            additional_args: Additional skipfish arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/skipfish", data)

    # 密码攻击类工具
    @mcp.tool()
    def hydra_attack(target: str, service: str, username: str = "", username_file: str = "", 
                    password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute hydra password cracking tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", 
                  format_type: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format_type": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def hashcat_attack(hash: str, hash_type: str = "0", 
                      wordlist: str = "/usr/share/wordlists/rockyou.txt", 
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute hashcat password recovery tool.
        
        Args:
            hash: Hash value to crack
            hash_type: Hash type identifier
            wordlist: Path to wordlist file
            additional_args: Additional hashcat arguments
            
        Returns:
            Attack results
        """
        data = {
            "hash": hash,
            "hash_type": hash_type,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hashcat", data)

    @mcp.tool()
    def medusa_attack(target: str, service: str, username: str = "", username_file: str = "", 
                     password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute medusa network login cracker.
        
        Args:
            target: Target IP or hostname
            service: Service to attack
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional medusa arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/medusa", data)

    @mcp.tool()
    def patator_attack(module: str, target: str, username: str = "", username_file: str = "", 
                      password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute patator multi-purpose brute-forcer.
        
        Args:
            module: Attack module to use
            target: Target IP or hostname
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional patator arguments
            
        Returns:
            Attack results
        """
        data = {
            "module": module,
            "target": target,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/patator", data)

    @mcp.tool()
    def crowbar_attack(target: str, service: str, username: str = "", username_file: str = "", 
                      password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute crowbar brute force tool.
        
        Args:
            target: Target IP or hostname
            service: Service to attack
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional crowbar arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/crowbar", data)

    # 无线攻击类工具
    @mcp.tool()
    def aircrack_scan(interface: str = "", bssid: str = "", capture_file: str = "", 
                     wordlist: str = "/usr/share/wordlists/rockyou.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute aircrack-ng wireless security tool.
        
        Args:
            interface: Wireless interface to use
            bssid: Target BSSID
            capture_file: Path to capture file
            wordlist: Path to wordlist file
            additional_args: Additional aircrack arguments
            
        Returns:
            Scan results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "capture_file": capture_file,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/aircrack", data)

    @mcp.tool()
    def reaver_attack(interface: str, bssid: str, channel: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute reaver WPS attack tool.
        
        Args:
            interface: Wireless interface to use
            bssid: Target BSSID
            channel: Wireless channel
            additional_args: Additional reaver arguments
            
        Returns:
            Attack results
        """
        data = {
            "interface": interface,
            "bssid": bssid,
            "channel": channel,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/reaver", data)

    @mcp.tool()
    def wifite_scan(interface: str, target_bssid: str = "", channel: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wifite automated wireless attack tool.
        
        Args:
            interface: Wireless interface to use
            target_bssid: Target BSSID
            channel: Wireless channel
            additional_args: Additional wifite arguments
            
        Returns:
            Scan results
        """
        data = {
            "interface": interface,
            "target_bssid": target_bssid,
            "channel": channel,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wifite", data)

    @mcp.tool()
    def wifiphisher_attack(interface: str, channel: str = "", essid: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute wifiphisher wireless phishing tool.
        
        Args:
            interface: Wireless interface to use
            channel: Wireless channel
            essid: Target ESSID
            additional_args: Additional wifiphisher arguments
            
        Returns:
            Attack results
        """
        data = {
            "interface": interface,
            "channel": channel,
            "essid": essid,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wifiphisher", data)

    # 漏洞利用类工具
    @mcp.tool()
    def beef_exploit(hook_url: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute BeEF browser exploitation framework.
        
        Args:
            hook_url: Hook URL for BeEF
            additional_args: Additional BeEF arguments
            
        Returns:
            Exploitation results
        """
        data = {
            "hook_url": hook_url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/beef", data)

    @mcp.tool()
    def empire_exploit(listener_name: str = "", listener_type: str = "http", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Empire post-exploitation framework.
        
        Args:
            listener_name: Listener name for Empire
            listener_type: Listener type (http, https, etc.)
            additional_args: Additional Empire arguments
            
        Returns:
            Exploitation results
        """
        data = {
            "listener_name": listener_name,
            "listener_type": listener_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/empire", data)

    @mcp.tool()
    def set_attack(attack_vector: str, payload: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Social Engineer Toolkit.
        
        Args:
            attack_vector: Attack vector to use
            payload: Payload to deliver
            additional_args: Additional SET arguments
            
        Returns:
            Attack results
        """
        data = {
            "attack_vector": attack_vector,
            "payload": payload,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/set", data)

    @mcp.tool()
    def gophish_attack(config_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GoPhish phishing framework.
        
        Args:
            config_file: Configuration file for GoPhish
            additional_args: Additional GoPhish arguments
            
        Returns:
            Attack results
        """
        data = {
            "config_file": config_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gophish", data)

    # 后渗透测试类工具
    @mcp.tool()
    def mimikatz_attack(command: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Mimikatz Windows credential extraction tool.
        
        Args:
            command: Mimikatz command to execute
            additional_args: Additional arguments for Mimikatz
            
        Returns:
            Attack results
        """
        data = {
            "command": command,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/mimikatz", data)

    @mcp.tool()
    def powersploit_exploit(module: str = "", script_path: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute PowerSploit PowerShell penetration testing framework.
        
        Args:
            module: PowerSploit module to use
            script_path: Path to PowerShell script
            additional_args: Additional arguments for PowerSploit
            
        Returns:
            Exploitation results
        """
        data = {
            "module": module,
            "script_path": script_path,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/powersploit", data)

    @mcp.tool()
    def psexec_attack(target: str, command: str, username: str = "", password: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute PsExec remote execution tool.
        
        Args:
            target: Target Windows machine
            command: Command to execute on target
            username: Username for authentication
            password: Password for authentication
            additional_args: Additional arguments for PsExec
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "command": command,
            "username": username,
            "password": password,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/psexec", data)

    @mcp.tool()
    def winexe_attack(target: str, command: str, username: str = "", password: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Winexe Windows remote command execution tool.
        
        Args:
            target: Target Windows machine
            command: Command to execute on target
            username: Username for authentication
            password: Password for authentication
            additional_args: Additional arguments for Winexe
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "command": command,
            "username": username,
            "password": password,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/winexe", data)

    # Web扫描和爬虫工具
    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute FFuF web fuzzing tool.
        
        Args:
            url: Target URL to scan
            wordlist: Path to wordlist file
            extensions: File extensions to scan (e.g., php,html)
            additional_args: Additional FFuF arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "extensions": extensions,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ffuf", data)

    @mcp.tool()
    def wfuzz_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", payload: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wfuzz web application fuzzer.
        
        Args:
            url: Target URL to scan
            wordlist: Path to wordlist file
            payload: Payload to fuzz
            additional_args: Additional Wfuzz arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "payload": payload,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wfuzz", data)

    @mcp.tool()
    def cewl_generate(url: str, depth: int = 2, min_word_length: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute CeWL custom wordlist generator.
        
        Args:
            url: Target URL to crawl
            depth: Crawling depth
            min_word_length: Minimum word length
            additional_args: Additional CeWL arguments
            
        Returns:
            Generated wordlist
        """
        data = {
            "url": url,
            "depth": depth,
            "min_word_length": min_word_length,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/cewl", data)

    @mcp.tool()
    def scrapy_crawl(url: str, spider: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Scrapy web crawling framework.
        
        Args:
            url: Target URL to crawl
            spider: Spider to use
            output_file: Output file for results
            additional_args: Additional Scrapy arguments
            
        Returns:
            Crawling results
        """
        data = {
            "url": url,
            "spider": spider,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/scrapy", data)

    @mcp.tool()
    def gospider_scan(url: str, threads: int = 10, depth: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GoSpider web spider.
        
        Args:
            url: Target URL to scan
            threads: Number of threads
            depth: Crawling depth
            additional_args: Additional GoSpider arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "threads": threads,
            "depth": depth,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gospider", data)

    @mcp.tool()
    def linkfinder_analyze(url: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute LinkFinder JavaScript endpoint discovery tool.
        
        Args:
            url: Target URL to analyze
            output_file: Output file for results
            additional_args: Additional LinkFinder arguments
            
        Returns:
            Analysis results
        """
        data = {
            "url": url,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/linkfinder", data)

    @mcp.tool()
    def js_scan_analyze(url: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute JS-Scan JavaScript analysis tool.
        
        Args:
            url: Target URL to analyze
            output_file: Output file for results
            additional_args: Additional JS-Scan arguments
            
        Returns:
            Analysis results
        """
        data = {
            "url": url,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/js_scan", data)

    @mcp.tool()
    def secretfinder_scan(url: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SecretFinder secret discovery tool.
        
        Args:
            url: Target URL to scan
            output_file: Output file for results
            additional_args: Additional SecretFinder arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/secretfinder", data)

    # 渗透测试报告生成工具
    @mcp.tool()
    def dradis_report(project_name: str, template: str = "default", output_format: str = "pdf", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate penetration testing report using Dradis.
        
        Args:
            project_name: Name of the Dradis project
            template: Report template to use
            output_format: Output format (pdf, html, docx)
            additional_args: Additional Dradis arguments
            
        Returns:
            Report generation results
        """
        data = {
            "project_name": project_name,
            "template": template,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dradis", data)

    @mcp.tool()
    def serpico_report(template: str = "default", findings_file: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate penetration testing report using Serpico.
        
        Args:
            template: Report template to use
            findings_file: Path to findings file
            output_file: Output file path
            additional_args: Additional Serpico arguments
            
        Returns:
            Report generation results
        """
        data = {
            "template": template,
            "findings_file": findings_file,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/serpico", data)

    @mcp.tool()
    def faraday_report(workspace: str, template: str = "default", output_format: str = "html", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate collaborative penetration testing report using Faraday.
        
        Args:
            workspace: Faraday workspace name
            template: Report template to use
            output_format: Output format (html, pdf, json)
            additional_args: Additional Faraday arguments
            
        Returns:
            Report generation results
        """
        data = {
            "workspace": workspace,
            "template": template,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/faraday", data)

    @mcp.tool()
    def magictree_report(xml_file: str, template: str = "default", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate penetration testing report using MagicTree.
        
        Args:
            xml_file: Path to XML data file
            template: Report template to use
            output_file: Output file path
            additional_args: Additional MagicTree arguments
            
        Returns:
            Report generation results
        """
        data = {
            "xml_file": xml_file,
            "template": template,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/magictree", data)

    @mcp.tool()
    def pipal_analyze(password_file: str, analysis_type: str = "basic", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate password analysis report using Pipal.
        
        Args:
            password_file: Path to password file
            analysis_type: Type of analysis (basic, advanced, full)
            output_file: Output file path
            additional_args: Additional Pipal arguments
            
        Returns:
            Password analysis results
        """
        data = {
            "password_file": password_file,
            "analysis_type": analysis_type,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/pipal", data)

    @mcp.tool()
    def generate_consolidated_report(tool_results: List[str], template: str = "comprehensive", output_format: str = "pdf", additional_args: str = "") -> Dict[str, Any]:
        """
        Generate consolidated penetration testing report from multiple tool results.
        
        Args:
            tool_results: List of tool result files/paths
            template: Report template to use
            output_format: Output format (pdf, html, docx)
            additional_args: Additional arguments
            
        Returns:
            Consolidated report generation results
        """
        data = {
            "tool_results": tool_results,
            "template": template,
            "output_format": output_format,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/consolidated_report", data)

    @mcp.tool()
    def hakrawler_scan(url: str, depth: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hakrawler web crawler.
        
        Args:
            url: Target URL to scan
            depth: Crawling depth
            additional_args: Additional Hakrawler arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "depth": depth,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hakrawler", data)

    @mcp.tool()
    def crawley_scan(url: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Crawley web crawler.
        
        Args:
            url: Target URL to scan
            output_file: Output file for results
            additional_args: Additional Crawley arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/crawley", data)

    @mcp.tool()
    def photon_scan(url: str, threads: int = 10, level: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Photon web crawler.
        
        Args:
            url: Target URL to scan
            threads: Number of threads
            level: Crawling level
            additional_args: Additional Photon arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "threads": threads,
            "level": level,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/photon", data)

    # 网络分析工具
    @mcp.tool()
    def netcat_scan(target: str, port: int, listen: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Netcat network utility.
        
        Args:
            target: Target host or IP
            port: Target port
            listen: Listen mode
            additional_args: Additional Netcat arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "port": port,
            "listen": listen,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/netcat", data)

    @mcp.tool()
    def traceroute_scan(target: str, max_ttl: int = 30, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Traceroute network diagnostic tool.
        
        Args:
            target: Target host or IP
            max_ttl: Maximum TTL value
            additional_args: Additional Traceroute arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "max_ttl": max_ttl,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/traceroute", data)

    @mcp.tool()
    def tcpdump_capture(interface: str = "any", filter: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Tcpdump packet analyzer.
        
        Args:
            interface: Network interface to capture
            filter: Packet filter expression
            output_file: Output file for capture
            additional_args: Additional Tcpdump arguments
            
        Returns:
            Capture results
        """
        data = {
            "interface": interface,
            "filter": filter,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/tcpdump", data)

    @mcp.tool()
    def socat_connect(source: str, destination: str, options: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Socat multipurpose relay tool.
        
        Args:
            source: Source address specification
            destination: Destination address specification
            options: Socat options
            additional_args: Additional Socat arguments
            
        Returns:
            Connection results
        """
        data = {
            "source": source,
            "destination": destination,
            "options": options,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/socat", data)

    # 漏洞扫描工具
    @mcp.tool()
    def nmap_nse_scan(target: str, script: str = "", script_args: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nmap with NSE scripts.
        
        Args:
            target: Target host or IP
            script: NSE script to run
            script_args: Script arguments
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "script": script,
            "script_args": script_args,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap_nse", data)

    @mcp.tool()
    def vulners_scan(target: str, port: int = 0, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Vulners vulnerability scanner.
        
        Args:
            target: Target host or IP
            port: Target port
            additional_args: Additional Vulners arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "port": port,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/vulners", data)

    @mcp.tool()
    def sn1per_scan(target: str, mode: str = "recon", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Sn1per penetration testing framework.
        
        Args:
            target: Target host or IP
            mode: Scan mode (recon, port, web, etc.)
            additional_args: Additional Sn1per arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "mode": mode,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sn1per", data)

    @mcp.tool()
    def lazyrecon_scan(target: str, output_dir: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute LazyRecon reconnaissance framework.
        
        Args:
            target: Target domain or IP
            output_dir: Output directory
            additional_args: Additional LazyRecon arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "output_dir": output_dir,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/lazyrecon", data)

    # 密码分析工具
    @mcp.tool()
    def crunch_generate(min_length: int, max_length: int, charset: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Crunch wordlist generator.
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            charset: Character set to use
            output_file: Output file for wordlist
            additional_args: Additional Crunch arguments
            
        Returns:
            Generated wordlist
        """
        data = {
            "min_length": min_length,
            "max_length": max_length,
            "charset": charset,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/crunch", data)

    @mcp.tool()
    def johnny_attack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Johnny password cracker.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            additional_args: Additional Johnny arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/johnny", data)

    @mcp.tool()
    def hash_identifier_analyze(hash_string: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Hash-Identifier hash type analyzer.
        
        Args:
            hash_string: Hash string to identify
            additional_args: Additional Hash-Identifier arguments
            
        Returns:
            Analysis results
        """
        data = {
            "hash_string": hash_string,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hash_identifier", data)

    @mcp.tool()
    def wordlists_manage(action: str = "list", wordlist_path: str = "", search_term: str = "", output_file: str = "", min_length: str = "", max_length: str = "", pattern: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Manage and manipulate wordlists.
        
        Args:
            action: Action to perform (list, search, combine, filter)
            wordlist_path: Path to wordlist file(s)
            search_term: Term to search for in wordlist
            output_file: Output file for results
            min_length: Minimum word length for filtering
            max_length: Maximum word length for filtering
            pattern: Pattern to match for filtering
            additional_args: Additional wordlists arguments
            
        Returns:
            Wordlist management results
        """
        data = {
            "action": action,
            "wordlist_path": wordlist_path,
            "search_term": search_term,
            "output_file": output_file,
            "min_length": min_length,
            "max_length": max_length,
            "pattern": pattern,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wordlists", data)

    # 逆向工程工具
    @mcp.tool()
    def ghidra_analyze(file_path: str, script: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Ghidra reverse engineering framework.
        
        Args:
            file_path: Path to file to analyze
            script: Ghidra script to run
            additional_args: Additional Ghidra arguments
            
        Returns:
            Analysis results
        """
        data = {
            "file_path": file_path,
            "script": script,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ghidra", data)

    @mcp.tool()
    def ollydbg_analyze(file_path: str, breakpoint: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OllyDbg debugger.
        
        Args:
            file_path: Path to executable file
            breakpoint: Breakpoint to set
            additional_args: Additional OllyDbg arguments
            
        Returns:
            Analysis results
        """
        data = {
            "file_path": file_path,
            "breakpoint": breakpoint,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ollydbg", data)

    @mcp.tool()
    def gdb_analyze(file_path: str, command: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB debugger.
        
        Args:
            file_path: Path to executable file
            command: GDB command to execute
            additional_args: Additional GDB arguments
            
        Returns:
            Analysis results
        """
        data = {
            "file_path": file_path,
            "command": command,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gdb", data)

    # 其他安全工具
    @mcp.tool()
    def exploitdb_search(query: str, platform: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ExploitDB search.
        
        Args:
            query: Search query
            platform: Target platform
            additional_args: Additional ExploitDB arguments
            
        Returns:
            Search results
        """
        data = {
            "query": query,
            "platform": platform,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/exploitdb", data)

    @mcp.tool()
    def mobsf_analyze(file_path: str, scan_type: str = "static", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute MobSF mobile security framework.
        
        Args:
            file_path: Path to mobile app file
            scan_type: Scan type (static, dynamic)
            additional_args: Additional MobSF arguments
            
        Returns:
            Analysis results
        """
        data = {
            "file_path": file_path,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/mobsf", data)

    @mcp.tool()
    def apktool_decompile(apk_file: str, output_dir: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Apktool APK decompiler.
        
        Args:
            apk_file: Path to APK file
            output_dir: Output directory
            additional_args: Additional Apktool arguments
            
        Returns:
            Decompilation results
        """
        data = {
            "apk_file": apk_file,
            "output_dir": output_dir,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/apktool", data)

    @mcp.tool()
    def pacu_attack(module: str = "", target: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Pacu AWS exploitation framework.
        
        Args:
            module: Pacu module to run
            target: Target AWS account
            additional_args: Additional Pacu arguments
            
        Returns:
            Attack results
        """
        data = {
            "module": module,
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/pacu", data)

    @mcp.tool()
    def scout_suite_scan(target: str, service: str = "aws", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Scout Suite cloud security scanner.
        
        Args:
            target: Target cloud environment
            service: Cloud service (aws, azure, gcp)
            additional_args: Additional Scout Suite arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "service": service,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/scout_suite", data)

    @mcp.tool()
    def cloudsploit_scan(service: str = "aws", scan_type: str = "all", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute CloudSploit cloud security scanner.
        
        Args:
            service: Cloud service (aws, azure, gcp)
            scan_type: Scan type (all, compliance, security)
            additional_args: Additional CloudSploit arguments
            
        Returns:
            Scan results
        """
        data = {
            "service": service,
            "scan_type": scan_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/cloudsploit", data)

    @mcp.tool()
    def firmwalker_scan(firmware_path: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Firmwalker firmware analysis tool.
        
        Args:
            firmware_path: Path to firmware file
            output_file: Output file for results
            additional_args: Additional Firmwalker arguments
            
        Returns:
            Analysis results
        """
        data = {
            "firmware_path": firmware_path,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/firmwalker", data)

    @mcp.tool()
    def iotseeker_scan(firmware_path: str, output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute IoTSeeker IoT device scanner.
        
        Args:
            firmware_path: Path to firmware file
            output_file: Output file for results
            additional_args: Additional IoTSeeker arguments
            
        Returns:
            Scan results
        """
        data = {
            "firmware_path": firmware_path,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/iotseeker", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.
        
        Args:
            command: The command to execute
            
        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)

    @mcp.tool()
    def sublist3r_scan(domain: str, threads: int = 40, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Sublist3r subdomain enumeration tool.
        
        Args:
            domain: Target domain name
            threads: Number of threads to use
            additional_args: Additional Sublist3r arguments
            
        Returns:
            Subdomain enumeration results
        """
        data = {
            "domain": domain,
            "threads": threads,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sublist3r", data)

    @mcp.tool()
    def openvas_scan(target: str, scan_config: str = "Full and fast", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute OpenVAS vulnerability scanner.
        
        Args:
            target: Target IP or hostname
            scan_config: Scan configuration profile
            additional_args: Additional OpenVAS arguments
            
        Returns:
            Vulnerability scan results
        """
        data = {
            "target": target,
            "scan_config": scan_config,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/openvas", data)

    @mcp.tool()
    def netsparker_scan(url: str, scan_profile: str = "Full Scan", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Netsparker web application security scanner.
        
        Args:
            url: Target URL
            scan_profile: Scan profile configuration
            additional_args: Additional Netsparker arguments
            
        Returns:
            Web application scan results
        """
        data = {
            "url": url,
            "scan_profile": scan_profile,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/netsparker", data)

    @mcp.tool()
    def wireshark_capture(interface: str = "any", capture_filter: str = "", output_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Wireshark network protocol analyzer.
        
        Args:
            interface: Network interface to capture on
            capture_filter: BPF capture filter expression
            output_file: Output file for captured packets
            additional_args: Additional Wireshark/tshark arguments
            
        Returns:
            Network capture results
        """
        data = {
            "interface": interface,
            "capture_filter": capture_filter,
            "output_file": output_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wireshark", data)

    @mcp.tool()
    def xsser_scan(url: str, payload: str = "", method: str = "GET", additional_args: str = "") -> Dict[str, Any]:
        """Execute XSSer XSS vulnerability scanner.
        
        Args:
            url: The target URL
            payload: Custom XSS payload to test
            method: HTTP method to use (GET, POST, etc.)
            additional_args: Additional XSSer arguments
            
        Returns:
            XSS vulnerability scan results
        """
        data = {
            "url": url,
            "payload": payload,
            "method": method,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/xsser", data)

    @mcp.tool()
    def autorecon_scan(targets: List[str] = None, target_file: str = "", ports: str = "", 
                      max_scans: str = "50", output_dir: str = "results", 
                      additional_args: str = "") -> Dict[str, Any]:
        """Execute AutoRecon automated reconnaissance tool.
        
        Args:
            targets: List of target IPs, CIDR ranges, or hostnames
            target_file: Path to file containing targets (one per line)
            ports: Comma-separated list of ports/port ranges to scan
            max_scans: Maximum number of concurrent scans (default: 50)
            output_dir: Output directory for results (default: results)
            additional_args: Additional AutoRecon arguments
            
        Returns:
            Automated reconnaissance results
        """
        if targets is None:
            targets = []
        
        data = {
            "targets": targets,
            "target_file": target_file,
            "ports": ports,
            "max_scans": max_scans,
            "output_dir": output_dir,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/autorecon", data)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    mcp.run()

if __name__ == "__main__":
    main()
