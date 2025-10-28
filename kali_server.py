#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
from datetime import datetime
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500





@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 信息收集工具 - 网络发现和端口扫描
@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute masscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        rate = params.get("rate", "1000")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Masscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"masscan -p {ports} --rate={rate} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/zmap", methods=["POST"])
def zmap():
    """Execute zmap with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "80")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Zmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"zmap -p {port} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in zmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/unicornscan", methods=["POST"])
def unicornscan():
    """Execute unicornscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Unicornscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"unicornscan -mU -p {ports} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in unicornscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/netdiscover", methods=["POST"])
def netdiscover():
    """Execute netdiscover with the provided parameters."""
    try:
        params = request.json
        range = params.get("range", "192.168.1.0/24")
        interface = params.get("interface", "")
        additional_args = params.get("additional_args", "")
        
        if not range:
            logger.warning("Netdiscover called without range parameter")
            return jsonify({
                "error": "Range parameter is required"
            }), 400
        
        command = f"netdiscover -r {range}"
        
        if interface:
            command += f" -i {interface}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in netdiscover endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/naabu", methods=["POST"])
def naabu():
    """Execute naabu with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Naabu called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = "naabu"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" -host {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in naabu endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/rustscan", methods=["POST"])
def rustscan():
    """Execute rustscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Rustscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = "rustscan"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in rustscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 信息收集工具 - DNS和域名分析
@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute subfinder with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Subfinder called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"subfinder -d {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in subfinder endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute amass with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Amass called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"amass enum -d {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in amass endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dnsrecon", methods=["POST"])
def dnsrecon():
    """Execute dnsrecon with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("DNSRecon called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"dnsrecon -d {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsrecon endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("DNSEnum called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"dnsenum {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsenum endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Fierce called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"fierce --domain {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in fierce endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sublist3r", methods=["POST"])
def sublist3r():
    """Execute Sublist3r with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Sublist3r called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"sublist3r -d {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sublist3r endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/findomain", methods=["POST"])
def findomain():
    """Execute findomain with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Findomain called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"findomain -t {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in findomain endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/whois", methods=["POST"])
def whois():
    """Execute whois with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Whois called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"whois {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whois endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 信息收集工具 - 网络服务识别
@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Execute whatweb with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Whatweb called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"whatweb {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"wafw00f {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wafw00f endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 信息收集工具 - Web目录和文件扫描
@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute dirsearch with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = params.get("extensions", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirsearch called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirsearch -u {url} -w {wordlist}"
        
        if extensions:
            command += f" -e {extensions}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirsearch endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute feroxbuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Feroxbuster called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"feroxbuster -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in feroxbuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/katana", methods=["POST"])
def katana():
    """Execute katana with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Katana called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"katana -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in katana endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/meg", methods=["POST"])
def meg():
    """Execute meg with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Meg called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"meg {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in meg endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute arjun with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Arjun called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"arjun -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in arjun endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """Execute paramspider with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("ParamSpider called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"paramspider --domain {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in paramspider endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute waybackurls with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Waybackurls called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"waybackurls {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in waybackurls endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gau", methods=["POST"])
def gau():
    """Execute gau with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Gau called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"gau {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gau endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 漏洞分析工具 - 网络漏洞扫描
@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute nuclei with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        templates = params.get("templates", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nuclei -u {target}"
        
        if templates:
            command += f" -t {templates}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/openvas", methods=["POST"])
def openvas():
    """Execute OpenVAS with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_config = params.get("scan_config", "Full and fast")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("OpenVAS called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        # OpenVAS 通常通过 omp 命令进行扫描
        command = f"omp --target={target} --config-name=\"{scan_config}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in openvas endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/vulmap", methods=["POST"])
def vulmap():
    """Execute vulmap with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Vulmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"vulmap -u {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in vulmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/lynis", methods=["POST"])
def lynis():
    """Execute lynis with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Lynis called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"lynis audit system"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in lynis endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/chkrootkit", methods=["POST"])
def chkrootkit():
    """Execute chkrootkit with the provided parameters."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")
        
        command = "chkrootkit"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in chkrootkit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/rkhunter", methods=["POST"])
def rkhunter():
    """Execute rkhunter with the provided parameters."""
    try:
        params = request.json
        additional_args = params.get("additional_args", "")
        
        command = "rkhunter --check"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in rkhunter endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/clamav", methods=["POST"])
def clamav():
    """Execute clamav with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("ClamAV called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"clamscan {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in clamav endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Web应用分析工具



@app.route("/api/tools/joomscan", methods=["POST"])
def joomscan():
    """Execute joomscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("JoomScan called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"joomscan -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in joomscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/droopescan", methods=["POST"])
def droopescan():
    """Execute droopescan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Droopescan called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"droopescan scan drupal -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in droopescan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cmsmap", methods=["POST"])
def cmsmap():
    """Execute cmsmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("CMSMap called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"cmsmap -t {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cmsmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wapiti", methods=["POST"])
def wapiti():
    """Execute wapiti with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Wapiti called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wapiti -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wapiti endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/arachni", methods=["POST"])
def arachni():
    """Execute arachni with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Arachni called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"arachni {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in arachni endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/netsparker", methods=["POST"])
def netsparker():
    """Execute Netsparker with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        scan_profile = params.get("scan_profile", "Full Scan")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Netsparker called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Netsparker 通常通过命令行工具进行扫描
        command = f"netsparker -u {url} --profile=\"{scan_profile}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in netsparker endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/skipfish", methods=["POST"])
def skipfish():
    """Execute skipfish with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Skipfish called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"skipfish -o /tmp/skipfish_output {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in skipfish endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 密码攻击类工具
@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra password cracking tool."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without required parameters")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        command_parts = ["hydra"]
        
        if username:
            command_parts.extend(["-l", username])
        elif username_file:
            command_parts.extend(["-L", username_file])
        
        if password:
            command_parts.extend(["-p", password])
        elif password_file:
            command_parts.extend(["-P", password_file])
        
        command_parts.extend([service, target])
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john the ripper password cracker."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format_type", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command_parts = ["john"]
        
        if wordlist:
            command_parts.extend(["--wordlist", wordlist])
        
        if format_type:
            command_parts.extend(["--format", format_type])
        
        command_parts.append(hash_file)
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute hashcat password recovery tool."""
    try:
        params = request.json
        hash_value = params.get("hash", "")
        hash_type = params.get("hash_type", "0")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        additional_args = params.get("additional_args", "")
        
        if not hash_value:
            logger.warning("Hashcat called without hash parameter")
            return jsonify({
                "error": "Hash parameter is required"
            }), 400
        
        command_parts = ["hashcat", "-m", hash_type, "-a", "0"]
        
        if wordlist:
            command_parts.append(wordlist)
        
        command_parts.append(hash_value)
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hashcat endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/medusa", methods=["POST"])
def medusa():
    """Execute medusa network login cracker."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Medusa called without required parameters")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        command_parts = ["medusa", "-h", target, "-M", service]
        
        if username:
            command_parts.extend(["-u", username])
        elif username_file:
            command_parts.extend(["-U", username_file])
        
        if password:
            command_parts.extend(["-p", password])
        elif password_file:
            command_parts.extend(["-P", password_file])
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in medusa endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/patator", methods=["POST"])
def patator():
    """Execute patator multi-purpose brute-forcer."""
    try:
        params = request.json
        module = params.get("module", "")
        target = params.get("target", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not module or not target:
            logger.warning("Patator called without required parameters")
            return jsonify({
                "error": "Module and target parameters are required"
            }), 400
        
        command_parts = ["patator", module, "host", target]
        
        if username:
            command_parts.extend(["user", username])
        elif username_file:
            command_parts.extend(["user_file", username_file])
        
        if password:
            command_parts.extend(["password", password])
        elif password_file:
            command_parts.extend(["password_file", password_file])
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in patator endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/crowbar", methods=["POST"])
def crowbar():
    """Execute crowbar brute force tool."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Crowbar called without required parameters")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        command_parts = ["crowbar", "-b", service, "-s", target]
        
        if username:
            command_parts.extend(["-u", username])
        elif username_file:
            command_parts.extend(["-U", username_file])
        
        if password:
            command_parts.extend(["-p", password])
        elif password_file:
            command_parts.extend(["-P", password_file])
        
        if additional_args:
            command_parts.append(additional_args)
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in crowbar endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# 无线攻击类工具
@app.route("/api/tools/aircrack", methods=["POST"])
def aircrack():
    """Execute aircrack-ng wireless security tool."""
    try:
        params = request.json
        interface = params.get("interface", "")
        bssid = params.get("bssid", "")
        capture_file = params.get("capture_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        additional_args = params.get("additional_args", "")
        
        if not interface and not capture_file:
            logger.warning("Aircrack called without interface or capture file parameter")
            return jsonify({
                "error": "Interface or capture file parameter is required"
            }), 400
        
        command_parts = ["aircrack-ng"]
        
        if bssid:
            command_parts.extend(["-b", bssid])
        
        if wordlist:
            command_parts.extend(["-w", wordlist])
        
        if additional_args:
            command_parts.append(additional_args)
        
        if capture_file:
            command_parts.append(capture_file)
        else:
            # If no capture file, start monitoring mode
            command_parts.extend(["-a", "1", interface])
        
        command = " ".join(command_parts)
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in aircrack endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/reaver", methods=["POST"])
def reaver():
    """Execute reaver WPS attack tool."""
    try:
        params = request.json
        interface = params.get("interface", "")
        bssid = params.get("bssid", "")
        channel = params.get("channel", "")
        additional_args = params.get("additional_args", "")
        
        if not interface or not bssid:
            logger.warning("Reaver called without interface or BSSID parameter")
            return jsonify({
                "error": "Interface and BSSID parameters are required"
            }), 400
        
        command = f"reaver -i {interface} -b {bssid}"
        
        if channel:
            command += f" -c {channel}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in reaver endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wifite", methods=["POST"])
def wifite():
    """Execute wifite automated wireless attack tool."""
    try:
        params = request.json
        interface = params.get("interface", "")
        target_bssid = params.get("target_bssid", "")
        channel = params.get("channel", "")
        additional_args = params.get("additional_args", "")
        
        if not interface:
            logger.warning("Wifite called without interface parameter")
            return jsonify({
                "error": "Interface parameter is required"
            }), 400
        
        command = f"wifite -i {interface}"
        
        if target_bssid:
            command += f" --bssid {target_bssid}"
        
        if channel:
            command += f" --channel {channel}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wifite endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wifiphisher", methods=["POST"])
def wifiphisher():
    """Execute wifiphisher wireless phishing tool."""
    try:
        params = request.json
        interface = params.get("interface", "")
        channel = params.get("channel", "")
        essid = params.get("essid", "")
        additional_args = params.get("additional_args", "")
        
        if not interface:
            logger.warning("Wifiphisher called without interface parameter")
            return jsonify({
                "error": "Interface parameter is required"
            }), 400
        
        command = f"wifiphisher -i {interface}"
        
        if channel:
            command += f" -c {channel}"
        
        if essid:
            command += f" -e {essid}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wifiphisher endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 漏洞利用类工具
@app.route("/api/tools/beef", methods=["POST"])
def beef():
    """Execute BeEF browser exploitation framework."""
    try:
        params = request.json
        hook_url = params.get("hook_url", "")
        additional_args = params.get("additional_args", "")
        
        command = "beef-xss"
        
        if hook_url:
            command += f" --hook-url {hook_url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in beef endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/empire", methods=["POST"])
def empire():
    """Execute Empire post-exploitation framework."""
    try:
        params = request.json
        listener_name = params.get("listener_name", "")
        listener_type = params.get("listener_type", "http")
        additional_args = params.get("additional_args", "")
        
        command = "powershell-empire"
        
        if listener_name:
            command += f" --listener {listener_name}"
        
        if listener_type:
            command += f" --type {listener_type}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in empire endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/set", methods=["POST"])
def set():
    """Execute Social Engineer Toolkit."""
    try:
        params = request.json
        attack_vector = params.get("attack_vector", "")
        payload = params.get("payload", "")
        additional_args = params.get("additional_args", "")
        
        if not attack_vector:
            logger.warning("SET called without attack vector parameter")
            return jsonify({
                "error": "Attack vector parameter is required"
            }), 400
        
        command = f"setoolkit --attack {attack_vector}"
        
        if payload:
            command += f" --payload {payload}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in set endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gophish", methods=["POST"])
def gophish():
    """Execute GoPhish phishing framework."""
    try:
        params = request.json
        config_file = params.get("config_file", "")
        additional_args = params.get("additional_args", "")
        
        command = "gophish"
        
        if config_file:
            command += f" --config {config_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gophish endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# 后渗透测试类工具
@app.route("/api/tools/mimikatz", methods=["POST"])
def mimikatz():
    """Execute Mimikatz Windows credential extraction tool."""
    try:
        params = request.json
        command = params.get("command", "")
        additional_args = params.get("additional_args", "")
        
        if not command:
            logger.warning("Mimikatz called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        full_command = f"mimikatz {command}"
        
        if additional_args:
            full_command += f" {additional_args}"
        
        result = execute_command(full_command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in mimikatz endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/powersploit", methods=["POST"])
def powersploit():
    """Execute PowerSploit PowerShell penetration testing framework."""
    try:
        params = request.json
        module = params.get("module", "")
        script_path = params.get("script_path", "")
        additional_args = params.get("additional_args", "")
        
        if not module and not script_path:
            logger.warning("PowerSploit called without module or script path parameter")
            return jsonify({
                "error": "Module or script path parameter is required"
            }), 400
        
        if script_path:
            command = f"powershell -ExecutionPolicy Bypass -File {script_path}"
        else:
            command = f"powershell -ExecutionPolicy Bypass -Command \"Import-Module {module}; Invoke-{module}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in powersploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/psexec", methods=["POST"])
def psexec():
    """Execute PsExec remote execution tool."""
    try:
        params = request.json
        target = params.get("target", "")
        command = params.get("command", "")
        username = params.get("username", "")
        password = params.get("password", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not command:
            logger.warning("PsExec called without target or command parameter")
            return jsonify({
                "error": "Target and command parameters are required"
            }), 400
        
        command_parts = ["psexec", "\\" + target, "-s", "-d"]
        
        if username:
            command_parts.extend(["-u", username])
        
        if password:
            command_parts.extend(["-p", password])
        
        command_parts.append(command)
        
        if additional_args:
            command_parts.append(additional_args)
        
        full_command = " ".join(command_parts)
        
        result = execute_command(full_command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in psexec endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/winexe", methods=["POST"])
def winexe():
    """Execute Winexe Windows remote command execution tool."""
    try:
        params = request.json
        target = params.get("target", "")
        command = params.get("command", "")
        username = params.get("username", "")
        password = params.get("password", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not command:
            logger.warning("Winexe called without target or command parameter")
            return jsonify({
                "error": "Target and command parameters are required"
            }), 400
        
        command_parts = ["winexe", "//" + target]
        
        if username:
            command_parts.extend(["-U", username])
        
        if password:
            command_parts.extend(["-P", password])
        
        command_parts.extend(["cmd", "/c", command])
        
        if additional_args:
            command_parts.append(additional_args)
        
        full_command = " ".join(command_parts)
        
        result = execute_command(full_command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in winexe endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Web Scanning and Crawling Tools

@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuF (Fuzz Faster U Fool) web fuzzing tool."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = params.get("extensions", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("FFuF called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"ffuf -u {url}/FUZZ"
        
        if wordlist:
            command += f" -w {wordlist}"
        
        if extensions:
            command += f" -e {extensions}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ffuf endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz web application fuzzer."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        payload = params.get("payload", "FUZZ")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Wfuzz called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wfuzz -c -z file,{wordlist} --hc 404 {url}"
        
        if payload != "FUZZ":
            command = f"wfuzz -c -z file,{wordlist} -d \"{payload}\" {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wfuzz endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cewl", methods=["POST"])
def cewl():
    """Execute CeWL (Custom Word List generator) tool."""
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", "2")
        min_word_length = params.get("min_word_length", "3")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("CeWL called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"cewl -d {depth} -m {min_word_length} {url}"
        
        if output_file:
            command += f" -w {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cewl endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/scrapy", methods=["POST"])
def scrapy():
    """Execute Scrapy web crawling framework."""
    try:
        params = request.json
        url = params.get("url", "")
        spider_name = params.get("spider_name", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url and not spider_name:
            logger.warning("Scrapy called without URL or spider name parameter")
            return jsonify({
                "error": "URL or spider name parameter is required"
            }), 400
        
        if spider_name:
            command = f"scrapy crawl {spider_name}"
        else:
            command = f"scrapy shell {url}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in scrapy endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gospider", methods=["POST"])
def gospider():
    """Execute GoSpider web crawling tool."""
    try:
        params = request.json
        url = params.get("url", "")
        threads = params.get("threads", "10")
        depth = params.get("depth", "1")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("GoSpider called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"gospider -s {url} -t {threads} -d {depth}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gospider endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/linkfinder", methods=["POST"])
def linkfinder():
    """Execute LinkFinder JavaScript endpoint discovery tool."""
    try:
        params = request.json
        url = params.get("url", "")
        file_path = params.get("file_path", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url and not file_path:
            logger.warning("LinkFinder called without URL or file path parameter")
            return jsonify({
                "error": "URL or file path parameter is required"
            }), 400
        
        if url:
            command = f"python3 -m linkfinder -i {url}"
        else:
            command = f"python3 -m linkfinder -i {file_path}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in linkfinder endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/js_scan", methods=["POST"])
def js_scan():
    """Execute JS-Scan JavaScript analysis tool."""
    try:
        params = request.json
        url = params.get("url", "")
        file_path = params.get("file_path", "")
        output_dir = params.get("output_dir", "")
        additional_args = params.get("additional_args", "")
        
        if not url and not file_path:
            logger.warning("JS-Scan called without URL or file path parameter")
            return jsonify({
                "error": "URL or file path parameter is required"
            }), 400
        
        if url:
            command = f"js-scan -u {url}"
        else:
            command = f"js-scan -f {file_path}"
        
        if output_dir:
            command += f" -o {output_dir}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in js_scan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/secretfinder", methods=["POST"])
def secretfinder():
    """Execute SecretFinder secret discovery tool."""
    try:
        params = request.json
        url = params.get("url", "")
        file_path = params.get("file_path", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url and not file_path:
            logger.warning("SecretFinder called without URL or file path parameter")
            return jsonify({
                "error": "URL or file path parameter is required"
            }), 400
        
        if url:
            command = f"secretfinder -i {url}"
        else:
            command = f"secretfinder -i {file_path}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in secretfinder endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """Execute Hakrawler web crawling tool."""
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", "2")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Hakrawler called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"hakrawler -url {url} -depth {depth}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hakrawler endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/crawley", methods=["POST"])
def crawley():
    """Execute Crawley web crawling tool."""
    try:
        params = request.json
        url = params.get("url", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Crawley called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"crawley {url}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in crawley endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/photon", methods=["POST"])
def photon():
    """Execute Photon web crawling tool."""
    try:
        params = request.json
        url = params.get("url", "")
        threads = params.get("threads", "10")
        delay = params.get("delay", "0")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Photon called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"photon -u {url} -t {threads} -d {delay}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in photon endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Network Analysis Tools

@app.route("/api/tools/netcat", methods=["POST"])
def netcat():
    """Execute Netcat network utility tool."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "")
        listen = params.get("listen", False)
        command = params.get("command", "")
        additional_args = params.get("additional_args", "")
        
        if not target and not listen:
            logger.warning("Netcat called without target or listen parameter")
            return jsonify({
                "error": "Target or listen parameter is required"
            }), 400
        
        if listen:
            nc_command = "nc -lvp"
            if port:
                nc_command += f" {port}"
        else:
            nc_command = f"nc {target}"
            if port:
                nc_command += f" {port}"
        
        if command:
            nc_command += f" -e {command}"
        
        if additional_args:
            nc_command += f" {additional_args}"
        
        result = execute_command(nc_command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in netcat endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/traceroute", methods=["POST"])
def traceroute():
    """Execute Traceroute network diagnostic tool."""
    try:
        params = request.json
        target = params.get("target", "")
        max_hops = params.get("max_hops", "30")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Traceroute called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"traceroute -m {max_hops} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in traceroute endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/tcpdump", methods=["POST"])
def tcpdump():
    """Execute Tcpdump network packet analyzer."""
    try:
        params = request.json
        interface = params.get("interface", "any")
        count = params.get("count", "100")
        filter_expression = params.get("filter", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        command = "tcpdump"
        
        if interface:
            command += f" -i {interface}"
        
        if count:
            command += f" -c {count}"
        
        if filter_expression:
            command += f" {filter_expression}"
        
        if output_file:
            command += f" -w {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in tcpdump endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/socat", methods=["POST"])
def socat():
    """Execute Socat multipurpose relay tool."""
    try:
        params = request.json
        source = params.get("source", "")
        destination = params.get("destination", "")
        options = params.get("options", "")
        additional_args = params.get("additional_args", "")
        
        if not source or not destination:
            logger.warning("Socat called without source or destination parameter")
            return jsonify({
                "error": "Source and destination parameters are required"
            }), 400
        
        command = f"socat {source} {destination}"
        
        if options:
            command += f" {options}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in socat endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wireshark", methods=["POST"])
def wireshark():
    """Execute Wireshark network protocol analyzer."""
    try:
        params = request.json
        interface = params.get("interface", "any")
        capture_filter = params.get("capture_filter", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        # Wireshark 通常通过 tshark 命令行工具进行数据包捕获
        command = "tshark"
        
        if interface:
            command += f" -i {interface}"
        
        if capture_filter:
            command += f" -f \"{capture_filter}\""
        
        if output_file:
            command += f" -w {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wireshark endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Vulnerability Scanning Tools

@app.route("/api/tools/nmap_nse", methods=["POST"])
def nmap_nse():
    """Execute Nmap with NSE (Nmap Scripting Engine) scripts."""
    try:
        params = request.json
        target = params.get("target", "")
        script = params.get("script", "")
        script_category = params.get("script_category", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nmap NSE called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nmap --script"
        
        if script:
            command += f" {script}"
        elif script_category:
            command += f" {script_category}"
        else:
            command += " default"
        
        command += f" {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap_nse endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/vulners", methods=["POST"])
def vulners():
    """Execute Vulners vulnerability scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Vulners called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nmap --script vulners"
        
        if port:
            command += f" -p {port}"
        
        command += f" {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in vulners endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sn1per", methods=["POST"])
def sn1per():
    """Execute Sn1per automated penetration testing tool."""
    try:
        params = request.json
        target = params.get("target", "")
        mode = params.get("mode", "recon")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Sn1per called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"sniper -t {target} -m {mode}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sn1per endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/lazyrecon", methods=["POST"])
def lazyrecon():
    """Execute LazyRecon automated reconnaissance tool."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("LazyRecon called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"lazyrecon {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in lazyrecon endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Password Analysis Tools

@app.route("/api/tools/crunch", methods=["POST"])
def crunch():
    """Execute Crunch wordlist generator."""
    try:
        params = request.json
        min_length = params.get("min_length", "1")
        max_length = params.get("max_length", "8")
        charset = params.get("charset", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not min_length or not max_length:
            logger.warning("Crunch called without min/max length parameters")
            return jsonify({
                "error": "Min and max length parameters are required"
            }), 400
        
        command = f"crunch {min_length} {max_length}"
        
        if charset:
            command += f" {charset}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in crunch endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/johnny", methods=["POST"])
def johnny():
    """Execute Johnny GUI for John the Ripper."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("Johnny called without hash file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"johnny {hash_file}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in johnny endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hash_identifier", methods=["POST"])
def hash_identifier():
    """Execute Hash-Identifier hash type detection tool."""
    try:
        params = request.json
        hash_value = params.get("hash", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_value:
            logger.warning("Hash-Identifier called without hash parameter")
            return jsonify({
                "error": "Hash parameter is required"
            }), 400
        
        command = f"hashid {hash_value}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hash_identifier endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Reverse Engineering Tools

@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    """Execute Ghidra reverse engineering framework."""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        project_path = params.get("project_path", "")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            logger.warning("Ghidra called without file path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400
        
        command = f"ghidra"
        
        if file_path:
            command += f" {file_path}"
        
        if project_path:
            command += f" -import {project_path}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ghidra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/ollydbg", methods=["POST"])
def ollydbg():
    """Execute OllyDbg debugger (Windows)."""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            logger.warning("OllyDbg called without file path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400
        
        command = f"ollydbg {file_path}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ollydbg endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gdb", methods=["POST"])
def gdb():
    """Execute GDB (GNU Debugger)."""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        command = params.get("command", "")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            logger.warning("GDB called without file path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400
        
        gdb_command = f"gdb {file_path}"
        
        if command:
            gdb_command += f" -ex \"{command}\""
        
        if additional_args:
            gdb_command += f" {additional_args}"
        
        result = execute_command(gdb_command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gdb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wordlists", methods=["POST"])
def wordlists():
    """Manage and manipulate wordlists."""
    try:
        params = request.json
        action = params.get("action", "list")  # list, search, combine, filter
        wordlist_path = params.get("wordlist_path", "")
        search_term = params.get("search_term", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if action == "list":
            # List available wordlists in common directories
            command = "find /usr/share/wordlists -type f -name \"*.txt\" | head -20"
        elif action == "search":
            if not wordlist_path or not search_term:
                return jsonify({
                    "error": "Wordlist path and search term are required for search action"
                }), 400
            command = f"grep -i \"{search_term}\" {wordlist_path}"
        elif action == "combine":
            if not wordlist_path:
                return jsonify({
                    "error": "Wordlist path is required for combine action"
                }), 400
            # Combine multiple wordlists (comma-separated)
            wordlists = wordlist_path.split(",")
            command = f"cat {' '.join(wordlists)}"
            if output_file:
                command += f" | sort -u > {output_file}"
            else:
                command += " | sort -u"
        elif action == "filter":
            if not wordlist_path:
                return jsonify({
                    "error": "Wordlist path is required for filter action"
                }), 400
            # Filter wordlist by length or pattern
            min_length = params.get("min_length", "")
            max_length = params.get("max_length", "")
            pattern = params.get("pattern", "")
            
            command = f"cat {wordlist_path}"
            if min_length:
                command += f" | awk 'length($0) >= {min_length}'"
            if max_length:
                command += f" | awk 'length($0) <= {max_length}'"
            if pattern:
                command += f" | grep \"{pattern}\""
            if output_file:
                command += f" > {output_file}"
        else:
            return jsonify({
                "error": "Invalid action. Supported actions: list, search, combine, filter"
            }), 400
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wordlists endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Other Security Tools

@app.route("/api/tools/exploitdb", methods=["POST"])
def exploitdb():
    """Execute ExploitDB search tool."""
    try:
        params = request.json
        search_term = params.get("search_term", "")
        platform = params.get("platform", "")
        additional_args = params.get("additional_args", "")
        
        if not search_term:
            logger.warning("ExploitDB called without search term parameter")
            return jsonify({
                "error": "Search term parameter is required"
            }), 400
        
        command = f"searchsploit {search_term}"
        
        if platform:
            command += f" -p {platform}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in exploitdb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/mobsf", methods=["POST"])
def mobsf():
    """Execute MobSF (Mobile Security Framework)."""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        platform = params.get("platform", "android")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            logger.warning("MobSF called without file path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400
        
        command = f"mobsf"
        
        if file_path:
            command += f" {file_path}"
        
        if platform:
            command += f" --platform {platform}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in mobsf endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/apktool", methods=["POST"])
def apktool():
    """Execute APKTool Android application analysis tool."""
    try:
        params = request.json
        apk_file = params.get("apk_file", "")
        output_dir = params.get("output_dir", "")
        decode = params.get("decode", True)
        additional_args = params.get("additional_args", "")
        
        if not apk_file:
            logger.warning("APKTool called without APK file parameter")
            return jsonify({
                "error": "APK file parameter is required"
            }), 400
        
        if decode:
            command = f"apktool d {apk_file}"
        else:
            command = f"apktool b {apk_file}"
        
        if output_dir:
            command += f" -o {output_dir}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in apktool endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """Execute Pacu AWS penetration testing tool."""
    try:
        params = request.json
        session_name = params.get("session_name", "")
        module = params.get("module", "")
        additional_args = params.get("additional_args", "")
        
        command = "pacu"
        
        if session_name:
            command += f" --session {session_name}"
        
        if module:
            command += f" --module {module}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in pacu endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/scout_suite", methods=["POST"])
def scout_suite():
    """Execute Scout Suite multi-cloud security auditing tool."""
    try:
        params = request.json
        provider = params.get("provider", "aws")
        access_key = params.get("access_key", "")
        secret_key = params.get("secret_key", "")
        additional_args = params.get("additional_args", "")
        
        command = f"scout {provider}"
        
        if access_key:
            command += f" --access-key {access_key}"
        
        if secret_key:
            command += f" --secret-key {secret_key}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in scout_suite endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cloudsploit", methods=["POST"])
def cloudsploit():
    """Execute CloudSploit cloud security scanning tool."""
    try:
        params = request.json
        provider = params.get("provider", "aws")
        scan_type = params.get("scan_type", "")
        additional_args = params.get("additional_args", "")
        
        command = f"cloudsploit --provider {provider}"
        
        if scan_type:
            command += f" --scan {scan_type}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cloudsploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/firmwalker", methods=["POST"])
def firmwalker():
    """Execute Firmwalker firmware analysis tool."""
    try:
        params = request.json
        firmware_path = params.get("firmware_path", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not firmware_path:
            logger.warning("Firmwalker called without firmware path parameter")
            return jsonify({
                "error": "Firmware path parameter is required"
            }), 400
        
        command = f"firmwalker {firmware_path}"
        
        if output_file:
            command += f" -o {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in firmwalker endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/iotseeker", methods=["POST"])
def iotseeker():
    """Execute IoTSeeker IoT device security scanner."""
    try:
        params = request.json
        target = params.get("target", "")
        port = params.get("port", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("IoTSeeker called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"iotseeker {target}"
        
        if port:
            command += f" -p {port}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in iotseeker endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Penetration Testing Report Generation Tools

@app.route("/api/tools/dradis", methods=["POST"])
def dradis():
    """Execute Dradis penetration testing report generation tool."""
    try:
        params = request.json
        project_name = params.get("project_name", "")
        template = params.get("template", "default")
        output_format = params.get("output_format", "pdf")
        additional_args = params.get("additional_args", "")
        
        if not project_name:
            logger.warning("Dradis called without project name parameter")
            return jsonify({
                "error": "Project name parameter is required"
            }), 400
        
        command = f"dradis --project {project_name}"
        
        if template != "default":
            command += f" --template {template}"
        
        if output_format != "pdf":
            command += f" --format {output_format}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dradis endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/serpico", methods=["POST"])
def serpico():
    """Execute Serpico penetration testing report generation tool."""
    try:
        params = request.json
        template = params.get("template", "default")
        findings_file = params.get("findings_file", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not template:
            logger.warning("Serpico called without template parameter")
            return jsonify({
                "error": "Template parameter is required"
            }), 400
        
        command = f"serpico --template {template}"
        
        if findings_file:
            command += f" --findings {findings_file}"
        
        if output_file:
            command += f" --output {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in serpico endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/faraday", methods=["POST"])
def faraday():
    """Execute Faraday collaborative penetration testing report tool."""
    try:
        params = request.json
        workspace = params.get("workspace", "")
        template = params.get("template", "default")
        output_format = params.get("output_format", "html")
        additional_args = params.get("additional_args", "")
        
        if not workspace:
            logger.warning("Faraday called without workspace parameter")
            return jsonify({
                "error": "Workspace parameter is required"
            }), 400
        
        command = f"faraday --workspace {workspace}"
        
        if template != "default":
            command += f" --template {template}"
        
        if output_format != "html":
            command += f" --format {output_format}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in faraday endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/magictree", methods=["POST"])
def magictree():
    """Execute MagicTree penetration testing report generation tool."""
    try:
        params = request.json
        xml_file = params.get("xml_file", "")
        template = params.get("template", "default")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not xml_file:
            logger.warning("MagicTree called without XML file parameter")
            return jsonify({
                "error": "XML file parameter is required"
            }), 400
        
        command = f"magictree --xml {xml_file}"
        
        if template != "default":
            command += f" --template {template}"
        
        if output_file:
            command += f" --output {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in magictree endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/pipal", methods=["POST"])
def pipal():
    """Execute Pipal password analysis and report generation tool."""
    try:
        params = request.json
        password_file = params.get("password_file", "")
        analysis_type = params.get("analysis_type", "basic")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not password_file:
            logger.warning("Pipal called without password file parameter")
            return jsonify({
                "error": "Password file parameter is required"
            }), 400
        
        command = f"pipal --file {password_file}"
        
        if analysis_type != "basic":
            command += f" --type {analysis_type}"
        
        if output_file:
            command += f" --output {output_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in pipal endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/consolidated_report", methods=["POST"])
def consolidated_report():
    """Execute consolidated penetration testing report generation tool."""
    try:
        params = request.json
        tool_results = params.get("tool_results", [])
        template = params.get("template", "comprehensive")
        output_format = params.get("output_format", "pdf")
        additional_args = params.get("additional_args", "")
        
        if not tool_results:
            logger.warning("Consolidated report called without tool results parameter")
            return jsonify({
                "error": "Tool results parameter is required"
            }), 400
        
        # Create a temporary file with tool results
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for result in tool_results:
                f.write(f"{result}\n")
            temp_file = f.name
        
        command = f"consolidated_report --input {temp_file}"
        
        if template != "comprehensive":
            command += f" --template {template}"
        
        if output_format != "pdf":
            command += f" --format {output_format}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # Clean up temporary file
        import os
        os.unlink(temp_file)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in consolidated_report endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/xsser", methods=["POST"])
def xsser():
    """Execute XSSer XSS vulnerability scanner."""
    try:
        params = request.json
        url = params.get("url", "")
        payload = params.get("payload", "")
        method = params.get("method", "GET")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("XSSer called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"xsser -u {url}"
        
        if payload:
            command += f" --payload '{payload}'"
        
        if method and method.upper() != "GET":
            command += f" --method {method.upper()}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in xsser endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/autorecon", methods=["POST"])
def autorecon():
    """Execute AutoRecon automated reconnaissance tool."""
    try:
        params = request.json
        targets = params.get("targets", [])
        target_file = params.get("target_file", "")
        ports = params.get("ports", "")
        max_scans = params.get("max_scans", "50")
        output_dir = params.get("output_dir", "results")
        additional_args = params.get("additional_args", "")
        
        if not targets and not target_file:
            logger.warning("AutoRecon called without targets or target file parameter")
            return jsonify({
                "error": "Targets or target file parameter is required"
            }), 400
        
        command = "autorecon"
        
        if target_file:
            command += f" -t {target_file}"
        elif targets:
            # Convert list of targets to space-separated string
            targets_str = " ".join(targets)
            command += f" {targets_str}"
        
        if ports:
            command += f" -p {ports}"
        
        if max_scans != "50":
            command += f" -m {max_scans}"
        
        if output_dir != "results":
            command += f" -o {output_dir}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in autorecon endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "metasploit", "wpscan", "enum4linux",
        "masscan", "zmap", "unicornscan", "netdiscover", "naabu", "rustscan", "subfinder",
        "amass", "dnsrecon", "dnsenum", "fierce", "sublist3r", "findomain", "whois", "whatweb", "wafw00f", "dirsearch",
        "feroxbuster", "katana", "meg", "arjun", "paramspider", "waybackurls", "gau", "nuclei",
        "openvas", "vulmap", "lynis", "chkrootkit", "rkhunter", "clamav", "joomscan", "droopescan",
        "cmsmap", "wapiti", "arachni", "netsparker", "skipfish", "hydra", "john", "hashcat",
        "medusa", "patator", "crowbar", "aircrack", "reaver", "wifite", "wifiphisher", "beef",
        "empire", "set", "gophish", "mimikatz", "powersploit", "psexec", "winexe", "ffuf",
        "wfuzz", "cewl", "scrapy", "gospider", "linkfinder", "js_scan", "secretfinder", "hakrawler",
        "crawley", "photon", "netcat", "traceroute", "tcpdump", "wireshark", "nmap_nse", "vulners",
        "sn1per", "lazyrecon", "crunch", "johnny", "hash_identifier", "ghidra", "ollydbg", "gdb",
        "exploitdb", "mobsf", "apktool", "pacu", "scout_suite", "cloudsploit", "firmwalker", "iotseeker",
        "dradis", "serpico", "faraday", "magictree", "pipal", "consolidated_report", "xsser", "autorecon", "wordlists", "socat"
    ]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    # Categorize tools by type for better organization
    tool_categories = {
        "network_scanners": ["nmap", "masscan", "zmap", "unicornscan", "netdiscover", "naabu", "rustscan", "netcat", "traceroute", "tcpdump", "wireshark", "socat"],
        "web_scanners": ["gobuster", "dirb", "nikto", "wpscan", "whatweb", "wafw00f", "dirsearch", "feroxbuster", "katana", "meg", "arjun", "paramspider", "waybackurls", "gau", "nuclei", "vulmap", "joomscan", "droopescan", "cmsmap", "wapiti", "arachni", "skipfish", "netsparker", "ffuf", "wfuzz", "xsser"],
        "enumeration_tools": ["enum4linux", "subfinder", "amass", "dnsrecon", "dnsenum", "fierce", "sublist3r", "findomain", "whois", "autorecon", "lazyrecon", "sn1per"],
        "dns_analysis": ["dnsrecon", "dnsenum", "fierce"],
        "web_crawlers": ["scrapy", "gospider", "linkfinder", "js_scan", "secretfinder", "hakrawler", "crawley", "photon", "cewl"],
        "vulnerability_scanners": ["openvas", "nmap_nse", "vulners", "vulmap"],
        "security_assessment": ["lynis", "chkrootkit", "rkhunter", "clamav"],
        "password_attackers": ["hydra", "john", "hashcat", "medusa", "patator", "crowbar", "crunch", "johnny", "hash_identifier", "wordlists"],
        "wireless_tools": ["aircrack", "reaver", "wifite", "wifiphisher"],
        "social_engineering": ["beef", "empire", "set", "gophish"],
        "post_exploitation": ["mimikatz", "powersploit", "psexec", "winexe"],
        "reverse_engineering": ["ghidra", "ollydbg", "gdb"],
        "exploit_frameworks": ["metasploit", "exploitdb"],
        "mobile_security": ["mobsf", "apktool"],
        "cloud_security": ["pacu", "scout_suite", "cloudsploit"],
        "iot_security": ["firmwalker", "iotseeker"],
        "reporting_tools": ["dradis", "serpico", "faraday", "magictree", "pipal", "consolidated_report"]
    }
    
    # Calculate category-wise availability
    category_status = {}
    for category, tools in tool_categories.items():
        category_status[category] = {
            "available": sum(1 for tool in tools if tools_status.get(tool, False)),
            "total": len(tools),
            "tools": {tool: tools_status.get(tool, False) for tool in tools}
        }
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "tool_categories": category_status,
        "server_info": {
            "version": "1.0.0",
            "total_tools": len(essential_tools),
            "available_tools": sum(1 for status in tools_status.values() if status),
            "timestamp": datetime.now().isoformat()
        }
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
