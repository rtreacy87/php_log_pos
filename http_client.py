"""
HTTP client abstraction for making requests to the target server.
Follows Single Responsibility Principle.
"""

import requests
from typing import Optional, Dict


class HttpClient:
    """Handles all HTTP communication with the target server."""
    
    def __init__(self, timeout: int = 10):
        """
        Initialize HTTP client.
        
        Args:
            timeout: Request timeout in seconds
        """
        self.session = requests.Session()
        self.timeout = timeout
    
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
        """
        Perform GET request.
        
        Args:
            url: Target URL
            headers: Optional HTTP headers
            
        Returns:
            Response object
            
        Raises:
            requests.RequestException: On request failure
        """
        return self.session.get(url, headers=headers, timeout=self.timeout)
    
    def close(self):
        """Close the session."""
        self.session.close()
