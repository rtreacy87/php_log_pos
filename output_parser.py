"""
Output parser for extracting command results from HTML responses.
Follows Single Responsibility Principle.
"""

from bs4 import BeautifulSoup
from typing import List


class OutputParser:
    """Parses and extracts command output from HTML responses."""
    
    @staticmethod
    def parse(html: str, command: str, max_lines: int = 50) -> str:
        """
        Extract command output from HTML response.
        
        Args:
            html: Raw HTML response
            command: Command that was executed
            max_lines: Maximum number of output lines to return
            
        Returns:
            Extracted command output
        """
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove unwanted elements
        for element in soup(["script", "style", "header", "footer", "nav"]):
            element.decompose()
        
        # Extract and clean text
        text = soup.get_text()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Find command output
        output_lines = OutputParser._find_output(lines, command)
        
        if output_lines:
            return '\n'.join(output_lines[:max_lines])
        
        # Fallback: return limited raw text
        return '\n'.join(lines[:30]) if lines else "No output captured"
    
    @staticmethod
    def _find_output(lines: List[str], command: str) -> List[str]:
        """
        Find relevant output lines from parsed text.
        
        Args:
            lines: Cleaned text lines
            command: Command that was executed
            
        Returns:
            List of output lines
        """
        output_lines = []
        in_output = False
        
        # Skip patterns that indicate HTML structure
        skip_patterns = ['<!doctype', '<html', '</html>', 'containers', 'inlane freight']
        
        for line in lines:
            # Skip common HTML/page elements
            if any(skip in line.lower() for skip in skip_patterns):
                continue
            
            # Look for command or typical output patterns
            if (command in line or 'uid=' in line or 
                'total' in line or 'root:' in line):
                in_output = True
            
            if in_output and line and len(line) < 500:
                output_lines.append(line)
        
        return output_lines
