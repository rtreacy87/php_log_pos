"""
Configuration module for log poisoning attack framework.
Defines log locations, poisoning methods, and system settings.
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class LogLocation:
    """Represents a log file location with its characteristics."""
    paths: List[str]
    method: str
    description: str


@dataclass
class Config:
    """Application configuration."""
    default_user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    request_timeout: int = 10
    max_output_lines: int = 50
    max_content_preview: int = 200
    
    log_locations: Dict[str, LogLocation] = field(default_factory=lambda: {
        'apache_access': LogLocation(
            paths=[
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
            method='user_agent',
            description='Apache Access Log (User-Agent)'
        ),
        'nginx_access': LogLocation(
            paths=[
                '/var/log/nginx/access.log',
                '/var/log/nginx/access_log',
                'C:\\nginx\\logs\\access.log',
                '/usr/local/nginx/logs/access.log',
                '/var/www/logs/nginx_access.log'
            ],
            method='user_agent',
            description='Nginx Access Log (User-Agent)'
        ),
        'apache_error': LogLocation(
            paths=[
                '/var/log/apache2/error.log',
                '/var/log/apache/error.log',
                '/var/log/httpd/error_log',
                '/var/log/httpd-error.log',
                'C:\\xampp\\apache\\logs\\error.log',
                'C:\\Apache24\\logs\\error.log',
                '/usr/local/apache2/logs/error_log',
                '/var/www/logs/error_log'
            ],
            method='malformed_request',
            description='Apache Error Log (Malformed Request)'
        ),
        'nginx_error': LogLocation(
            paths=[
                '/var/log/nginx/error.log',
                '/var/log/nginx/error_log',
                'C:\\nginx\\logs\\error.log',
                '/usr/local/nginx/logs/error.log'
            ],
            method='malformed_request',
            description='Nginx Error Log (Malformed Request)'
        ),
        'ssh': LogLocation(
            paths=[
                '/var/log/auth.log',
                '/var/log/secure',
                '/var/log/sshd.log',
                'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx'
            ],
            method='ssh_username',
            description='SSH Log (Username)'
        ),
        'ftp': LogLocation(
            paths=[
                '/var/log/vsftpd.log',
                '/var/log/proftpd/proftpd.log',
                '/var/log/ftp.log',
                '/var/log/xferlog'
            ],
            method='ftp_username',
            description='FTP Log (Username)'
        ),
        'mail': LogLocation(
            paths=[
                '/var/log/mail.log',
                '/var/log/mail',
                '/var/log/maillog',
                '/var/mail/www-data'
            ],
            method='mail_field',
            description='Mail Log (Email fields)'
        ),
        'proc_environ': LogLocation(
            paths=[
                '/proc/self/environ',
                '/proc/self/fd/0',
                '/proc/self/fd/1',
                '/proc/self/fd/2'
            ],
            method='user_agent',
            description='Process Environment (User-Agent)'
        )
    })
    
    # Log readability indicators
    log_indicators: List[str] = field(default_factory=lambda: [
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
    ])
