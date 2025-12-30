# Log Poisoning LFI Attack Framework

A modular, SOLID-compliant framework for exploiting Local File Inclusion (LFI) vulnerabilities via log poisoning.

## Architecture

This refactored version follows SOLID principles:

- **Single Responsibility Principle**: Each module has one clear purpose
- **Open/Closed Principle**: Strategy pattern allows easy extension of poisoning methods
- **Liskov Substitution Principle**: All poisoning strategies are interchangeable
- **Interface Segregation Principle**: Focused interfaces for each component
- **Dependency Inversion Principle**: High-level modules depend on abstractions

## Project Structure

```
php_log_pos/
├── log_poison.py           # Main entry point
├── app.py                  # Application orchestrator
├── config.py               # Configuration and constants
├── http_client.py          # HTTP communication abstraction
├── log_scanner.py          # Log file detection
├── poisoning_strategies.py # Strategy pattern for poisoning methods
├── command_executor.py     # Command execution via poisoned logs
├── output_parser.py        # HTML response parsing
└── ui.py                   # User interface
```

## Modules

### config.py
Centralizes all configuration including log locations, poisoning methods, and system settings.

### http_client.py
Abstracts HTTP communication with the target server.

### log_scanner.py
Scans for readable log files via LFI vulnerability.

### poisoning_strategies.py
Implements Strategy Pattern for different poisoning methods:
- User-Agent header poisoning
- Malformed request poisoning
- Referer header poisoning

### command_executor.py
Executes commands via poisoned log files.

### output_parser.py
Parses HTML responses to extract command output.

### ui.py
Handles user interaction for both interactive and single-command modes.

### app.py
Main orchestrator that coordinates all components.

## Usage

```bash
# Scan for vulnerable logs and enter interactive mode
python3 log_poison.py -u http://target.com/index.php

# Execute single command
python3 log_poison.py -u http://target.com/index.php -c "ls -la"

# Use specific log file
python3 log_poison.py -u http://target.com/index.php -l /var/log/apache2/access.log

# Custom parameter name
python3 log_poison.py -u http://target.com/index.php -p page -c "id"
```

## Requirements

```
requests
beautifulsoup4
```

Install with:
```bash
pip install requests beautifulsoup4
```

## Benefits of Refactoring

1. **Maintainability**: Each module has a single, clear purpose
2. **Testability**: Components can be tested in isolation
3. **Extensibility**: New poisoning strategies can be added without modifying existing code
4. **Reusability**: Modules can be used independently
5. **Readability**: Clear separation of concerns makes code easier to understand
6. **Flexibility**: Easy to swap implementations (e.g., different HTTP clients)

## Adding New Poisoning Strategies

To add a new poisoning method:

1. Create a new class in `poisoning_strategies.py` that extends `PoisoningStrategy`
2. Implement the `poison()` method
3. Register it in `PoisoningStrategyFactory.create()`
4. Add corresponding log location in `config.py`

Example:
```python
class CustomPoisoning(PoisoningStrategy):
    def poison(self, target_url: str, param: str, log_path: str, payload: str) -> bool:
        # Your implementation
        pass
```
