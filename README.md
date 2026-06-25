PlugNPlay IT Hardening & Security Audit Suite:

An interactive, cross-platform security auditor designed exclusively for Windows and Linux hosts. It allows network students, developers, and system administrators to audit loopback port configurations, inspect firewall policies, check anti-malware status, and selectively check for registered system vulnerabilities using the live NIST National Vulnerability Database (NVD).

Features:

Exclusive OS Compatibility Guardrail: Safely supports mainstream Windows and Linux environments. Operates with an automatic termination guardrail if run on macOS to prevent unintended behavior.

Detailed OS Version Detection: Automatically gathers precise operating system details (such as your specific Windows release or Linux distribution name and version).

Interactive CVE Query Gate: Offers a privacy-conscious console prompt asking whether you want to query the live NVD API for vulnerability records explicitly matching your operating system version.

Loopback Port Profiling: Fast, multi-threaded localhost network audit scanning for standard services and administrative ports (1-1024).

Automated Dependency Setup: Automatically detects and silently installs required third-party libraries (psutil and requests) on demand.

Dual Reporting: Automatically generates a modern, dark-themed HTML visual report (scan_report.html) alongside a structured data dump (scan_results.json).

Installation & Usage:

1. Ensure Python is Installed

Make sure you have Python 3 installed on your machine. You can verify this by opening a terminal or Command Prompt and running:

python --version



(On Windows, remember to check the "Add Python to PATH" option during installation).

2. Running the Audit

Simply download the plugnplay.py script and run it from your terminal.

On Windows:

Open Command Prompt or PowerShell as Administrator and run:

python plugnplay.py



On Linux:

Open your terminal. It is recommended to run the script with elevated permissions (sudo) to allow the parser to audit system files like SSH configurations and sudoers:

sudo python3 plugnplay.py



User Controls & Command Line Options:

Interactive Prompt: NVD CVE Query

At startup, the tool will identify your specific OS version and ask:

Audit OS-specific CVE records? (y/n):



Press y (Yes): The tool securely connects to the live NIST NVD API to find up to 5 critical vulnerabilities associated with your specific OS version.

Press n (No): Bypasses internet-facing queries entirely. Ideal for offline diagnostic runs or preserving system bandwidth.

Getting Help

You can print the built-in manual directly in your terminal at any time by passing the help flag:

python plugnplay.py --help



Scan Outputs:

Upon a successful audit, two files are written to your current folder:

scan_report.html: A highly stylized, dark-themed HTML report containing responsive tables of open ports, categorized risk indicators, security configurations, and live threat streams.

scan_results.json: A raw, structured JSON file containing all diagnostic metrics—perfect for database archiving or automated scripting.

Troubleshooting:

"ModuleNotFoundError": The script attempts to auto-install dependencies (psutil and requests). If your system blocks auto-installation, manually install them by typing:

pip install psutil requests



Permission Errors on Linux: If the script cannot check SSH configurations, run the script using sudo python3 plugnplay.py.

macOS Execution Error: The tool is designed specifically for Windows and Linux hosts; execution on macOS is intentionally blocked.
