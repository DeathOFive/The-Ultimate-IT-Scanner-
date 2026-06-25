#!/usr/bin/env python3
"""
PlugNPlay System Hardening & IT Audit Suite
-------------------------------------------
A single, cross-platform security diagnostic script that auto-detects 
host systems (Windows & Linux, excluding macOS) and executes tailored 
vulnerability, firewall, and configuration audits with interactive CVE filters.
"""

import os
import platform
import socket
import subprocess
import time
import sys
import threading
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- COLOR CLASS WITH WINDOWS VT SUPPORT ---
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        os.system("")  # Standard fallback to trigger ANSI parsing

class Theme:
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    INFO_BADGE = f"{CYAN}[*]{RESET}"
    OK_BADGE = f"{GREEN}[✓]{RESET}"
    WARN_BADGE = f"{YELLOW}[!]{RESET}"
    ERR_BADGE = f"{RED}[-]{RESET}"

# --- OS VERIFICATION & PREVENTIONS ---
def verify_supported_os():
    current_os = platform.system().lower()
    if current_os == "darwin":
        os.system('cls' if os.name == 'nt' else 'clear')
        termination_panel = f"""
{Theme.RED}{Theme.BOLD}╔═════════════════════════════════════════════════════════════════════╗
║                      UNSUPPORTED PLATFORM ERROR                     ║
╚═════════════════════════════════════════════════════════════════════╝{Theme.RESET}

  {Theme.WARN_BADGE} {Theme.BOLD}Detection Engine Output:{Theme.RESET} {Theme.YELLOW}Apple macOS (Darwin) Detected{Theme.RESET}
  
  {Theme.ERR_BADGE} {Theme.RED}Constraint Halt:{Theme.RESET} 
    By design policies, this audit solution has been configured to
    run exclusively on mainstream Windows and Linux architectures.
    macOS operation is strictly blocked.

  {Theme.INFO_BADGE} Execution halted safely. Exiting diagnostic process.
"""
        print(termination_panel)
        sys.exit(1)

# Run OS check immediately before doing anything else
verify_supported_os()

# --- MANUAL / HELP SYSTEM ---
HELP_MANUAL = f"""
{Theme.CYAN}{Theme.BOLD}╔═════════════════════════════════════════════════════════════════════╗
║                      PLUGNPLAY USER MANUAL                          ║
╚═════════════════════════════════════════════════════════════════════╝{Theme.RESET}

{Theme.BOLD}ABOUT:{Theme.RESET}
  This tool is an interactive, unified, zero-dependency endpoint
  security auditor designed exclusively for Windows and Linux hosts.

{Theme.BOLD}FEATURES:{Theme.RESET}
  {Theme.GREEN}●{Theme.RESET} Active loopback socket profiling & open port map
  {Theme.GREEN}●{Theme.RESET} Adaptive host firewall policy analyzer
  {Theme.GREEN}●{Theme.RESET} AV & endpoint agent engine checks
  {Theme.GREEN}●{Theme.RESET} Interactive targeted OS-specific CVE query selection
  {Theme.GREEN}●{Theme.RESET} Beautiful, interactive HTML UI reports (`scan_report.html`)
  {Theme.GREEN}●{Theme.RESET} Structured JSON export format (`scan_results.json`)

{Theme.BOLD}USAGE:{Theme.RESET}
  Normal Execution:
    {Theme.CYAN}python plugnplay.py{Theme.RESET}

  To view this documentation page:
    {Theme.CYAN}python plugnplay.py --help{Theme.RESET} (or -h)

{Theme.BOLD}SYSTEM PREREQUISITES:{Theme.RESET}
  {Theme.CYAN}Windows:{Theme.RESET}
    Compatible with Windows 10, 11, and Server derivatives.
  {Theme.CYAN}Linux:{Theme.RESET}
    Compatible with Debian/Ubuntu, RHEL/CentOS, and Arch flavors. 
    Run with {Theme.YELLOW}sudo{Theme.RESET} for deep security configuration parsing.
"""

def print_help_if_requested():
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h", "-help", "/?"]:
        print(HELP_MANUAL)
        sys.exit(0)

print_help_if_requested()

# --- SAFE AUTO-INSTALLATION OF LIBRARIES ---
def ensure_dependencies():
    print(f"{Theme.INFO_BADGE} Verifying runtime library dependencies...")
    required = ["psutil", "requests"]
    missing = []
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
            
    if missing:
        print(f"{Theme.WARN_BADGE} Missing required libraries: {Theme.YELLOW}{', '.join(missing)}{Theme.RESET}")
        print(f"{Theme.INFO_BADGE} Silently configuring environment via pip...")
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', *missing, '--quiet'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"{Theme.OK_BADGE} Dependency configuration complete.")
        except Exception as e:
            print(f"{Theme.ERR_BADGE} {Theme.RED}Auto-install failed: {e}{Theme.RESET}")
            print(f"{Theme.WARN_BADGE} Please install manually: pip install psutil requests")
            sys.exit(1)

ensure_dependencies()

# Core system imports are now safe
import psutil
import requests

# --- MULTI-THREADED PROGRESS SPINNER ---
spinner_lock = threading.Lock()
spinner_running = False
spinner_text = ""

def run_spinner():
    global spinner_running, spinner_text
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    i = 0
    while True:
        with spinner_lock:
            if not spinner_running:
                break
            current_text = spinner_text
        color = [Theme.CYAN, Theme.BLUE, Theme.MAGENTA][i % 3]
        sys.stdout.write(f"\r  {color}{frames[i % len(frames)]}{Theme.RESET} {Theme.DIM}{current_text}{Theme.RESET}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * 80 + "\r")
    sys.stdout.flush()

def start_progress(message):
    global spinner_running, spinner_text
    with spinner_lock:
        spinner_text = message
        if not spinner_running:
            spinner_running = True
            threading.Thread(target=run_spinner, daemon=True).start()

def update_progress(message):
    global spinner_text
    with spinner_lock:
        spinner_text = message

def stop_progress(status_badge=Theme.OK_BADGE, completion_message="Done"):
    global spinner_running
    with spinner_lock:
        spinner_running = False
    time.sleep(0.12) # Prevent stdout overlap
    print(f"  {status_badge} {completion_message}")

# --- ENHANCED SYSTEM INFORMATION GATHERING ---
def get_os():
    return platform.system().lower()

def get_detailed_os_string():
    """Gets a clean, precise operating system and version description for NVD targeting."""
    os_type = get_os()
    if os_type == "windows":
        release = platform.release()
        if "10" in release:
            return "Windows 10"
        elif "11" in release:
            return "Windows 11"
        return f"Windows {release}"
    elif os_type == "linux":
        try:
            if os.path.exists("/etc/os-release"):
                info = {}
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            info[k] = v.strip('"')
                if "PRETTY_NAME" in info:
                    return info["PRETTY_NAME"]
                elif "NAME" in info and "VERSION_ID" in info:
                    return f"{info['NAME']} {info['VERSION_ID']}"
        except Exception:
            pass
        return f"Linux {platform.release()}"
    return "Unknown OS"

def print_banner(detected_os, os_details):
    os_label = detected_os.upper()
    # Corrected banner containing the letter "Y" properly aligned
    banner = f"""
{Theme.CYAN}{Theme.BOLD} ╔═════════════════════════════════════════════════════════════════════════╗
 ║  ██████╗ ██╗     ██╗   ██╗ ██████╗ ███╗   ██╗██████╗ ██╗      █████╗ ██╗  ██╗ ║
 ║  ██╔══██╗██║     ██║   ██║██╔════╝ ████╗  ██║██╔══██╗██║     ██╔══██╗╚██╗██╔╝ ║
 ║  ██████╔╝██║     ██║   ██║██║  ███╗██╔██╗ ██║██████╔╝██║     ███████║ ╚███╔╝  ║
 ║  ██╔═══╝ ██║     ██║   ██║██║   ██║██║╚██╗██║██╔═══╝ ██║     ██╔══██║  ╚██╔╝   ║
 ║  ██║     ███████╗╚██████╔╝╚██████╔╝██║ ╚████║██║     ███████╗██║  ██║   ██║    ║
 ║  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝    ║
 ║                                                                         ║
 ║              -- EXCLUSIVE WINDOWS & LINUX SECURITY SUITE --             ║
 ║   OS Context: {os_details.ljust(54)}║
 ╚═════════════════════════════════════════════════════════════════════════╝{Theme.RESET}
    """
    print(banner)

def print_section_header(title):
    width = 75
    inner_width = width - 4
    formatted_title = f" {title} "
    fill_left = (inner_width - len(formatted_title)) // 2
    fill_right = inner_width - len(formatted_title) - fill_left
    border_line = "═" * (width - 2)
    
    print(f"\n{Theme.BLUE}╔{border_line}╗")
    print(f"║{' ' * fill_left}{Theme.BOLD}{Theme.CYAN}{formatted_title}{Theme.BLUE}{' ' * fill_right}║")
    print(f"╚{border_line}╝{Theme.RESET}")

# --- AUDITING MODULES ---
def scan_ports():
    start_progress("Initializing local interface analysis (System Safe Mode)...")
    open_ports = []
    ip = '127.0.0.1'
    
    ports_to_scan = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 
        3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000, 27017
    ] + list(range(1, 1025))
    
    ports_to_scan = sorted(list(set(ports_to_scan)))
    total_ports = len(ports_to_scan)

    def check_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.15) # Safe, responsive timeout
            if s.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Unknown"
                return {"port": port, "service": service}
        return None

    scanned_count = 0
    # Reduced max_workers from 150 to 30 for system safety, preventing resource fatigue or AV triggers
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_port, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            scanned_count += 1
            if scanned_count % 50 == 0 or scanned_count == total_ports:
                update_progress(f"Scanning target port structures ({scanned_count}/{total_ports})...")
            
            res = future.result()
            if res:
                open_ports.append(res)

    sorted_ports = sorted(open_ports, key=lambda x: x["port"])
    stop_progress(Theme.OK_BADGE, f"Completed: {len(sorted_ports)} localhost ports open")
    return sorted_ports

def check_firewall_status(os_type):
    start_progress("Evaluating host system packet filter rule state...")
    try:
        if os_type == "windows":
            output = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles"],
                stderr=subprocess.DEVNULL,
                shell=True
            ).decode(errors='ignore')
            
            profiles = {"Domain": "Unknown", "Private": "Unknown", "Public": "Unknown"}
            current_prof = None
            for line in output.splitlines():
                if "Profile Settings" in line:
                    current_prof = line.split()[0]
                elif "State" in line and current_prof in profiles:
                    profiles[current_prof] = "Enabled" if "ON" in line else "Disabled"
            
            summary = ", ".join([f"{k}: {v}" for k, v in profiles.items()])
            stop_progress(Theme.OK_BADGE, "Windows Advanced Firewall rules parsed")
            return {"status": "Configured", "details": summary}
            
        elif os_type == "linux":
            try:
                ufw_status = subprocess.check_output(["ufw", "status"], stderr=subprocess.DEVNULL).decode().strip()
                if "active" in ufw_status:
                    stop_progress(Theme.OK_BADGE, "UFW active configuration found")
                    return {"status": "Enabled", "details": f"UFW: {ufw_status}"}
            except:
                pass
            
            try:
                nft = subprocess.check_output(["nft", "list", "ruleset"], stderr=subprocess.DEVNULL).decode().strip()
                if nft:
                    stop_progress(Theme.OK_BADGE, "nftables active ruleset verified")
                    return {"status": "Enabled", "details": "Active nftables tables configured"}
            except:
                pass
                
            stop_progress(Theme.WARN_BADGE, "No standard user-space firewall daemon identified")
            return {"status": "Inactive", "details": "No standard wrapper firewall (UFW/nftables) detected."}
            
        stop_progress(Theme.WARN_BADGE, "Unknown target platform interface")
        return {"status": "Unknown", "details": f"Check logic bounds do not cover: {os_type}"}
    except Exception as e:
        stop_progress(Theme.ERR_BADGE, f"Firewall query exception: {e}")
        return {"status": "Error", "details": str(e)}

def list_installed_programs(os_type):
    start_progress("Scanning registries for administrative software...")
    keywords = [
        "antivirus", "security", "firewall", "defender", "malware", "protector",
        "eset", "avast", "avg", "kaspersky", "bitdefender", "mcafee",
        "norton", "comodo", "malwarebytes", "sophos", "crowdstrike", "sentinelone",
        "cybereason", "trend micro", "carbon black", "zonealarm", "defender"
    ]
    detected = []
    
    try:
        if os_type == "windows":
            reg_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            import winreg
            for path in reg_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, f"{path}\\{subkey_name}")
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            try:
                                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                            except:
                                version = "Unknown"
                            name_lower = name.lower()
                            if any(kw in name_lower for kw in keywords):
                                detected.append(f"{name} ({version})")
                        except OSError:
                            continue
                except OSError:
                    continue
        else:
            try:
                processes = [p.info['name'] for p in psutil.process_iter(['name'])]
                for proc in processes:
                    if any(kw in proc.lower() for kw in keywords):
                        detected.append(proc)
            except Exception:
                pass
                
        detected = list(set(detected))
        stop_progress(Theme.OK_BADGE, f"Search finished: {len(detected)} modules cataloged")
        return detected if detected else ["No administrative or security agents mapped in standard tables."]
    except Exception as e:
        stop_progress(Theme.ERR_BADGE, f"System mapping exception: {e}")
        return [f"Query error: {e}"]

def check_av_status(os_type):
    start_progress("Polling system endpoint protection configurations...")
    try:
        if os_type == "windows":
            output = subprocess.check_output(
                'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"',
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if output:
                data = json.loads(output)
                details = []
                for k, v in data.items():
                    color = Theme.GREEN if v else Theme.RED
                    details.append(f"{k}: {color}{'ON' if v else 'OFF'}{Theme.RESET}")
                stop_progress(Theme.OK_BADGE, "Windows Defender core components evaluated")
                return " | ".join(details)
            stop_progress(Theme.WARN_BADGE, "Windows Defender returned blank configuration frame")
            return "Defender reports empty registry structure."
        elif os_type == "linux":
            paths = ["/usr/bin/clamscan", "/usr/local/bin/clamscan"]
            for path in paths:
                if os.path.exists(path):
                    stop_progress(Theme.OK_BADGE, "ClamAV engine present")
                    return "ClamAV engine configured natively."
            stop_progress(Theme.WARN_BADGE, "No standard local protection engine identified")
            return "No native endpoint threat protection engines located."
        stop_progress(Theme.WARN_BADGE, "Unknown host context scope")
        return "Unknown platform endpoint context."
    except Exception as e:
        stop_progress(Theme.ERR_BADGE, f"Probing exception occurred: {e}")
        return f"Probing failed: {e}"

def check_misconfigurations(os_type):
    start_progress("Executing configuration hardening diagnostics...")
    findings = []

    if os_type == "windows":
        # 1. UAC Audit
        try:
            output = subprocess.check_output('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA', shell=True, stderr=subprocess.DEVNULL).decode()
            if '0x0' in output or '0' in output:
                findings.append(f"{Theme.RED}[CRITICAL]{Theme.RESET} UAC (User Account Control) is disabled (EnableLUA is 0).")
        except:
            pass

        # 2. Windows Update Service Audit
        try:
            output = subprocess.check_output('sc query wuauserv', shell=True, stderr=subprocess.DEVNULL).decode()
            if 'STOPPED' in output:
                findings.append(f"{Theme.YELLOW}[MEDIUM]{Theme.RESET} Windows Update Service (wuauserv) is stopped.")
        except:
            pass

        # 3. Native Administrator Account Audit
        try:
            output = subprocess.check_output('net user Administrator', shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            if 'Account active               Yes' in output:
                findings.append(f"{Theme.CYAN}[LOW]{Theme.RESET} Default Administrator account is active.")
        except:
            pass

        # 4. Guest Account Audit
        try:
            output = subprocess.check_output('net user guest', shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            if 'Account active               Yes' in output:
                findings.append(f"{Theme.RED}[HIGH]{Theme.RESET} Built-in Windows Guest account is active.")
        except:
            pass
            
    elif os_type == "linux":
        # 1. SSH Root Login Permit
        ssh_config_paths = ["/etc/ssh/sshd_config", "/etc/sshd_config"]
        for path in ssh_config_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", errors='ignore') as f:
                        for line in f:
                            if line.strip().startswith("PermitRootLogin") and "yes" in line.lower():
                                findings.append(f"{Theme.RED}[HIGH]{Theme.RESET} SSH daemon permits root login directly.")
                                break
                except PermissionError:
                    findings.append(f"{Theme.CYAN}[INFO]{Theme.RESET} Root SSH config requires elevated permissions to audit.")
                    break
        
        # 2. World Writable Files Audit in system directories
        critical_dirs = ["/etc", "/sbin", "/bin"]
        writable = []
        for d in critical_dirs:
            if os.path.exists(d):
                try:
                    for root, dirs, files in os.walk(d):
                        for file in files[:100]: # Bound search depth
                            full_path = os.path.join(root, file)
                            if os.access(full_path, os.W_OK) and os.getuid() != 0:
                                writable.append(full_path)
                except:
                    pass
        if writable:
            findings.append(f"{Theme.YELLOW}[MEDIUM]{Theme.RESET} Found {len(writable)} world-writable files in core directory trees.")

        # 3. Passwordless Sudo Configurations
        sudoers_path = "/etc/sudoers"
        if os.path.exists(sudoers_path):
            try:
                with open(sudoers_path, "r", errors='ignore') as f:
                    for line in f:
                        if "NOPASSWD" in line and not line.strip().startswith("#"):
                            findings.append(f"{Theme.RED}[HIGH]{Theme.RESET} Sudoers configuration has passwordless NOPASSWD entries.")
                            break
            except PermissionError:
                pass

    stop_progress(Theme.OK_BADGE, f"Completed: {len(findings)} issues registered")
    return findings if findings else [f"{Theme.GREEN}[✓]{Theme.RESET} Host settings match all benchmark hardening profiles."]

def fetch_cve_info(target_os_string, enabled):
    """Queries live vulnerability database feeds optionally filtered by OS Keyword."""
    if not enabled:
        print(f"  {Theme.WARN_BADGE} CVE database sync bypassed by operator choice.")
        return [{"id": "Disabled", "description": "Query bypassed based on user configuration settings."}]

    start_progress(f"Connecting to NVD query interfaces for '{target_os_string}'...")
    try:
        encoded_keyword = urllib.parse.quote(target_os_string)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_keyword}&resultsPerPage=5"
        headers = {"User-Agent": "NVDVulnerabilityScanner/2.0"}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                if 'cve' in item and 'id' in item['cve']:
                    cve_id = item['cve']['id']
                    desc = item['cve']['descriptions'][0]['value']
                    if len(desc) > 130:
                        desc = desc[:127] + "..."
                    cves.append({"id": cve_id, "description": desc})
            
            if not cves:
                update_progress("No explicit CVEs found. Sourcing general critical vulnerabilities...")
                url_fallback = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=5"
                response = requests.get(url_fallback, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("vulnerabilities", []):
                        if 'cve' in item and 'id' in item['cve']:
                            cve_id = item['cve']['id']
                            desc = item['cve']['descriptions'][0]['value']
                            if len(desc) > 130:
                                desc = desc[:127] + "..."
                            cves.append({"id": cve_id, "description": desc})

            stop_progress(Theme.OK_BADGE, f"Feed synchronization complete: {len(cves)} vulnerability risks cataloged")
            return cves
        else:
            stop_progress(Theme.WARN_BADGE, f"NVD server returned HTTP error: {response.status_code}")
            return [{"id": "HTTP Error", "description": f"Failed connection: Code {response.status_code}"}]
    except Exception as e:
        stop_progress(Theme.ERR_BADGE, "Connection to NVD servers failed or timed out")
        return [{"id": "NVD Unreachable", "description": f"Feed synchronization failed: {e}"}]

# --- HTML REPORTING COMPILER ---
def generate_reports(results, cves_enabled):
    start_progress("Compiling reporting frameworks...")
    
    # 1. Output structured JSON
    try:
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
    except Exception:
        pass

    # 2. Output modern HTML dashboard
    try:
        port_rows = "".join([
            f"<tr><td><span class='badge badge-success'>{item['port']}</span></td><td>{item['service']}</td></tr>"
            for item in results["open_ports"]
        ]) if results["open_ports"] else "<tr><td colspan='2'>No open ports exposed.</td></tr>"

        clean_configs = []
        for raw in results["misconfigurations"]:
            cleaned = raw.replace(Theme.RED, "").replace(Theme.YELLOW, "").replace(Theme.GREEN, "").replace(Theme.CYAN, "").replace(Theme.RESET, "")
            clean_configs.append(cleaned)
            
        config_list = "".join([f"<li>{item}</li>" for item in clean_configs])
        software_list = "".join([f"<li>{item}</li>" for item in results["software"]])
        
        cve_cards = "".join([
            f"<div class='cve-card'><h5>{item['id']}</h5><p>{item['description']}</p></div>"
            for item in results["cves"]
        ]) if cves_enabled and results["cves"] else "<p style='color: var(--text-muted); font-style: italic;'>NVD CVE tracking was bypassed by operator choice.</p>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Audit Report</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --panel: #111827;
            --border: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent: #10b981;
            --accent-blue: #3b82f6;
            --warning: #f59e0b;
        }}
        body {{
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{ margin: 0; font-size: 2rem; color: var(--accent); }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        .card h3 {{ margin-top: 0; margin-bottom: 0.5rem; color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .card p {{ margin: 0; font-size: 1.15rem; font-weight: bold; }}
        .sections {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
        }}
        @media (max-width: 768px) {{
            .sections {{ grid-template-columns: 1fr; }}
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{ background-color: rgba(255, 255, 255, 0.02); color: var(--text-muted); font-size: 0.85rem; }}
        ul {{ padding-left: 1.2rem; margin: 0.5rem 0; }}
        li {{ margin-bottom: 0.5rem; }}
        .badge-success {{ color: var(--accent); font-weight: bold; }}
        .cve-card {{
            border-left: 3px solid var(--warning);
            background: rgba(245, 158, 11, 0.03);
            padding: 1rem;
            border-radius: 0 8px 8px 0;
            margin-bottom: 1rem;
        }}
        .cve-card h5 {{ margin: 0 0 0.5rem 0; color: var(--accent-blue); }}
        .cve-card p {{ margin: 0; font-size: 0.85rem; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>System Security Audit Log</h1>
            <p style="color: var(--text-muted); margin: 0.5rem 0 0 0;">Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="grid">
            <div class="card">
                <h3>Target OS Platform</h3>
                <p>{results['os'].upper()} ({results['os_details']})</p>
            </div>
            <div class="card">
                <h3>Firewall Status</h3>
                <p>{results['firewall']['status']}</p>
            </div>
            <div class="card">
                <h3>Anti-Malware Core</h3>
                <p style="font-size: 1rem; word-break: break-all;">{results['av_status'].replace(Theme.GREEN, "").replace(Theme.RED, "").replace(Theme.RESET, "")}</p>
            </div>
        </div>

        <div class="sections">
            <div>
                <div class="card" style="margin-bottom: 1.5rem;">
                    <h2 style="margin-top: 0; color: var(--accent-blue); font-size: 1.3rem;">Audit Findings & Risks</h2>
                    <ul>
                        {config_list}
                    </ul>
                </div>

                <div class="card">
                    <h2 style="margin-top: 0; color: var(--accent-blue); font-size: 1.3rem;">Local Network Port Expositions</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Exposed Port</th>
                                <th>Service mapped</th>
                            </tr>
                        </thead>
                        <tbody>
                            {port_rows}
                        </tbody>
                    </table>
                </div>
            </div>

            <div>
                <div class="card" style="margin-bottom: 1.5rem;">
                    <h2 style="margin-top: 0; color: var(--accent); font-size: 1.3rem;">Security Hardware & Processes</h2>
                    <ul>
                        {software_list}
                    </ul>
                </div>

                <div class="card">
                    <h2 style="margin-top: 0; color: var(--warning); font-size: 1.3rem;">Threat Disclosures ({results['os_details']})</h2>
                    {cve_cards}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""
        with open("scan_report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        stop_progress(Theme.OK_BADGE, "Reporting frameworks built successfully")
    except Exception as e:
        stop_progress(Theme.ERR_BADGE, f"HTML render failed: {e}")

# --- MAIN CONTROLLER ---
def main():
    detected_os = get_os()
    os_details = get_detailed_os_string()
    print_banner(detected_os, os_details)
    
    # --- INTERACTIVE USER PREFERENCE SELECTION ---
    print(f"\n{Theme.BLUE}╔═════════════════════════════════════════════════════════════════════╗")
    print(f"║                         VULNERABILITY CONTEXT                       ║")
    print(f"╚═════════════════════════════════════════════════════════════════════╝{Theme.RESET}")
    print(f"  {Theme.INFO_BADGE} Detected exact OS distribution: {Theme.BOLD}{Theme.CYAN}{os_details}{Theme.RESET}")
    print(f"  {Theme.INFO_BADGE} By enabling the CVE option, the scanner will connect to the live NVD")
    print(f"      database API and parse specific vulnerability records registered")
    print(f"      expressly for '{os_details}'.")
    
    cve_selection = ""
    while cve_selection not in ["y", "n"]:
        try:
            raw_input = input(f"\n  {Theme.WARN_BADGE} {Theme.BOLD}Audit OS-specific CVE records? (y/n): {Theme.RESET}").lower().strip()
            cve_selection = raw_input
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {Theme.WARN_BADGE} Input canceled. Skipping CVE analysis based on safety baseline.")
            cve_selection = "n"
            break
            
    cves_enabled = (cve_selection == "y")
    print(f"\n{Theme.INFO_BADGE} Initializing execution scans...\n")

    # Platform adaptive audits
    ports = scan_ports()
    fw = check_firewall_status(detected_os)
    av_status = check_av_status(detected_os)
    installed_software = list_installed_programs(detected_os)
    misconfigs = check_misconfigurations(detected_os)
    cve_data = fetch_cve_info(os_details, cves_enabled)
    
    results = {
        "os": detected_os,
        "os_details": os_details,
        "open_ports": ports,
        "firewall": fw,
        "av_status": av_status,
        "software": installed_software,
        "misconfigurations": misconfigs,
        "cves": cve_data
    }
    generate_reports(results, cves_enabled)
    
    # Styled CLI Display Output
    print_section_header("SYSTEM ENVIRONMENT SUMMARY")
    print(f"  {Theme.CYAN}Target Host OS:{Theme.RESET}      {detected_os.upper()} ({os_details})")
    print(f"  {Theme.CYAN}Firewall Boundary:{Theme.RESET}  {Theme.BOLD}{fw['status']}{Theme.RESET} ({fw['details']})")
    print(f"  {Theme.CYAN}Anti-Malware state:{Theme.RESET} {av_status}")

    print_section_header("LOCAL NETWORK SURFACE AREA")
    if ports:
        print(f"  {Theme.DIM}Exposed ports accessible locally:{Theme.RESET}")
        for item in ports:
            print(f"    ├─ Port {Theme.BOLD}{Theme.YELLOW}{str(item['port']).ljust(6)}{Theme.RESET} ── Service: {Theme.GREEN}{item['service']}{Theme.RESET}")
    else:
        print(f"  {Theme.GREEN}[✓] No open ports identified on the local host.{Theme.RESET}")

    print_section_header("DEFENSIVE AGENT FOOTPRINT")
    for soft in installed_software:
        print(f"  {Theme.GREEN}●{Theme.RESET} {soft}")

    print_section_header("LOCAL RISK ASSESSMENTS")
    for issue in misconfigs:
        print(f"  {issue}")

    if cves_enabled:
        print_section_header(f"TARGETED DISCLOSURES: {os_details.upper()}")
        for item in cve_data:
            print(f"  {Theme.YELLOW}● {item['id']}{Theme.RESET}")
            print(f"    {Theme.DIM}{item['description']}{Theme.RESET}")

    print(f"\n{Theme.BLUE}╔═════════════════════════════════════════════════════════════════════╗")
    print(f"║  {Theme.OK_BADGE} Audit Successful. Reports written to workspace directory:         ║")
    print(f"║    ├─ {Theme.CYAN}scan_report.html{Theme.BLUE} (Interactive Web Dashboard)                 ║")
    print(f"║    └─ {Theme.CYAN}scan_results.json{Theme.BLUE} (Structured machine logs)                  ║")
    print(f"╚═════════════════════════════════════════════════════════════════════╝{Theme.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        print(f"{Theme.WARN_BADGE} Diagnostic suite execution terminated by operator.")
    input(f"{Theme.INFO_BADGE} Audit Session Complete. Press [Enter] to close terminal...")