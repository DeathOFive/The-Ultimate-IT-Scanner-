import platform
import socket
import subprocess
import time
import sys
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def ensure_dependencies():
    print("[*] Checking required modules...")
    required = ["psutil", "requests"]
    for module in required:
        try:
            __import__(module)
        except ImportError:
            print(f"[!] Missing module: {module}. Attempting to install...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', module, '--quiet'])
                print(f"[+] Installed {module} successfully.")
            except Exception as e:
                print(f"[!] Failed to install {module}: {e}")
                sys.exit(1)

ensure_dependencies()
import psutil

spinner_running = True

def spinner():
    while spinner_running:
        for c in '|/-\\':
            sys.stdout.write(f'\r[*] Initializing Scanner... {c}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\r[*] Initialization Complete.     \n')

def get_os():
    print("[*] Detecting OS...")
    return platform.system().lower()

def scan_ports():
    print("[*] Scanning open ports on 127.0.0.1 (fast mode)...")
    open_ports = []
    ip = '127.0.0.1'
    ports_to_scan = list(range(1, 1025))

    def check_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex((ip, port)) == 0:
                return port

    with ThreadPoolExecutor(max_workers=200) as executor:
        future_to_port = {executor.submit(check_port, port): port for port in ports_to_scan}
        for future in as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)

    return sorted(open_ports)

def check_firewall_status():
    print("[*] Checking firewall status...")
    os_type = platform.system().lower()
    try:
        if os_type == "windows":
            output = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles"], shell=True).decode()
            return "ON" if "State ON" in output else "OFF"
        elif os_type == "linux":
            output = subprocess.check_output(["ufw", "status"], stderr=subprocess.DEVNULL).decode()
            return output.strip()
        elif os_type == "darwin":
            output = subprocess.check_output(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]).decode()
            return output.strip()
        else:
            return "Unknown OS - cannot check firewall"
    except Exception as e:
        return f"Error checking firewall: {e}"

def list_installed_programs():
    print("[*] Searching for defensive/admin software...")
    os_type = platform.system().lower()
    keywords = [
        "antivirus", "security", "firewall", "defender", "malware", "protector",
        "eset", "avast", "avg", "kaspersky", "bitdefender", "mcafee",
        "norton", "comodo", "malwarebytes", "sophos", "crowdstrike", "sentinelone",
        "cybereason", "trend micro", "carbon black", "zonealarm"
    ]
    try:
        if os_type == "windows":
            output = subprocess.check_output(
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s',
                shell=True,
                stderr=subprocess.DEVNULL
            ).decode(errors='ignore')
            lines = output.splitlines()
            filtered_programs = []
            current_name, current_version = None, None

            for line in lines:
                if "DisplayName" in line:
                    current_name = line.split("    ")[-1].strip()
                elif "DisplayVersion" in line and current_name:
                    current_version = line.split("    ")[-1].strip()
                    name_lc = current_name.lower()
                    if any(kw in name_lc for kw in keywords):
                        filtered_programs.append(f"{current_name} ({current_version})")
                    current_name, current_version = None, None

            return "\n".join(filtered_programs) if filtered_programs else "No security/admin tools detected."
        else:
            return "Program listing not supported on this OS yet."
    except Exception as e:
        return f"Error: {e}"

def check_av_status():
    print("[*] Checking antivirus status...")
    os_type = platform.system().lower()
    try:
        if os_type == "windows":
            output = subprocess.check_output(
                'powershell -Command "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled"',
                shell=True
            ).decode()
            return output.strip()
        else:
            return "AV status check not supported on this OS."
    except Exception as e:
        return f"Error checking AV status: {e}"

def check_misconfigurations():
    print("[*] Checking for common misconfigurations...")
    findings = []
    os_type = platform.system().lower()

    if os_type == "windows":
        try:
            uac = subprocess.check_output('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA', shell=True).decode()
            if '0x0' in uac:
                findings.append("UAC (User Account Control) is disabled.")
        except:
            findings.append("Could not check UAC settings.")

        try:
            wu = subprocess.check_output('sc qc wuauserv', shell=True).decode()
            if 'STATE              : 1  STOPPED' in wu:
                findings.append("Windows Update service is disabled.")
        except:
            findings.append("Could not verify Windows Update service status.")

        try:
            guest = subprocess.check_output('net user guest', shell=True).decode()
            if 'Account active               Yes' in guest:
                findings.append("Guest account is enabled.")
        except:
            findings.append("Could not check guest account status.")

        try:
            autologin = subprocess.check_output('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon', shell=True).decode()
            if '1' in autologin:
                findings.append("Auto-login is enabled.")
        except:
            findings.append("Could not verify auto-login setting.")
    else:
        findings.append("Misconfig checks for non-Windows OS not yet implemented.")

    return "\n".join(findings) if findings else "No obvious misconfigurations detected."

def fetch_cve_info():
    print("[*] Checking CVEs from NVD...")
    try:
        import requests
    except ImportError:
        print("[!] requests module not installed. Skipping CVE fetch.")
        return "requests module not available"

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=5"
        headers = {"User-Agent": "VulnScanner/1.0"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cves = [
    f"{item['cve']['id']} - {item['cve']['descriptions'][0]['value']}"
    for item in data.get("vulnerabilities", []) if 'cve' in item and 'id' in item['cve']
]
            return "\n".join(cves) if cves else "No critical CVEs found."
        else:
            return f"Failed to fetch CVEs (HTTP {response.status_code})"
    except Exception as e:
        return f"CVE fetch error: {e}"

def run_scans():
    global spinner_running
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.start()
    time.sleep(2.5)  # Let spinner show for a bit
    spinner_running = False
    spinner_thread.join()

    print("[*] Starting system scan...")
    os_type = get_os()
    print(f"[+] OS: {os_type}")

    ports = scan_ports()
    print(f"[+] Open Ports: {ports}")

    fw = check_firewall_status()
    print(f"[+] Firewall: {fw}")

    av_status = check_av_status()
    print(f"[+] Antivirus Status:\n{av_status}")

    installed_software = list_installed_programs()
    print(f"[+] Defensive/Admin Software:\n{installed_software}")

    misconfigs = check_misconfigurations()
    print(f"[+] Misconfiguration Findings:\n{misconfigs}")

    cve_data = fetch_cve_info()
    print(f"[+] Recent Critical CVEs:\n{cve_data}")

    return {
        "os": os_type,
        "open_ports": ports,
        "firewall": fw,
        "av_status": av_status,
        "software": installed_software,
        "misconfigurations": misconfigs
    }

if __name__ == "__main__":
    run_scans()
    input("\n[!] Press Enter to exit...")