# The-Ultimate-IT-Scanner-
A plug-and-play Python-based system scanner that auto-detects vulnerabilities, misconfigurations, open ports, defensive tools, and fetches live CVEs from the NVD API. Cross-platform, dependency-free, and hacker-ready.

PlugNPlay Vulnerability Scanner — Installation & Setup
Welcome to PlugNPlay. This tool is designed to give you a plug-and-play experience: run it on any Windows, Linux, or macOS machine and get a full vulnerability check without needing to configure anything manually.

Whether you're a professional or just getting started, follow this guide to get up and running in minutes.

Files Included
plugnplay.py — the main scanner script (written in Python)

launch_plugnplay.bat — Windows launcher to run the scanner

README.txt — summary of this documentation

Installation Guide
Windows
1. Make sure Python is installed

If you're unsure, try the following:

Open the Command Prompt

Type:
'python --version'
If you see an error saying Python is not recognized, install it from:

https://www.python.org/downloads/windows

Important: During installation, be sure to select the checkbox that says "Add Python to PATH".

2. Run the scanner

Once Python is installed:

Double-click launch_plugnplay.bat

A terminal window will open

The script will install the required Python libraries (psutil, requests) silently

It will then begin scanning your system

You’ll see results printed in the terminal once the scan is complete — including open ports, firewall/AV status, installed security software, misconfigurations, and recent critical CVEs from the NVD database.

Linux
1. Install Python (if not installed)

On Debian-based systems (Ubuntu, Kali, etc.):

'sudo apt update
sudo apt install python3 python3-pip -y'

On Arch-based systems:

'sudo pacman -S python python-pip'

2. Run the scanner

'pip3 install psutil requests
python3 plugnplay.py'

If you want to run it without typing the command every time, create a shell script or alias.

macOS
1. Make sure Python and pip are available

If needed, install Xcode command line tools:

'xcode-select --install'

2. Install requirements and run

'python3 -m pip install --upgrade pip
pip3 install psutil requests
python3 plugnplay.py'

To make launching easier on Windows, include this .bat file alongside your script:

'@echo off
echo Launching PlugNPlay Scanner...
python plugnplay.py'

Troubleshooting
If nothing happens, double-check that Python is correctly installed and added to PATH.

Make sure your internet is working — the scanner fetches live CVE data.

If permissions errors occur, try running as Administrator (on Windows) or with sudo (on Linux/macOS).

The port scan or AV check may take a few seconds. Be patient — the tool is doing real work.
