import socket
import subprocess
import ssl
from termcolor import colored

TCP_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 143, 443,
    465, 587, 993, 995, 1080, 8080, 8443,
    1337, 4444, 5000, 6666, 8000, 9001, 13337, 31337,
    49152, 50000, 65000
]

UDP_PORTS = [53, 123]

PORT_LABELS = {
    20: "FTP - raw file transfer - data",
    21: "FTP - control channel - commands",
    22: "SSH - interactive shell - scp upload",
    23: "Telnet - unencrypted text exfil",
    25: "SMTP - outbound email exfil",
    53: "DNS - tunneling - iodine - dnscat",
    69: "TFTP - unauthenticated file transfer",
    80: "HTTP - post - webhook - get exfil",
    110: "POP3 - mail exfil via download",
    143: "IMAP - mail access - exfil vector",
    443: "HTTPS - encrypted post - TLS tunnel",
    465: "SMTPS - encrypted outbound email",
    587: "SMTP TLS - authenticated mail send",
    993: "IMAPS - secure inbox access",
    995: "POP3S - secure mail retrieval",
    1080: "SOCKS - proxy tunnel - bypass",
    8080: "Alt HTTP - proxy - API exfil",
    8443: "Alt HTTPS - secure API or UI",
    1337: "Custom port - tunnel - C2",
    4444: "Generic port - remote shell - metasploit",
    5000: "Dev API - webhook exfil - listener",
    6666: "IRC - simple tunnel or control",
    8000: "HTTP dev server - exfil endpoint",
    9001: "Tor - proxy relay - obfuscated exfil",
    13337: "custom services",
    31337: "custom services",
    49152: "custom services",
    50000: "custom services",
    65000: "custom services"
}

DNS_TEST_DOMAIN = "example.com"
TIMEOUT = 3

TCP_PRIMARY_HOST = "portquiz.net"
TCP_SECONDARY_HOST = "ping.online.net"

TEST_UDP_ICMP_IP = "1.1.1.1"

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def print_result(status, proto, port, label=""):
    icon = {
        "open": colored("[open]", "green"),
        "filtered": colored("[filtered]", "blue"),
        "blocked": colored("[blocked]", "red")
    }.get(status, colored("[?]", "yellow"))
    label_str = f" ({label})" if label else ""
    print(f"{icon} {proto.upper()} port {port}{label_str}")

def test_tcp(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        s.close()
        return True
    except:
        return False

def test_tcp_dual(port):
    ip1 = resolve_host(TCP_PRIMARY_HOST)
    ip2 = resolve_host(TCP_SECONDARY_HOST)
    label = PORT_LABELS.get(port, "")

    result1 = test_tcp(ip1, port) if ip1 else False
    result2 = test_tcp(ip2, port) if ip2 else False

    if result1:
        print_result("open", "tcp", port, label)
        return "open"
    elif result2:
        print_result("filtered", "tcp", port, label)
        return "filtered"
    else:
        print_result("blocked", "tcp", port, label)
        return "blocked"

def test_udp(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(b'\x00', (ip, port))
        try:
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "filtered"
        except:
            return "blocked"
    except:
        return "blocked"

def test_dns(domain):
    try:
        socket.gethostbyname(domain)
        print(colored("[open]", "green") + f" DNS resolution OK: {domain}")
    except:
        print(colored("[x]", "red") + f" DNS resolution FAILED: {domain}")

def test_icmp(ip):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", str(TIMEOUT), ip], stderr=subprocess.DEVNULL)
        print(colored("[open]", "green") + f" ICMP - echo request allowed - data exfiltration possible via payload")
    except:
        print(colored("[blocked]", "red") + f" ICMP - blocked - no ping - exfiltration via echo payload not possible")

def test_https(ip, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname="example.com") as ssock:
                ssock.getpeercert()
                print(colored("[open]", "green") + f" HTTPS TLS handshake OK on port {port}")
                return "open"
    except ssl.SSLError:
        print(colored("[filtered]", "blue") + f" HTTPS intercepted on port {port}")
        return "filtered"
    except:
        print(colored("[blocked]", "red") + f" HTTPS blocked on port {port}")
        return "blocked"

def main():
    print(colored("[?] Testing DNS", "yellow"))
    test_dns(DNS_TEST_DOMAIN)

    print(colored(f"\n[?] Testing TCP (dual host: {TCP_PRIMARY_HOST} / {TCP_SECONDARY_HOST})", "yellow"))
    open_ports = []
    filtered_ports = []
    blocked_ports = []
    
    for port in TCP_PORTS:
        result = test_tcp_dual(port)
        if result == "open":
            open_ports.append(port)
        elif result == "filtered":
            filtered_ports.append(port)
        else:
            blocked_ports.append(port)

    print(colored("\n[?] Testing UDP (to 1.1.1.1)", "yellow"))
    for port in UDP_PORTS:
        status = test_udp(TEST_UDP_ICMP_IP, port)
        print_result(status, "udp", port, PORT_LABELS.get(port, ""))

    print(colored("\n[?] Testing ICMP (ping)", "yellow"))
    test_icmp(TEST_UDP_ICMP_IP)

    print(colored("\n[?] Testing HTTPS TLS (to 1.1.1.1)", "yellow"))
    https_status = test_https(TEST_UDP_ICMP_IP, 443)
    
    if https_status == "filtered":
        if 443 in open_ports:
            open_ports.remove(443)
        filtered_ports.append(443)

    print(colored("\n[!] Security Analysis:", "cyan"))
    
    critical_ports = [22, 23, 69, 1080, 1337, 4444, 5000, 6666, 8000, 9001, 13337, 31337, 49152, 50000, 65000]
    open_critical_ports = []
    for port in critical_ports:
        if port in open_ports:
            open_critical_ports.append(port)
    
    if open_critical_ports:
        print(colored(f"[!] WARNING: {len(open_critical_ports)} non-essential ports are open:", "red"))
        for port in open_critical_ports:
            if port == 22:
                print(colored(f"    - SSH (22) is open - potential remote access", "red"))
            elif port == 23:
                print(colored(f"    - Telnet (23) is open - unencrypted access", "red"))
            elif port == 69:
                print(colored(f"    - TFTP (69) is open - unauthenticated file transfer", "red"))
            elif port == 1080:
                print(colored(f"    - SOCKS (1080) is open - proxy tunnel possible", "red"))
            elif port == 1337:
                print(colored(f"    - Custom port (1337) is open - potential C2", "red"))
            elif port == 4444:
                print(colored(f"    - Generic port (4444) is open - potential shell", "red"))
            elif port == 5000:
                print(colored(f"    - Dev API (5000) is open - potential webhook", "red"))
            elif port == 6666:
                print(colored(f"    - IRC (6666) is open - potential tunnel", "red"))
            elif port == 8000:
                print(colored(f"    - HTTP dev (8000) is open - potential endpoint", "red"))
            elif port == 9001:
                print(colored(f"    - Tor (9001) is open - potential relay", "red"))
            else:
                print(colored(f"    - Custom port ({port}) is open", "red"))
    
    total_ports = len(TCP_PORTS)
    open_percentage = (len(open_ports) / total_ports) * 100
    
    print(colored("\n[!] Network Filtering Analysis:", "cyan"))
    print(f"    - {open_percentage:.1f}% of tested ports are open ({len(open_ports)}/{total_ports})")
    print(f"    - {len(filtered_ports)} ports are filtered")
    print(f"    - {len(blocked_ports)} ports are blocked")
    
    if open_percentage > 80:
        print(colored("    - WARNING: High number of open ports - minimal outbound filtering", "red"))
    elif open_percentage > 50:
        print(colored("    - CAUTION: Moderate number of open ports - partial filtering", "yellow"))
    else:
        print(colored("    - Good: Strong outbound port filtering", "green"))
    
    print(colored("\n[!] Essential Services Analysis:", "cyan"))
    
    if 53 in open_ports:
        print(colored("    - DNS (53): Available - essential for web navigation", "green"))
    else:
        print(colored("    - DNS (53): Blocked - web navigation will be limited", "red"))
    
    if 80 in open_ports and 443 in open_ports:
        print(colored("    - Web: Both HTTP and HTTPS available - full web access", "green"))
    elif 443 in open_ports:
        print(colored("    - Web: Only HTTPS available - secure web access", "green"))
    elif 80 in open_ports:
        print(colored("    - Web: Only HTTP available - unencrypted web access", "yellow"))
    else:
        print(colored("    - Web: No web access available", "red"))
    
    if 25 in open_ports or 465 in open_ports or 587 in open_ports:
        print(colored("    - Email: SMTP available - email sending possible", "green"))
    else:
        print(colored("    - Email: No SMTP available - email sending blocked", "yellow"))
    
    print(colored("\n[!] Recommendations:", "cyan"))
    if open_percentage > 80:
        print(colored("    1. Implement strict outbound firewall rules", "red"))
        print(colored("    2. Block unnecessary outbound ports", "red"))
        print(colored("    3. Monitor outbound connections", "red"))
    elif open_percentage > 50:
        print(colored("    1. Review and reduce open outbound ports", "yellow"))
        print(colored("    2. Implement application-level filtering", "yellow"))
    else:
        print(colored("    1. Maintain current filtering policies", "green"))
        print(colored("    2. Regular security audits recommended", "green"))

if __name__ == "__main__":
    main()
