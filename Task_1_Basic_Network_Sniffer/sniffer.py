from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
import os
from collections import Counter


# -----------------------------
# COLORS FOR CLI DESIGN
# -----------------------------
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


# -----------------------------
# GLOBAL VARIABLES FOR STATS
# -----------------------------
packet_stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}

src_ip_counter = Counter()
dst_ip_counter = Counter()
port_counter = Counter()


# -----------------------------
# LOGGING SETUP
# -----------------------------
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_file_name = None


def banner():
    print(f"""{CYAN}{BOLD}
===========================================================
               CodeAlpha - Network Sniffer v2.0
===========================================================
   Author : IRFAN CSH
   Tool   : Basic Packet Sniffer (Professional CLI)
   Library: Scapy (Python)
===========================================================
{RESET}""")


def save_to_log(text):
    global log_file_name
    if log_file_name:
        with open(log_file_name, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "OTHER"


def get_tcp_flags(packet):
    if TCP in packet:
        flags = packet[TCP].flags
        return str(flags)
    return None


def update_statistics(packet, protocol, src_ip, dst_ip):
    packet_stats["total"] += 1

    if protocol == "TCP":
        packet_stats["tcp"] += 1
    elif protocol == "UDP":
        packet_stats["udp"] += 1
    elif protocol == "ICMP":
        packet_stats["icmp"] += 1
    else:
        packet_stats["other"] += 1

    src_ip_counter[src_ip] += 1
    dst_ip_counter[dst_ip] += 1

    if TCP in packet:
        port_counter[packet[TCP].dport] += 1
    elif UDP in packet:
        port_counter[packet[UDP].dport] += 1


def display_summary(packet, src_ip, dst_ip, protocol, src_port, dst_port, length):
    print(f"{GREEN}[+] {protocol:<5}{RESET} {src_ip}:{src_port}  -->  {dst_ip}:{dst_port}  | Len: {length}")


def display_detailed(packet, src_ip, dst_ip, protocol, src_port, dst_port, length):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{CYAN}==================================================={RESET}")
    print(f"{YELLOW}Time:{RESET} {timestamp}")
    print(f"{BLUE}Source IP:{RESET} {src_ip}")
    print(f"{BLUE}Destination IP:{RESET} {dst_ip}")
    print(f"{BLUE}Protocol:{RESET} {protocol}")
    print(f"{BLUE}Packet Length:{RESET} {length}")

    if src_port is not None and dst_port is not None:
        print(f"{BLUE}Source Port:{RESET} {src_port}")
        print(f"{BLUE}Destination Port:{RESET} {dst_port}")

    # TCP Flags
    flags = get_tcp_flags(packet)
    if flags:
        print(f"{BLUE}TCP Flags:{RESET} {flags}")

    # Payload (first 80 bytes)
    try:
        payload = bytes(packet[IP].payload)
        if payload:
            print(f"{BLUE}Payload (First 80 bytes):{RESET} {payload[:80]}")
        else:
            print(f"{BLUE}Payload:{RESET} None")
    except:
        print(f"{BLUE}Payload:{RESET} None")

    print(f"{CYAN}==================================================={RESET}")


def packet_callback(packet, display_mode, ip_filter, port_filter):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = get_protocol(packet)
    length = len(packet)

    src_port = None
    dst_port = None

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # IP Filter
    if ip_filter:
        if src_ip != ip_filter and dst_ip != ip_filter:
            return

    # Port Filter
    if port_filter:
        if src_port != port_filter and dst_port != port_filter:
            return

    # Update stats
    update_statistics(packet, protocol, src_ip, dst_ip)

    # Display output
    if display_mode == "1":
        display_summary(packet, src_ip, dst_ip, protocol, src_port, dst_port, length)
    else:
        display_detailed(packet, src_ip, dst_ip, protocol, src_port, dst_port, length)

    # Save to log if enabled
    log_entry = f"[{protocol}] {src_ip}:{src_port} --> {dst_ip}:{dst_port} | Length: {length}"
    save_to_log(log_entry)


def choose_interface():
    interfaces = get_if_list()

    print(f"\n{BOLD}{CYAN}Available Interfaces:{RESET}")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}) {iface}")

    choice = input(f"\n{YELLOW}Select interface number: {RESET}").strip()

    try:
        choice = int(choice)
        if 1 <= choice <= len(interfaces):
            return interfaces[choice - 1]
        else:
            print(f"{RED}[X] Invalid choice. Defaulting to first interface.{RESET}")
            return interfaces[0]
    except:
        print(f"{RED}[X] Invalid input. Defaulting to first interface.{RESET}")
        return interfaces[0]


def choose_protocol_filter():
    print(f"\n{BOLD}{CYAN}Select Protocol Filter:{RESET}")
    print("1) TCP")
    print("2) UDP")
    print("3) ICMP")
    print("4) ALL")

    choice = input(f"{YELLOW}Enter choice (1-4): {RESET}").strip()

    if choice == "1":
        return "tcp"
    elif choice == "2":
        return "udp"
    elif choice == "3":
        return "icmp"
    else:
        return ""


def choose_display_mode():
    print(f"\n{BOLD}{CYAN}Select Display Mode:{RESET}")
    print("1) Summary Mode (Fast Output)")
    print("2) Detailed Mode (Full Packet Info)")

    choice = input(f"{YELLOW}Enter choice (1-2): {RESET}").strip()

    if choice not in ["1", "2"]:
        print(f"{RED}[X] Invalid choice. Defaulting to Summary Mode.{RESET}")
        return "1"

    return choice


def choose_save_option():
    global log_file_name

    choice = input(f"\n{YELLOW}Do you want to save logs to file? (Y/N): {RESET}").strip().lower()

    if choice == "y":
        log_file_name = datetime.now().strftime("logs/sniffer_log_%Y-%m-%d_%H-%M-%S.txt")
        print(f"{GREEN}[+] Logging enabled: {log_file_name}{RESET}")
    else:
        log_file_name = None
        print(f"{RED}[!] Logging disabled. No file will be saved.{RESET}")


def choose_packet_count():
    count = input(f"\n{YELLOW}Enter packet count (0 for unlimited): {RESET}").strip()

    try:
        return int(count)
    except:
        return 0


def show_statistics():
    print(f"\n{BOLD}{CYAN}================== CAPTURE STATISTICS =================={RESET}")
    print(f"{GREEN}Total Packets Captured:{RESET} {packet_stats['total']}")
    print(f"{GREEN}TCP Packets:{RESET} {packet_stats['tcp']}")
    print(f"{GREEN}UDP Packets:{RESET} {packet_stats['udp']}")
    print(f"{GREEN}ICMP Packets:{RESET} {packet_stats['icmp']}")
    print(f"{GREEN}Other Packets:{RESET} {packet_stats['other']}")

    if src_ip_counter:
        top_src = src_ip_counter.most_common(3)
        print(f"\n{YELLOW}Top Source IPs:{RESET}")
        for ip, count in top_src:
            print(f"  {ip}  -> {count} packets")

    if dst_ip_counter:
        top_dst = dst_ip_counter.most_common(3)
        print(f"\n{YELLOW}Top Destination IPs:{RESET}")
        for ip, count in top_dst:
            print(f"  {ip}  -> {count} packets")

    if port_counter:
        top_ports = port_counter.most_common(3)
        print(f"\n{YELLOW}Top Destination Ports:{RESET}")
        for port, count in top_ports:
            print(f"  Port {port} -> {count} packets")

    print(f"{BOLD}{CYAN}========================================================={RESET}\n")


def main():
    banner()

    interface = choose_interface()
    protocol_filter = choose_protocol_filter()
    display_mode = choose_display_mode()

    ip_filter = input(f"\n{YELLOW}Enter IP Filter (leave blank for none): {RESET}").strip()
    if ip_filter == "":
        ip_filter = None

    port_filter_input = input(f"{YELLOW}Enter Port Filter (leave blank for none): {RESET}").strip()
    if port_filter_input == "":
        port_filter = None
    else:
        try:
            port_filter = int(port_filter_input)
        except:
            port_filter = None

    choose_save_option()
    packet_count = choose_packet_count()

    print(f"\n{CYAN}[i] Interface Selected:{RESET} {interface}")
    print(f"{CYAN}[i] Protocol Filter:{RESET} {protocol_filter if protocol_filter else 'ALL'}")
    print(f"{CYAN}[i] Display Mode:{RESET} {'Summary' if display_mode == '1' else 'Detailed'}")
    print(f"{CYAN}[i] IP Filter:{RESET} {ip_filter if ip_filter else 'None'}")
    print(f"{CYAN}[i] Port Filter:{RESET} {port_filter if port_filter else 'None'}")
    print(f"{CYAN}[i] Packet Count:{RESET} {packet_count if packet_count != 0 else 'Unlimited'}")

    print(f"\n{GREEN}[+] Sniffing Started... Press CTRL+C to stop.{RESET}\n")

    try:
        sniff(
            iface=interface,
            filter=protocol_filter,
            prn=lambda pkt: packet_callback(pkt, display_mode, ip_filter, port_filter),
            store=False,
            count=packet_count if packet_count > 0 else 0
        )
    except PermissionError:
        print(f"{RED}[X] Permission denied! Run as root/administrator.{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Sniffing stopped by user.{RESET}")
    except Exception as e:
        print(f"{RED}[X] Error: {e}{RESET}")

    show_statistics()

    if log_file_name:
        print(f"{GREEN}[+] Logs saved successfully in: {log_file_name}{RESET}")
    else:
        print(f"{YELLOW}[!] No logs were saved (Logging disabled).{RESET}")


if __name__ == "__main__":
    main()
