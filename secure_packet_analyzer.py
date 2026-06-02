import sys
import collections
from scapy.all import sniff, IP, TCP, UDP, ICMP

# 1. ADDING TRAFFIC STATISTICS & RECRUITER PORT SCAN COUNTERS
packet_counts = collections.Counter()
syn_flood_tracker = collections.defaultdict(set) # Tracks unique ports hit by a single IP

def process_secure_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Track total packet counts for our dashboard statistics
        packet_counts['Total IP Packets'] += 1

        # Determine precise Protocol and extract true application-layer data
        if packet.haslayer(TCP):
            packet_counts['TCP Packets'] += 1
            protocol_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # FIXED WEAKNESS #2: Extracting real application payload, skipping TCP headers
            payload = bytes(packet[TCP].payload)
            
            # FIXED WEAKNESS #3: ADDING THREAT DETECTION (Basic IDS for Port Scanning)
            # If we see connection flags (SYN), track what ports the IP is poking at
            if packet[TCP].flags == "S":
                syn_flood_tracker[src_ip].add(dport)
                if len(syn_flood_tracker[src_ip]) > 5: # More than 5 different ports hit
                    print(f"\n[⚠️ SECURITY ALERT] Possible Port Scan Detected from IP: {src_ip}!")
                    print(f"    -> Attacker probing target ports: {list(syn_flood_tracker[src_ip])}")

        elif packet.haslayer(UDP):
            packet_counts['UDP Packets'] += 1
            protocol_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload)
            
        elif packet.haslayer(ICMP):
            packet_counts['ICMP Packets'] += 1
            protocol_name = "ICMP"
            sport, dport = "N/A", "N/A"
            payload = bytes(packet[ICMP].payload)
        else:
            packet_counts['Other Proto'] += 1
            return

        # Terminal Printout Dashboard
        print(f"\n[+] [{protocol_name}] {src_ip}:{sport} -> {dst_ip}:{dport}")
        
        # Safely parse raw application layer payload string snippet
        if payload:
            clean_payload = ''.join([chr(b) if 32 <= b < 127 else '.' for b in payload[:60]])
            print(f"    Raw Application Payload: {clean_payload}")

def main():
    print("===============================================================")
    print("      ADVANCED NETWORK TRAFFIC ANALYZER & BASIC IDS            ")
    print("===============================================================")
    
    # FIXED WEAKNESS #1 & IMPRESS RECRUITER: Adding a BPF Packet Filter
    print("\nSelect a Packet Filter Option:")
    print("1. Capture Everything (No Filter)")
    print("2. Capture TCP Only (Web/SSH traffic)")
    print("3. Capture UDP Only (DNS/Streaming)")
    choice = input("Enter choice (1-3): ").strip()
    
    bpf_filter = ""
    if choice == "2":
        bpf_filter = "tcp"
        print("[!] BPF Filter Enabled: Filtering for TCP traffic only.")
    elif choice == "3":
        bpf_filter = "udp"
        print("[!] BPF Filter Enabled: Filtering for UDP traffic only.")
    else:
        print("[!] Capturing all IP network traffic layers.")

    print("\n[*] Analysis engine running... Press Ctrl+C to stop and view metrics.")
    
    try:
        # FIXED WEAKNESS #6: Proper Permission Error trapping
        sniff(filter=bpf_filter, prn=process_secure_packet, store=0)
    except KeyboardInterrupt:
        # FIXED WEAKNESS #5: IMPRESS RECRUITER WITH A LIVE METRICS DASHBOARD
        print("\n\n===============================================================")
        print("                 SESSION TRAFFIC STATISTICS REPORT             ")
        print("===============================================================")
        for statistic, value in packet_counts.items():
            print(f" -> {statistic}: {value}")
        print("===============================================================")
        print("[*] Session closed cleanly.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] CRITICAL ERROR: Administrative root privileges required.")
        sys.exit(1)

if __name__ == "__main__":
    main()
