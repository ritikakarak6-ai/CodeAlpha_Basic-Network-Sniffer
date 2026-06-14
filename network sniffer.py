import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        

        proto_name = "Unknown"
        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        elif proto == 1:
            proto_name = "ICMP"

        print(f"\n{"="*60}")
        print(f"[+] New Packet Captured:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto_name} (ID: {proto})")


        if TCP in packet:
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Dest Port      : {packet[TCP].dport}")
            print(f"    Flags          : {packet[TCP].flags}")
            
     elif UDP in packet:
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Dest Port      : {packet[UDP].dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
         
            print(f"    Payload Data   : {repr(payload[:100])}...")
        else:
            print(f"    Payload Data   : No Raw Payload")
            
        print(f"{"="*60}")

def main():
    print("="*60)
    print("         CODEALPHA - BASIC NETWORK SNIFFER (WINDOWS)         ")
    print("="*60)
    print("[*] Starting Basic Network Sniffer...")
    print("[*] Monitoring network traffic... Press Ctrl+C to stop.\n")
    
   
    try:
       
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[!] Error: Access Denied! Please run Command Prompt as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


