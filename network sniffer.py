import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    # ১. শুধুমাত্র IP প্যাকেটগুলো ফিল্টার এবং অ্যানালাইসিস করা হচ্ছে
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # প্রোটোকলের নাম নির্ধারণ করা
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

        # ২. TCP লেয়ারের ইনফরমেশন এবং পোর্ট অ্যানালাইসিস
        if TCP in packet:
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Dest Port      : {packet[TCP].dport}")
            print(f"    Flags          : {packet[TCP].flags}")

        # ৩. UDP লেয়ারের ইনফরমেশন
        elif UDP in packet:
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Dest Port      : {packet[UDP].dport}")

        # ৪. Payload বা ডেটা কন্টেন্ট ডিসপ্লে করা (যদি থাকে)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # অনেক সময় বাইট ডেটা প্রিন্ট করতে এরর দেয়, তাই safe decoding বা printable format দেখানো হচ্ছে
            print(f"    Payload Data   : {repr(payload[:100])}...") # প্রথম ১০০ ক্যারেক্টার দেখাচ্ছে
        else:
            print(f"    Payload Data   : No Raw Payload")
            
        print(f"{"="*60}")

def main():
    print("="*60)
    print("         CODEALPHA - BASIC NETWORK SNIFFER (WINDOWS)         ")
    print("="*60)
    print("[*] Starting Basic Network Sniffer...")
    print("[*] Monitoring network traffic... Press Ctrl+C to stop.\n")
    
    # Windows-এ Administrator প্রিভিলেজ ছাড়া রান করলে স্ক্রিপ্ট বন্ধ হয়ে যাবে
    try:
        # store=False দিলে মেমোরি কনজাম্পশন কম হয়, সরাসরি স্ক্রিনে প্রিন্ট হয়
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[!] Error: Access Denied! Please run Command Prompt as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


