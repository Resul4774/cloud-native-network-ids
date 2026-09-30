import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ICMP
from prometheus_client import start_http_server, Counter

PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 10
ICMP_FLOOD_THRESHOLD = 50
ICMP_FLOOD_WINDOW = 5

SUSPICIOUS_PORT_SCAN = Counter('ids_port_scan_alerts_total', 'Total detected port scan attempts', ['src_ip'])
ICMP_FLOOD = Counter('ids_icmp_flood_alerts_total', 'Total detected ICMP flood attempts', ['src_ip'])
UNAUTHORIZED_SSH = Counter('ids_unauthorized_ssh_alerts_total', 'Total detected unauthorized SSH connection attempts', ['src_ip', 'dst_ip'])
TOTAL_PACKETS = Counter('ids_packets_processed_total', 'Total processed network packets', ['protocol'])

port_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)

def cleanup_tracker(tracker, window, now):
    for ip in list(tracker.keys()):
        tracker[ip] = [t for t in tracker[ip] if now - t <= window]
        if not tracker[ip]:
            del tracker[ip]

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    now = time.time()

    if packet.haslayer(TCP):
        TOTAL_PACKETS.labels(protocol='TCP').inc()
        dst_port = packet[TCP].dport

        if dst_port == 22 and packet[TCP].flags == 'S':
            UNAUTHORIZED_SSH.labels(src_ip=src_ip, dst_ip=dst_ip).inc()

        # Burası düzeltildi: Sadece zaman damgasını takip ediyoruz
        port_tracker[src_ip].append(now)
        cleanup_tracker(port_tracker, PORT_SCAN_WINDOW, now)
        
        # Burası düzeltildi: Port yerine tetiklenme sayısını kontrol ediyoruz
        if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            SUSPICIOUS_PORT_SCAN.labels(src_ip=src_ip).inc()
            port_tracker[src_ip].clear()

    elif packet.haslayer(ICMP):
        TOTAL_PACKETS.labels(protocol='ICMP').inc()
        icmp_tracker[src_ip].append(now)
        cleanup_tracker(icmp_tracker, ICMP_FLOOD_WINDOW, now)
        if len(icmp_tracker[src_ip]) >= ICMP_FLOOD_THRESHOLD:
            ICMP_FLOOD.labels(src_ip=src_ip).inc()
            icmp_tracker[src_ip].clear()

    else:
        TOTAL_PACKETS.labels(protocol='OTHER').inc()

def main():
    start_http_server(8000)
    sniff(prn=analyze_packet, store=False)

if __name__ == '__main__':
    main()
