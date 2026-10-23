
from collections import Counter
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS

def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    results = []
    protocol_counts = Counter()
    total_bytes = 0

    for packet_number, packet in enumerate(packets, start=1):
        timestamp = float(packet.time)
        size = len(packet)
        total_bytes += size

        source_ip = "N/A"
        destination_ip = "N/A"
        source_port = "N/A"
        destination_port = "N/A"

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "DNS" if DNS in packet else "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        elif DNS in packet:
            protocol = "DNS"
        elif IPv6 in packet:
            protocol = "IPv6"
        elif IP in packet:
            protocol = "IP"
        else:
            protocol = packet.lastlayer().name

        protocol_counts[protocol] += 1

        results.append({
            "number": packet_number,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "size_bytes": size
        })

    return results, protocol_counts, total_bytes


if __name__ == "__main__":
    file_path = "captures/dns.cap"

    try:
        packets, protocol_counts, total_bytes = analyze_pcap(file_path)

        print("\n=== NETWORK PACKET ANALYZER ===")
        print(f"Total packets: {len(packets)}")
        print(f"Total captured bytes: {total_bytes}")

        print("\n=== PROTOCOL DISTRIBUTION ===")
        for protocol, count in protocol_counts.most_common():
            print(f"{protocol}: {count} packets")

        print("\n=== FIRST 10 PACKETS ===")
        for packet in packets[:10]:
            print(
                f"#{packet['number']} | "
                f"{packet['source_ip']} -> "
                f"{packet['destination_ip']} | "
                f"{packet['protocol']} | "
                f"{packet['size_bytes']} bytes"
            )

    except FileNotFoundError:
        print(f"Capture file not found: {file_path}")
        print("Download the sample capture into the captures folder.")
    except Exception as error:
        print(f"Analysis failed: {error}")
