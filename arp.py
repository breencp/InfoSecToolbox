from scapy.utils import rdpcap
from scapy.layers.l2 import ARP, Ether


def find_unicast_arp_requests(pcap_file):
    """
    Analyze a pcap file to find unicast ARP requests and print details of offending devices.

    Args:
        pcap_file (str): Path to the pcap file containing ARP traffic.

    Returns:
        None
    """
    try:
        # Read packets from the pcap file
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: File not found - {pcap_file}")
        return
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    print(f"Analyzing ARP packets in {pcap_file}...\n")
    unicast_arp_count = 0

    for pkt in packets:
        # Filter ARP packets and check for ARP requests (op == 1)
        if ARP in pkt and pkt[ARP].op == 1:  # ARP Request
            src_mac = pkt[ARP].hwsrc        # Source MAC
            src_ip = pkt[ARP].psrc          # Source IP
            dst_mac = pkt[Ether].dst        # Destination MAC
            dst_ip = pkt[ARP].pdst          # Target IP

            # Check if the ARP request is unicast (not broadcast)
            if dst_mac.lower() != "ff:ff:ff:ff:ff:ff":
                unicast_arp_count += 1
                print(f"Unicast ARP Request Detected:")
                print(f"  Source MAC: {src_mac}")
                print(f"  Source IP: {src_ip}")
                print(f"  Destination MAC: {dst_mac}")
                print(f"  Target IP: {dst_ip}")
                print(f"  Packet Summary: {pkt.summary()}\n")

    if unicast_arp_count == 0:
        print("No unicast ARP requests found.")
    else:
        print(f"Total unicast ARP requests found: {unicast_arp_count}")


def gratuitous_arp(dnsmasq_leases, pcap, static_ips):
    """
    Compare ARP packets in a pcap file against the dnsmasq leases file for discrepancies.

    Args:
        dnsmasq_leases (str): Path to the dnsmasq leases file.
            /var/lib/misc/dnsmasq.leases
        pcap (str): Path to the pcap file containing ARP packets.
            sudo tcpdump -i eth0 arp and arp[6:2] == 2 -n -vv -w arp_replies.pcap
        static_ips (str): Path to the file containing static IP-MAC mappings.
            Format: "IP MAC". Self-made file.

    Returns:
        None: Prints the discrepancies found.
    """

    # Load DHCP leases into a dictionary (MAC -> IP)
    dhcp_table = {}
    try:
        with open(dnsmasq_leases, "r") as leases_file:
            for line in leases_file:
                parts = line.split()
                if len(parts) >= 3:
                    mac = parts[1].lower()  # Normalize MAC address
                    ip = parts[2]           # IP address
                    dhcp_table[mac] = ip
    except FileNotFoundError:
        print(f"Error: File not found - {dnsmasq_leases}")
        return
    except Exception as e:
        print(f"Error reading dnsmasq leases: {e}")
        return

    # Load static IP mappings into the same dictionary
    try:
        with open(static_ips, "r") as static_file:
            for line in static_file:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]           # Static IP
                    mac = parts[1].lower()  # Normalize MAC address
                    dhcp_table[mac] = ip
    except FileNotFoundError:
        print(f"Error: File not found - {static_ips}")
        return
    except Exception as e:
        print(f"Error reading static IP mappings: {e}")
        return

    # Read ARP packets from the pcap file
    try:
        packets = rdpcap(pcap)
    except FileNotFoundError:
        print(f"Error: File not found - {pcap}")
        return
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    # Process ARP packets and check for discrepancies
    print("Checking ARP packets for discrepancies...")
    discrepancies_found = False
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:  # ARP Reply (is-at)
            arp_mac = pkt[ARP].hwsrc.lower()  # Source MAC
            arp_ip = pkt[ARP].psrc           # Source IP

            # Compare against the combined DHCP and static IP table
            if arp_mac in dhcp_table:
                if dhcp_table[arp_mac] != arp_ip:
                    print(f"Discrepancy: MAC {arp_mac} claims IP {arp_ip}, "
                          f"expected {dhcp_table[arp_mac]}")
                    discrepancies_found = True
            else:
                print(f"Unknown MAC {arp_mac} claims IP {arp_ip}")
                discrepancies_found = True

    if not discrepancies_found:
        print("No discrepancies found. All ARP activity matches the DHCP table.")


if __name__ == '__main__':
    # gratuitous_arp("working_files/dnsmasq.leases", "working_files/arp_replies.pcap", "working_files/static_ips.txt")
    find_unicast_arp_requests("working_files/arp_traffic.pcap")
