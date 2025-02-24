import argparse
from tools.monitoring import DnsListener

def main():
    # TODO: create a menu to select service i.e. listerner, arp, packet analysis etc...
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS network packet sniffer")
    parser.add_argument("-iface", "--interface", help="Interface to listen on")
    parser.add_argument("-s", "--filter-src-ip", help="Filter by source IP address")
    parser.add_argument("-d", "--filter-dst-ip", help="Filter by destination IP address")
    parser.add_argument("--output-pcap-file", help="Save captured packets to a pcap file")
    args = parser.parse_args()

    dns_listener = DnsListener(interface=args.interface, filter_src_ip=args.filter_src_ip, filter_dst_ip=args.filter_dst_ip,
                               output_pcap_file=args.output_pcap_file)
    dns_listener.listen()
