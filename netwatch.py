import argparse
from tools.monitoring import DnsListener
from tools.spoofing import ArpSpoofer, arp_scan


def create_parser() -> None:
    parser = argparse.ArgumentParser(description="A command-line interface for network monitoring tools")
    subparsers = parser.add_subparsers(dest="service", help="Choose a service")
    
    dns_listener_parser = subparsers.add_parser("dns-listener", help="DNS Listener, a network packet sniffer")
    dns_listener_parser.add_argument("-iface", "--interface", help="Interface to listen on")
    dns_listener_parser.add_argument("-s", "--filter-src-ip", help="Filter by source IP address")
    dns_listener_parser.add_argument("-d", "--filter-dst-ip", help="Filter by destination IP address")
    dns_listener_parser.add_argument("--output-pcap-file", help="Save captured packets to a pcap file")

    arp_spoofer_parser = subparsers.add_parser("arp-spoofer", help="ARP Spoofer, a tool to sniff network traffic on a select device")
    arp_spoofer_parser.add_argument("-iface", "--interface", help="Interface to listen on")
    arp_spoofer_parser.add_argument("-g", "--gateway-ip", help="IP address of the gateway")
    arp_spoofer_parser.add_argument("-t", "--target-ip", help="IP address of the target")
    
    return parser

if __name__ == "__main__":

    parser = create_parser()
    args = parser.parse_args()

    if args.service == "dns-listener":
        dns_listener = DnsListener(interface=args.interface, filter_src_ip=args.filter_src_ip, filter_dst_ip=args.filter_dst_ip,
                               output_pcap_file=args.output_pcap_file)
        dns_listener.listen()
    elif args.service == "arp-spoofer":
        if not args.target_ip:
            network = args.gateway_ip[:args.gateway_ip.rfind('.') + 1] + "0/24"
            target_ip = arp_scan(network, args.interface)
        else:
            target_ip = args.target_ip
        spoofer = ArpSpoofer(interface=args.interface, gateway_ip=args.gateway_ip, target_ip=target_ip)
        spoofer.watch()
