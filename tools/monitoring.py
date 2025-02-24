import logging
from collections import defaultdict
from colorama import Fore, Style
from datetime import datetime
from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, IP, TCP
from mac_vendor_lookup import MacLookup, VendorNotFoundError


class DnsListener:
    def __init__(self, interface: str=None, filter_src_ip: str=None, filter_dst_ip: str=None, output_pcap_file: str=None):
        self.interface = interface
        self.filter_src_ip = filter_src_ip
        self.filter_dst_ip = filter_dst_ip
        self.output_pcap_file = output_pcap_file
    
    def listen(self) -> None:
        if self.interface:
            sniff(iface=self.interface, prn=self.process_packet, filter="udp port 53 or tcp port 53", store=0)
    
    def process_packet(self, pkt) -> None:
        if self.filter_src_ip and IP in pkt and pkt[IP].src != self.filter_src_ip:
            return

        if self.filter_dst_ip and IP in pkt and pkt[IP].dst != self.filter_dst_ip:
            return

        pkt_dict = defaultdict(str)

        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Unknown"

        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')

        pkt_dict["timestamp"] = timestamp
        pkt_dict["src_ip"] = pkt[IP].src
        pkt_dict["src_mac"] = pkt.src
        pkt_dict["src_mac_vendor"] = self.get_mac_vendor(pkt.src)
        pkt_dict["dst_ip"] = pkt[IP].dst
        pkt_dict["dst_mac"] = pkt.dst
        pkt_dict["dst_mac_vendor"] = self.get_mac_vendor(pkt.dst)
        pkt_dict["packet_size"] = len(pkt)
        pkt_dict["ttl"] = pkt.ttl
        pkt_dict["ip_checksum"] = pkt[IP].chksum
        pkt_dict["protocol"] = protocol
        pkt_dict["protocol_id"] = pkt[IP].proto
        pkt_dict["dns_request"] = pkt[DNS].qd.qname.decode("UTF-8").strip(".")

        self.print_packet(pkt_dict)

        if self.output_pcap_file:
            wrpcap(self.output_pcap_file, pkt, append=True)
    
    def print_packet(self, packet: dict) -> None:
        for k, v in packet.items():
            k = k.replace("_", " ").replace("src", "source").replace("dst", "destination").upper()
            if k == "TIMESTAMP":
                print(f"{Fore.CYAN}{k}: {Style.RESET_ALL}{v}")
            elif k == "DNS REQUEST":
                print(f"{Fore.YELLOW}{k}: {Style.RESET_ALL}{v}")
            else:
                print(f"{Fore.GREEN}{k}: {Style.RESET_ALL}{v}")
        print("-" * 50)
    
    def save_output_pcap_file(self, pkt) -> None:
        try:
            wrpcap(self.output_pcap_file, pkt, append=True)
        except Exception as error:
            logging.exception(error)

    def get_mac_vendor(self, mac: str) -> str:
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = "unknown device"
        
        return vendor
