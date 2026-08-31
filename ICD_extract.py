
import json
import time
from datetime import datetime

from scapy.all import sniff, get_if_list, conf
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP

DHCP_PORTS = (67, 68)
MDNS_PORT = 5353
SSDP_PORT = 1900

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"


class ICDExtractor:

    def __init__(self, iface=None):
        self.iface = iface
        self.t0 = None               
        self.t0_wallclock = None     
        self.records = []            
        self.packet_count = 0

    def _classify(self, pkt):
        is_l2_broadcast = pkt.haslayer(Ether) and pkt[Ether].dst == BROADCAST_MAC

        if pkt.haslayer(ARP):
            if is_l2_broadcast:
                return "ARP"
            return None

        if pkt.haslayer(DHCP) and pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if sport in DHCP_PORTS or dport in DHCP_PORTS:
                dst_ip_bcast = pkt.haslayer(IP) and pkt[IP].dst == BROADCAST_IP
                if is_l2_broadcast or dst_ip_bcast:
                    return "DHCP"
            return None
        
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            if dport == MDNS_PORT and is_l2_broadcast:
                return "mDNS"
            if dport == SSDP_PORT and is_l2_broadcast:
                return "SSDP"

        return None

    def _handle_packet(self, pkt):
        proto = self._classify(pkt)
        if proto is None:
            return 

        arrival = time.perf_counter()
        wallclock = datetime.now().isoformat(timespec="milliseconds")

        if self.t0 is None:
            self.t0 = arrival
            self.t0_wallclock = wallclock
            icd_ms = 0
        else:
            icd_ms = round((arrival - self.t0) * 1000, 3)

        self.packet_count += 1

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        src_ip = pkt[IP].src if pkt.haslayer(IP) else None

        record = {
            "packet_no": self.packet_count,
            "protocol": proto,
            "src_mac": src_mac,
            "src_ip": src_ip,
            "timestamp": wallclock,
            "icd_ms": icd_ms,
        }
        self.records.append(record)

        print(f"[{self.packet_count:04d}] {proto:<5} "
              f"src={src_ip or src_mac or '?':<15} "
              f"ICD={icd_ms} ms")

    def start(self):
        print(f"Sniffing on interface: {self.iface or '(scapy default)'}")
        print("Listening for broadcast packets.")
        print("Press Ctrl+C to stop and save results.\n")

        sniff(
            iface=self.iface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _pkt: False,
        )

    def save_json(self, filepath="icd_results.json"):
        output = {
            "interface": self.iface,
            "initialization_time": self.t0_wallclock,
            "total_packets": self.packet_count,
            "packets": self.records,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"\nSaved {self.packet_count} record(s) to {filepath}")


def list_interfaces():
    return get_if_list()