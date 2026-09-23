import json
import queue
import threading
import time
from datetime import datetime

from scapy.all import sniff, get_if_list, conf
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP

from icd_bits import icd_to_bits, CounterState

DHCP_PORTS = (67, 68)
MDNS_PORT = 5353
SSDP_PORT = 1900

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"

BPF_FILTER = (
    "(arp and ether dst ff:ff:ff:ff:ff:ff) or "
    "(udp and (port 67 or port 68) and "
    "(ether dst ff:ff:ff:ff:ff:ff or ip dst 255.255.255.255)) or "
    "(udp and dst port 5353 and ether dst ff:ff:ff:ff:ff:ff) or "
    "(udp and dst port 1900 and ether dst ff:ff:ff:ff:ff:ff)"
)


class ICDExtractor:

    def __init__(self, iface=None, matcher=None):
        self.iface = iface
        self.t0 = None
        self.t0_wallclock = None
        self.records = []
        self.packet_count = 0
        self.matcher = matcher
        self._queue = queue.Queue()
        self._worker = None
        self._counter_state = CounterState()

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

    def _on_sniff_packet(self, pkt):
        arrival = time.perf_counter()
        wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put((pkt, arrival, wallclock))

    def _process_loop(self):
        while True:
            item = self._queue.get()
            if item is None:  
                self._queue.task_done()
                break

            pkt, arrival, wallclock = item
            proto = self._classify(pkt)
            if proto is None:
                self._queue.task_done()
                continue

            if self.t0 is None:
                self.t0 = arrival
                self.t0_wallclock = wallclock
                icd_ms = 0
            else:
                icd_ms = round((arrival - self.t0) * 1000, 3)

            self.packet_count += 1

            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
            src_ip = pkt[IP].src if pkt.haslayer(IP) else None

            bits = icd_to_bits(icd_ms, self._counter_state)

            record = {
                "packet_no": self.packet_count,
                "protocol": proto,
                "src_mac": src_mac,
                "src_ip": src_ip,
                "timestamp": wallclock,
                "icd_ms": icd_ms,
                "rounded": bits["rounded"],
                "icd_counter_added": bits["icd_counter_added"],
            }
            self.records.append(record)

            print(f"[{self.packet_count:04d}] {proto:<5} "
                  f"src={src_ip or src_mac or '?':<15} "
                  f"ICD={icd_ms} ms -> rounded+counter="
                  f"{bits['icd_counter_added']}")

            if self.matcher is not None and not self.matcher.is_complete:
                attempt = self.matcher.try_match(
                    packet_no=self.packet_count,
                    bit_string=bits["bit_string"],
                )
                print(f"       -> window {attempt['window_index']:02d} "
                      f"[{attempt['window_bits']}] vs [{attempt['compared_bits']}] "
                      f"= {attempt['status'].upper()}")

            self._queue.task_done()

    def start(self):
        print(f"Sniffing on interface: {self.iface or '(scapy default)'}")
        print("Listening for broadcast packets.")
        if self.matcher is not None:
            print(f"Bit matching aktif: {len(self.matcher.windows)} window "
                  f"({self.matcher.window_size} bit/window) match.")
            print("Sniffing til its done.")
        print("Press Ctrl+C to stop and save results.\n")

        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()

        try:
            sniff(
                iface=self.iface,
                filter=BPF_FILTER,
                prn=self._on_sniff_packet,
                store=False,
                stop_filter=lambda _pkt: (
                    self.matcher is not None and self.matcher.is_complete
                ),
            )
        finally:
            self._queue.join()
            self._queue.put(None)
            self._worker.join()

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