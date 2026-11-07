"""Sniff supported group-destination packets and derive receiver counter values."""

import queue
import threading
import time
import uuid
from datetime import datetime

from scapy.all import conf, get_if_list
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import AsyncSniffer

from .history_bits import ReceiverCounterState, next_counter_value
from .history_buffer import ReceiverHistoryStore
from .pointer_recognition import PointerRecognizer
from .secret_bits import ReceiverSecretBitsStore


DHCP_PORTS = (67, 68)
MDNS_PORT = 5353
SSDP_PORT = 1900
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
GROUP_DESTINATION_FILTER = "(ether broadcast or ether multicast)"
ARP_BROADCAST_FILTER = "(arp and ether broadcast)"
DHCP_FILTER = (
    "(udp and (port 67 or port 68) and "
    f"{GROUP_DESTINATION_FILTER})"
)
MDNS_FILTER = f"(udp and dst port {MDNS_PORT} and {GROUP_DESTINATION_FILTER})"
SSDP_FILTER = f"(udp and dst port {SSDP_PORT} and {GROUP_DESTINATION_FILTER})"
CAPTURE_FILTER = (
    f"({ARP_BROADCAST_FILTER} or {DHCP_FILTER} or "
    f"{MDNS_FILTER} or {SSDP_FILTER})"
)


def get_packet_filter():
    return CAPTURE_FILTER


def list_interfaces():
    return get_if_list()


def describe_interface(interface_name):
    """Describe an Npcap name using Scapy's Windows adapter metadata."""
    try:
        interface = conf.ifaces.dev_from_networkname(interface_name)
    except Exception:
        return "Adapter details unavailable"

    names = []
    for value in (interface.name, interface.description):
        if value and value != interface_name and value not in names:
            names.append(value)

    label = " / ".join(names) or "Windows network adapter"
    details = []
    addresses = list(getattr(interface, "ips", {}).get(4, []))
    if not addresses and getattr(interface, "ip", None):
        addresses = [interface.ip]
    if addresses:
        details.append("IPv4 " + ", ".join(addresses))

    mac = getattr(interface, "mac", None)
    if mac and mac != "00:00:00:00:00:00":
        details.append("MAC " + str(mac))
    if details:
        label += " (" + "; ".join(details) + ")"
    return label


class ReceiverHistoryExtractor:
    def __init__(
        self,
        iface,
        buffer_path,
        log_path,
        secret_bits_path,
        pointer_source_ip,
    ):
        self.iface = iface
        self.store = ReceiverHistoryStore(buffer_path, log_path)
        self.secret_bits_store = ReceiverSecretBitsStore(secret_bits_path)
        self.pointer_recognizer = PointerRecognizer(pointer_source_ip)
        self.session_id = uuid.uuid4().hex
        self.packet_count = 0
        self.captured_packet_count = 0
        self._counter_state = ReceiverCounterState()
        self._queue = queue.Queue()
        self._worker = None

    @staticmethod
    def _is_group_destination(mac):
        try:
            first_octet = int(mac.split(":", 1)[0], 16)
        except (AttributeError, ValueError):
            return False
        return bool(first_octet & 1)

    def _packet_addresses(self, pkt):
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
        else:
            src_ip = None
        return src_mac, dst_mac, src_ip

    def _classify(self, pkt):
        if not pkt.haslayer(Ether) or not self._is_group_destination(
            pkt[Ether].dst
        ):
            return None

        if pkt.haslayer(ARP):
            return "ARP" if pkt[Ether].dst.lower() == BROADCAST_MAC else None

        if pkt.haslayer(DHCP) and pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if sport in DHCP_PORTS or dport in DHCP_PORTS:
                return "DHCP"

        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            if dport == MDNS_PORT:
                return "mDNS"
            if dport == SSDP_PORT:
                return "SSDP"
        return None

    def _on_sniff_packet(self, pkt):
        self.captured_packet_count += 1
        try:
            capture_timestamp = float(pkt.time)
            wallclock = datetime.fromtimestamp(capture_timestamp).isoformat(
                timespec="milliseconds"
            )
        except (AttributeError, TypeError, ValueError, OverflowError, OSError):
            wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put((pkt, wallclock))

    def _process_loop(self):
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    break

                pkt, wallclock = item
                try:
                    pointer_record = self.pointer_recognizer.recognize(pkt)
                    if pointer_record is not None:
                        pointer_record["timestamp"] = wallclock
                        self._counter_state.reset()
                        history_record = self.store.latest
                        pointer_event = self.secret_bits_store.record_pointer(
                            pointer_record,
                            history_record,
                        )
                        self.store.append_event({
                            "event_type": "pointer",
                            "session_id": self.session_id,
                            "protocol": "mDNS",
                            "timestamp": wallclock,
                            **pointer_record,
                            "pointer_no": pointer_event["pointer_no"],
                            "status": pointer_event["status"],
                            "counter": pointer_event.get("counter"),
                            "counter_bits": pointer_event.get("bits"),
                        })
                        if history_record is not None:
                            self.store.pop_latest()
                        print(
                            f"Pointer from "
                            f"{pointer_record['src_ip'] or pointer_record['src_mac'] or '?'} "
                            f"status={pointer_event['status']}; "
                            f"bits={pointer_event.get('bits', '')}; "
                            f"secret length="
                            f"{self.secret_bits_store.data['bit_length']} bits.",
                            flush=True,
                        )
                        continue

                    proto = self._classify(pkt)
                    if proto is None:
                        continue

                    self.packet_count += 1
                    src_mac, dst_mac, src_ip = self._packet_addresses(pkt)

                    counter_value = next_counter_value(self._counter_state)
                    record = {
                        "session_id": self.session_id,
                        "packet_no": self.packet_count,
                        "protocol": str(proto),
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                        "src_ip": src_ip,
                        "timestamp": wallclock,
                        **counter_value,
                    }
                    self.store.add(record)
                    print(
                        f"[{self.packet_count:04d}] {proto:<5} "
                        f"src={src_ip or src_mac or '?':<15} "
                        f"counter={record['counter']:02d} "
                        f"-> bits={record['counter_bits']} "
                        f"(buffer {len(self.store.newest_first)}/"
                        f"{self.store.capacity})",
                        flush=True,
                    )
                except Exception as exc:
                    print(f"Packet processing failed: {exc}", flush=True)
            finally:
                self._queue.task_done()

    def start(self):
        if self.iface is None:
            print("Sniffing on interface: Scapy default", flush=True)
        else:
            print(
                f"Sniffing on interface: {describe_interface(self.iface)}",
                flush=True,
            )
            print(f"Npcap capture ID: {self.iface}", flush=True)
        print(
            "Listening only for group-destination ARP, DHCP, mDNS, and SSDP.",
            flush=True,
        )
        print(f"Capture filter: {get_packet_filter()}", flush=True)
        print(
            f"Pointer source IPv4: {self.pointer_recognizer.sender_ip}",
            flush=True,
        )
        print(
            "Extracting counter-based values; keeping the latest "
            f"{self.store.capacity} in the receiver buffer.",
            flush=True,
        )
        print("Press Ctrl+C to stop sniffing.\n", flush=True)

        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=get_packet_filter(),
            prn=self._on_sniff_packet,
            store=False,
            started_callback=started.set,
        )
        sniffer_started = False
        try:
            sniffer.start()
            sniffer_started = True
            if not started.wait(timeout=5):
                raise RuntimeError("Scapy sniffer did not start within 5 seconds.")
            while sniffer.running:
                time.sleep(0.1)
        finally:
            try:
                if sniffer_started:
                    if sniffer.running:
                        sniffer.stop()
                    else:
                        sniffer.join()
            finally:
                self._queue.put(None)
                self._queue.join()
                self._worker.join()

            print(
                f"Capture received {self.captured_packet_count} "
                f"broadcast/multicast frame(s); "
                f"{self.packet_count} produced counter values.",
                flush=True,
            )
            print(f"Latest buffer: {self.store.buffer_path}", flush=True)
            print(f"Append-only log: {self.store.log_path}", flush=True)
            print(
                f"Secret bits: {self.secret_bits_store.filepath}",
                flush=True,
            )

