import json
import math
import queue
import threading
import time
from datetime import datetime

from scapy.all import conf, get_if_list
from scapy.sendrecv import AsyncSniffer
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import DHCP

from packet_filter import get_packet_filter
from .history_bits import icd_to_bits, CounterState, OUTPUT_BITS

DHCP_PORTS = (67, 68)
MDNS_PORT = 5353
SSDP_PORT = 1900
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

class ICDExtractor:

    def __init__(
        self,
        iface=None,
        matcher=None,
        on_match=None,
        ignore_packet=None,
        matched_only_output=False,
        poi_mode="legacy",
        silent_interval_ms=None,
    ):
        self.iface = iface
        self._t0_perf_counter = None
        self._t0_capture_timestamp = None
        self.t0_wallclock = None
        self.records = []
        self.packet_count = 0
        self.captured_packet_count = 0
        self.matcher = matcher
        self.on_match = on_match
        self.ignore_packet = ignore_packet
        self.matched_only_output = matched_only_output
        if poi_mode not in ("legacy", "arp", "ssdp"):
            raise ValueError(f"Unsupported PoI mode: {poi_mode}")
        self.poi_mode = poi_mode
        if silent_interval_ms is not None and (
            not math.isfinite(float(silent_interval_ms))
            or float(silent_interval_ms) <= 0
        ):
            raise ValueError("silent_interval_ms must be a positive finite number")
        self.silent_interval_ms = (
            float(silent_interval_ms)
            if silent_interval_ms is not None
            else None
        )
        self._last_pointer_sent_perf_counter = None
        self.silent_interval_dropped_packets = []
        self._queue = queue.Queue()
        self._worker = None
        self._counter_state = CounterState()

    @staticmethod
    def _is_group_destination(mac):
        try:
            first_octet = int(mac.split(":", 1)[0], 16)
        except (AttributeError, ValueError):
            return False
        return bool(first_octet & 1)

    def _classify(self, pkt):
        if self.ignore_packet is not None and self.ignore_packet(pkt):
            return None

        if not pkt.haslayer(Ether):
            return None

        if self.poi_mode == "arp":
            return "ARP" if pkt.haslayer(ARP) else None

        if not self._is_group_destination(pkt[Ether].dst):
            return None

        if self.poi_mode == "ssdp":
            return "SSDP" if (
                pkt.haslayer(UDP) and pkt[UDP].dport == SSDP_PORT
            ) else None

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
        arrival_perf_counter = time.perf_counter()
        try:
            capture_timestamp = float(pkt.time)
            wallclock = datetime.fromtimestamp(capture_timestamp).isoformat(
                timespec="milliseconds"
            )
        except (AttributeError, TypeError, ValueError, OverflowError, OSError):
            capture_timestamp = None
            wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put((pkt, capture_timestamp, arrival_perf_counter, wallclock))

    def _process_loop(self):
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    break

                pkt, capture_timestamp, arrival_perf_counter, wallclock = item
                try:
                    proto = self._classify(pkt)
                    if proto is None:
                        continue
                    proto = str(proto)

                    if self._last_pointer_sent_perf_counter is not None:
                        delta_ms = (
                            arrival_perf_counter
                            - self._last_pointer_sent_perf_counter
                        ) * 1000
                        if 0 <= delta_ms < self.silent_interval_ms:
                            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                            dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
                            src_ip = (
                                pkt[IP].src if pkt.haslayer(IP)
                                else pkt[IPv6].src if pkt.haslayer(IPv6)
                                else None
                            )
                            self.silent_interval_dropped_packets.append({
                                "protocol": proto,
                                "src_ip": src_ip,
                                "src_mac": src_mac,
                                "dst_mac": dst_mac,
                                "timestamp": wallclock,
                                "delta_from_pointer_ms": round(delta_ms, 3),
                            })
                            print(
                                f"Silent interval ignored {proto} packet "
                                f"{delta_ms:.3f} ms after pointer "
                                f"(threshold {self.silent_interval_ms:g} ms).",
                                flush=True,
                            )
                            continue
                        if delta_ms >= self.silent_interval_ms:
                            self._last_pointer_sent_perf_counter = None

                    if self._t0_perf_counter is None:
                        self._t0_perf_counter = arrival_perf_counter
                        self._t0_capture_timestamp = capture_timestamp
                        self.t0_wallclock = wallclock
                        icd_ms = 0
                    elif (
                        self._t0_capture_timestamp is not None
                        and capture_timestamp is not None
                    ):
                        icd_ms = round(
                            (capture_timestamp - self._t0_capture_timestamp) * 1000,
                            3,
                        )
                    else:
                        icd_ms = round(
                            (arrival_perf_counter - self._t0_perf_counter) * 1000,
                            3,
                        )

                    self.packet_count += 1

                    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                    elif pkt.haslayer(IPv6):
                        src_ip = pkt[IPv6].src
                    else:
                        src_ip = None
                    bits = icd_to_bits(icd_ms, self._counter_state)

                    record = {
                        "packet_no": self.packet_count,
                        "protocol": proto,
                        "poi_mode": self.poi_mode,
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                        "src_ip": src_ip,
                        "timestamp": wallclock,
                        "icd_ms": icd_ms,
                        "rounded": bits["rounded"],
                        "counter": bits["counter"],
                    }
                    self.records.append(record)

                    attempt = None
                    if self.matcher is not None and not self.matcher.is_complete:
                        attempt = self.matcher.try_match(
                            packet_no=self.packet_count,
                            bit_value=bits["bit_value"],
                        )

                    if self.matched_only_output:
                        if attempt is not None and attempt["status"] == "matched":
                            window = (
                                f"{attempt['window_index'] + 1}/"
                                f"{len(self.matcher.windows)}"
                            )
                            print(
                                f"[{self.packet_count:04d}] MATCH "
                                f"window={window} counter={bits['counter']:02d} "
                                f"src_ip={src_ip or '-'} src_mac={src_mac or '-'}",
                                flush=True,
                            )
                    else:
                        print(
                            f"[{self.packet_count:04d}] {proto:<5} "
                            f"src={src_ip or src_mac or '?':<15} "
                            f"dst_mac={dst_mac or '?':<17} "
                            f"ICD={icd_ms} ms -> counter={bits['counter']:02d} "
                            f"-> bits={bits['bit_value']:0{OUTPUT_BITS}b}",
                            flush=True,
                        )

                    if attempt is not None:
                        if not self.matched_only_output:
                            window_display = (
                                f"{attempt['window_value']:0{attempt['window_width']}b}"
                            )
                            compared_display = (
                                f"{attempt['compared_value']:0{attempt['window_width']}b}"
                            )
                            print(
                                f"       -> window {attempt['window_index']:02d} "
                                f"[{window_display}] vs [{compared_display}] "
                                f"= {attempt['status'].upper()}",
                                flush=True,
                            )
                        if attempt["status"] == "matched":
                            self._counter_state.reset()
                        if (
                            attempt["status"] == "matched"
                            and self.on_match is not None
                        ):
                            try:
                                signal_attempt = {
                                    **attempt,
                                    "packet": record,
                                }
                                self.on_match(signal_attempt)
                                if self.silent_interval_ms is not None:
                                    self._last_pointer_sent_perf_counter = (
                                        time.perf_counter()
                                    )
                            except Exception as exc:
                                print(
                                    f"       -> pointer signal failed: {exc}",
                                    flush=True,
                                )
                except Exception as exc:
                    print(f"Packet processing failed: {exc}", flush=True)
            finally:
                self._queue.task_done()

    def start(self):
        if not self.matched_only_output:
            if self.iface is None:
                print("Sniffing on interface: Scapy default", flush=True)
            else:
                print(
                    f"Sniffing on interface: {describe_interface(self.iface)}",
                    flush=True,
                )
                print(f"Npcap capture ID: {self.iface}", flush=True)
            print(
                "PoI mode: "
                + {
                    "arp": "ARP only",
                    "ssdp": "SSDP only",
                    "legacy": "legacy (ARP/DHCP/mDNS/SSDP)",
                }[self.poi_mode],
                flush=True,
            )
            print(
                "Silent interval: "
                + (
                    f"{self.silent_interval_ms:g} ms"
                    if self.silent_interval_ms is not None
                    else "disabled"
                ),
                flush=True,
            )
            print(
                f"Capture filter: {get_packet_filter(self.poi_mode)}",
                flush=True,
            )
            if self.matcher is not None:
                print(f"Bit matching aktif: {len(self.matcher.windows)} window "
                      f"({self.matcher.window_size} bit/window) match.", flush=True)
                print("Sniffing til its done.", flush=True)
            print("Press Ctrl+C to stop and save results.\n", flush=True)

        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()

        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=get_packet_filter(self.poi_mode),
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
                if self.matcher is not None and self.matcher.is_complete:
                    break
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
                if not self.matched_only_output:
                    print(
                        f"Capture received {self.captured_packet_count} "
                        f"frame(s); "
                        f"{self.packet_count} were used for counters.",
                        flush=True,
                    )

    def save_json(self, filepath="history_results.json", verbose=True):
        output = {
            "interface": self.iface,
            "poi_mode": self.poi_mode,
            "silent_interval_ms": self.silent_interval_ms,
            "silent_interval_dropped_packets": (
                self.silent_interval_dropped_packets
            ),
            "poi_definition": {
                "arp": "all ARP packets",
                "ssdp": "group-destination SSDP packets only",
                "legacy": "group-destination ARP, DHCP, mDNS, and SSDP packets",
            }[self.poi_mode],
            "initialization_time": self.t0_wallclock,
            "total_packets": self.packet_count,
            "packets": self.records,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        if verbose:
            print(f"\nSaved {self.packet_count} record(s) to {filepath}")


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
