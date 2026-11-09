"""Sniff supported group-destination packets and derive receiver counter values."""

import queue
import threading
import time
import uuid
import math
from collections import deque
from datetime import datetime

from scapy.all import conf, get_if_list
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import AsyncSniffer

from .history_bits import (
    ReceiverCounterState,
    next_counter_value,
    next_periodic_counter_value,
)
from .history_buffer import ReceiverHistoryStore
from .pointer_recognition import PointerRecognizer
from .secret_bits import ReceiverSecretBitsStore
from engine.periodic_counter import (
    PERIODIC_COUNTER_INTERVAL_SECONDS,
    PeriodicCounterState,
)


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
POINTER_FILTER = f"(udp and dst port {MDNS_PORT} and dst host 224.0.0.251)"


def get_packet_filter(poi_mode="legacy"):
    if poi_mode == "legacy":
        return CAPTURE_FILTER
    if poi_mode == "arp":
        # Keep mDNS available for pointer recognition, but exclude it from
        # history counters in _classify().
        return f"(arp or {MDNS_FILTER})"
    if poi_mode == "ssdp":
        # Keep mDNS available for pointer recognition, but use only SSDP for
        # history counters in _classify().
        return f"({SSDP_FILTER} or {MDNS_FILTER})"
    raise ValueError(f"Unsupported PoI mode: {poi_mode}")


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
        poi_mode="legacy",
        silent_interval_ms=None,
        counter_mode="packet",
    ):
        self.iface = iface
        if counter_mode not in ("packet", "periodic"):
            raise ValueError(f"Unsupported counter mode: {counter_mode}")
        self.counter_mode = counter_mode
        if counter_mode == "periodic" and silent_interval_ms is not None:
            raise ValueError("silent interval is not available in periodic mode")
        self.store = ReceiverHistoryStore(
            buffer_path, log_path, counter_mode=counter_mode
        )
        self.secret_bits_store = ReceiverSecretBitsStore(secret_bits_path)
        self.pointer_recognizer = PointerRecognizer(pointer_source_ip)
        if counter_mode == "packet" and poi_mode not in ("legacy", "arp", "ssdp"):
            raise ValueError(f"Unsupported PoI mode: {poi_mode}")
        self.poi_mode = poi_mode if counter_mode == "packet" else None
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
        self.session_id = uuid.uuid4().hex
        self.packet_count = 0
        self.captured_packet_count = 0
        self.silent_interval_dropped_packets = 0
        self._pending_history_packets = deque()
        self._counter_state = (
            PeriodicCounterState()
            if counter_mode == "periodic"
            else ReceiverCounterState()
        )
        self._next_periodic_tick = None
        self._sample_no = 0
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
            wallclock = datetime.now().isoformat(timespec="milliseconds")
        self._queue.put((pkt, wallclock, arrival_perf_counter))

    def _record_history_packet(self, pkt, wallclock, proto):
        self.packet_count += 1
        src_mac, dst_mac, src_ip = self._packet_addresses(pkt)
        counter_value = next_counter_value(self._counter_state)
        record = {
            "session_id": self.session_id,
            "packet_no": self.packet_count,
            "counter_mode": "packet",
            "protocol": str(proto),
            "poi_mode": self.poi_mode,
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

    def _record_periodic_value(self):
        self._sample_no += 1
        self.packet_count += 1
        counter_value = next_periodic_counter_value(self._counter_state)
        record = {
            "session_id": self.session_id,
            "sample_no": self._sample_no,
            "protocol": "PERIODIC",
            "counter_mode": "periodic",
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            **counter_value,
        }
        self.store.add(record)
        print(
            f"[{self._sample_no:04d}] PERIODIC counter={record['counter']:02d} "
            f"-> bits={record['counter_bits']} "
            f"(buffer {len(self.store.newest_first)}/"
            f"{self.store.capacity})",
            flush=True,
        )

    def _emit_due_periodic_values(self, now_perf_counter):
        while (
            self.counter_mode == "periodic"
            and self._next_periodic_tick is not None
            and now_perf_counter >= self._next_periodic_tick
        ):
            next_tick = (
                self._next_periodic_tick + PERIODIC_COUNTER_INTERVAL_SECONDS
            )
            self._record_periodic_value()
            self._next_periodic_tick = max(
                next_tick,
                time.perf_counter() + PERIODIC_COUNTER_INTERVAL_SECONDS,
            )

    def _record_silent_interval_drop(
        self,
        pkt,
        wallclock,
        proto,
        delta_ms,
        relation,
    ):
        src_mac, dst_mac, src_ip = self._packet_addresses(pkt)
        event = {
            "event_type": "silent_interval_drop",
            "session_id": self.session_id,
            "protocol": str(proto),
            "poi_mode": self.poi_mode,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "timestamp": wallclock,
            "relation_to_pointer": relation,
            "delta_ms": round(delta_ms, 3),
            "threshold_ms": self.silent_interval_ms,
        }
        self.store.append_event(event)
        self.silent_interval_dropped_packets += 1
        print(
            f"Silent interval ignored {proto} packet "
            f"{delta_ms:.3f} ms {relation} pointer "
            f"(threshold {self.silent_interval_ms:g} ms).",
            flush=True,
        )

    def _flush_expired_history_packets(self, now_perf_counter):
        if self.silent_interval_ms is None:
            return
        while self._pending_history_packets:
            pending = self._pending_history_packets[0]
            age_ms = (
                now_perf_counter - pending["arrival_perf_counter"]
            ) * 1000
            if age_ms < self.silent_interval_ms:
                break
            self._pending_history_packets.popleft()
            self._record_history_packet(
                pending["packet"],
                pending["wallclock"],
                pending["protocol"],
            )

    def _resolve_pending_before_pointer(self, pointer_arrival_perf_counter):
        while self._pending_history_packets:
            pending = self._pending_history_packets.popleft()
            delta_ms = (
                pointer_arrival_perf_counter
                - pending["arrival_perf_counter"]
            ) * 1000
            if 0 <= delta_ms < self.silent_interval_ms:
                self._record_silent_interval_drop(
                    pending["packet"],
                    pending["wallclock"],
                    pending["protocol"],
                    delta_ms,
                    "before",
                )
            else:
                self._record_history_packet(
                    pending["packet"],
                    pending["wallclock"],
                    pending["protocol"],
                )

    def _process_loop(self):
        while True:
            timeout = None
            if self.counter_mode == "periodic":
                timeout = max(
                    0.0,
                    self._next_periodic_tick - time.perf_counter(),
                )
            elif self.silent_interval_ms is not None:
                timeout = 0.01
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                now = time.perf_counter()
                if self.counter_mode == "periodic":
                    self._emit_due_periodic_values(now)
                else:
                    self._flush_expired_history_packets(now)
                continue
            try:
                if item is None:
                    while self._pending_history_packets:
                        pending = self._pending_history_packets.popleft()
                        self._record_history_packet(
                            pending["packet"],
                            pending["wallclock"],
                            pending["protocol"],
                        )
                    break

                pkt, wallclock, arrival_perf_counter = item
                try:
                    self._flush_expired_history_packets(arrival_perf_counter)
                    self._emit_due_periodic_values(arrival_perf_counter)
                    pointer_record = self.pointer_recognizer.recognize(pkt)
                    if pointer_record is not None:
                        if self.silent_interval_ms is not None:
                            self._resolve_pending_before_pointer(
                                arrival_perf_counter
                            )
                        pointer_record["timestamp"] = wallclock
                        self._counter_state.reset()
                        if self.counter_mode == "periodic":
                            self._next_periodic_tick = (
                                arrival_perf_counter
                                + PERIODIC_COUNTER_INTERVAL_SECONDS
                            )
                        buffer_snapshot = self.store.newest_first
                        history_record = self.store.latest
                        pointer_event = self.secret_bits_store.record_pointer(
                            pointer_record,
                            history_record,
                            buffer_snapshot=buffer_snapshot,
                        )
                        self.store.append_event({
                            "event_type": "pointer",
                            "session_id": self.session_id,
                            "protocol": "mDNS",
                            "timestamp": wallclock,
                            **pointer_record,
                            "buffer_before_pop": buffer_snapshot,
                            "selected_record": history_record,
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

                    if self.counter_mode == "periodic":
                        continue

                    proto = self._classify(pkt)
                    if proto is None:
                        continue

                    if self.silent_interval_ms is not None:
                        self._pending_history_packets.append({
                            "packet": pkt,
                            "wallclock": wallclock,
                            "arrival_perf_counter": arrival_perf_counter,
                            "protocol": proto,
                        })
                    else:
                        self._record_history_packet(pkt, wallclock, proto)
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
        if self.counter_mode == "periodic":
            capture_filter = POINTER_FILTER
            print(
                "Counter mode: periodic, packet independent "
                f"(interval {PERIODIC_COUNTER_INTERVAL_SECONDS:g} seconds).",
                flush=True,
            )
            print("PoI mode: not used", flush=True)
        else:
            capture_filter = get_packet_filter(self.poi_mode)
            print(
                "PoI mode: "
                + {
                    "arp": "ARP only",
                    "ssdp": "SSDP only",
                    "legacy": "legacy (ARP/DHCP/mDNS/SSDP)",
                }[self.poi_mode],
                flush=True,
            )
        print(f"Capture filter: {capture_filter}", flush=True)
        print(
            f"Pointer source IPv4: {self.pointer_recognizer.sender_ip}",
            flush=True,
        )
        if self.counter_mode == "packet":
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
            "Extracting counter-based values; keeping the latest "
            f"{self.store.capacity} in the receiver buffer.",
            flush=True,
        )
        print("Press Ctrl+C to stop sniffing.\n", flush=True)

        if self.counter_mode == "periodic":
            self._next_periodic_tick = time.perf_counter()
        self._worker = threading.Thread(target=self._process_loop, daemon=True)
        self._worker.start()
        started = threading.Event()
        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=capture_filter,
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
                f"frame(s); "
                f"{self.packet_count} produced counter values.",
                flush=True,
            )
            if self.counter_mode == "packet":
                print(
                    "Packets ignored by silent interval: "
                    f"{self.silent_interval_dropped_packets}",
                    flush=True,
                )
            print(f"Latest buffer: {self.store.buffer_path}", flush=True)
            print(f"Append-only log: {self.store.log_path}", flush=True)
            print(
                f"Secret bits: {self.secret_bits_store.filepath}",
                flush=True,
            )

