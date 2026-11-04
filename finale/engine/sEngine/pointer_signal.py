import json
import uuid
from datetime import datetime
from pathlib import Path

from scapy.all import conf, get_if_addr, get_if_hwaddr, sendp
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


MDNS_GROUP_IP = "224.0.0.251"
MDNS_GROUP_MAC = "01:00:5e:00:00:fb"
MDNS_PORT = 5353
SIGNAL_SIGNATURE = "app=hcc-pointer-v1"
MESSAGE_CHUNK_SIZE = 200
SIGNAL_LOG_FILE = (
    Path(__file__).resolve().parents[3]
    / "engineDump"
    / "pointer_signals.json"
)


class PointerSignalSender:

    def __init__(
        self,
        iface=None,
        message_bits="",
        output_file=SIGNAL_LOG_FILE,
        report_status=True,
    ):
        if not message_bits or any(bit not in "01" for bit in message_bits):
            raise ValueError("message_bits must be a non-empty binary string")

        self.iface = iface if iface is not None else conf.iface
        self.message_bits = message_bits
        self.report_status = report_status
        self.session_id = uuid.uuid4().hex[:12]
        self.source_ip = get_if_addr(self.iface)
        self.source_mac = get_if_hwaddr(self.iface)
        self.output_file = Path(output_file)

        if self.source_ip == "0.0.0.0":
            raise RuntimeError(
                f"Interface {self.iface!r} has no usable IPv4 address; "
                "cannot send an mDNS pointer signal."
            )

    def _message_chunks(self):
        return [
            self.message_bits[start : start + MESSAGE_CHUNK_SIZE]
            for start in range(0, len(self.message_bits), MESSAGE_CHUNK_SIZE)
        ]

    def _build_packet(self, attempt, event_id):
        packet_no = attempt["packet_no"]
        window_index = attempt["window_index"]
        window_width = attempt["window_width"]
        window_bits = f"{attempt['window_value']:0{window_width}b}"
        packet_bits = f"{attempt['packet_bit_value']:04b}"
        compared_bits = f"{attempt['compared_value']:0{window_width}b}"

        txt_fields = [
            SIGNAL_SIGNATURE,
            f"event_id={event_id}",
            f"packet_no={packet_no}",
            f"window_index={window_index}",
            f"window_bits={window_bits}",
            f"packet_bits={packet_bits}",
            f"compared_bits={compared_bits}",
            f"message_bit_length={len(self.message_bits)}",
        ]
        txt_fields.extend(
            f"message_bits_{index:03d}={chunk}"
            for index, chunk in enumerate(self._message_chunks())
        )

        instance_name = f"{event_id}._hcc-pointer._udp.local."
        answer = DNSRR(
            rrname=instance_name,
            type="TXT",
            cacheflush=1,
            ttl=120,
            rdata=[field.encode("ascii") for field in txt_fields],
        )
        return (
            Ether(src=self.source_mac, dst=MDNS_GROUP_MAC)
            / IP(src=self.source_ip, dst=MDNS_GROUP_IP, ttl=255)
            / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
            / DNS(id=0, qr=1, aa=1, ancount=1, an=answer)
        )

    def _append_record(self, record):
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        if self.output_file.exists():
            with self.output_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("signals", []) if isinstance(data, dict) else []
        else:
            records = []

        records.append(record)
        with self.output_file.open("w", encoding="utf-8") as f:
            json.dump({"signals": records}, f, indent=2)

    def send_for_match(self, attempt):
        """Send one multicast mDNS TXT response for a matched window."""
        event_id = (
            f"s{self.session_id}-p{attempt['packet_no']}"
            f"-w{attempt['window_index']}"
        )
        packet = self._build_packet(attempt, event_id)
        record = {
            "event_id": event_id,
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "interface": self.iface,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "destination_ip": MDNS_GROUP_IP,
            "destination_port": MDNS_PORT,
            "packet_identity": {
                "packet_no": attempt["packet_no"],
                "window_index": attempt["window_index"],
            },
            "message_bits": self.message_bits,
            "message_bit_length": len(self.message_bits),
            "match": attempt,
            "wire_frame_hex": bytes(packet).hex(),
            "send_status": "sent",
        }

        try:
            sendp(packet, iface=self.iface, count=1, verbose=False)
        except Exception as exc:
            record["send_status"] = "failed"
            record["send_error"] = str(exc)
            self._append_record(record)
            raise

        self._append_record(record)
        if self.report_status:
            print(
                f"       -> mDNS pointer multicast sent for {event_id} "
                f"({len(self.message_bits)} message bits)"
            )

    def is_own_signal(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return False
        if (
            pkt[IP].src != self.source_ip
            or pkt[UDP].sport != MDNS_PORT
            or pkt[UDP].dport != MDNS_PORT
        ):
            return False
        return SIGNAL_SIGNATURE.encode("ascii") in bytes(pkt[UDP].payload)
