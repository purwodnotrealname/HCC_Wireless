"""Publish a DNS-SD service announcement for each successful bit match."""

import json
import socket
import uuid
from datetime import datetime
from pathlib import Path

from scapy.all import conf, get_if_addr
from scapy.layers.inet import IP, UDP


SERVICE_TYPE = "_hcc-match._udp.local."
SIGNAL_SIGNATURE = "hcc_match_trigger_v1"
MDNS_PORT = 5353
TRIGGER_LOG_FILE = (
    Path(__file__).resolve().parents[2]
    / "engineDump"
    / "mdns_triggers.json"
)


class MDNSTrigger:
    """Announce one short-lived DNS-SD service for every matched window."""

    def __init__(self, iface=None, output_file=TRIGGER_LOG_FILE):
        try:
            from zeroconf import IPVersion, Zeroconf
        except ImportError as exc:
            raise RuntimeError(
                "The new mDNS trigger needs the 'zeroconf' package. "
                "Install it with: pip install zeroconf"
            ) from exc

        self.iface = iface if iface is not None else conf.iface
        self.source_ip = get_if_addr(self.iface)
        if self.source_ip == "0.0.0.0":
            raise RuntimeError(
                f"Interface {self.iface!r} has no usable IPv4 address; "
                "cannot announce an mDNS service."
            )

        self.session_id = uuid.uuid4().hex[:12]
        self.server_name = f"hcc-{self.session_id}.local."
        self.output_file = Path(output_file)
        self._registered_services = []
        self._zeroconf = Zeroconf(
            interfaces=[self.source_ip],
            ip_version=IPVersion.V4Only,
        )

    def _append_record(self, record):
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        if self.output_file.exists():
            with self.output_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("triggers", []) if isinstance(data, dict) else []
        else:
            records = []

        records.append(record)
        with self.output_file.open("w", encoding="utf-8") as f:
            json.dump({"triggers": records}, f, indent=2)

    def send_for_match(self, attempt):
        """Register a DNS-SD service, causing Zeroconf to announce it."""
        event_id = (
            f"s{self.session_id}-p{attempt['packet_no']}"
            f"-w{attempt['window_index']}"
        )
        service_name = f"{event_id}.{SERVICE_TYPE}"
        window_width = attempt["window_width"]
        properties = {
            "app": SIGNAL_SIGNATURE,
            "event_id": event_id,
            "packet_no": str(attempt["packet_no"]),
            "window_index": str(attempt["window_index"]),
            "window_bits": f"{attempt['window_value']:0{window_width}b}",
            "packet_bits": f"{attempt['packet_bit_value']:04b}",
            "compared_bits": f"{attempt['compared_value']:0{window_width}b}",
            "status": attempt["status"],
        }
        record = {
            "event_id": event_id,
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "interface": self.iface,
            "source_ip": self.source_ip,
            "service_type": SERVICE_TYPE,
            "service_name": service_name,
            "properties": properties,
            "match": {
                key: value for key, value in attempt.items()
                if key != "packet"
            },
            "send_status": "announced",
        }

        try:
            from zeroconf import ServiceInfo

            service = ServiceInfo(
                type_=SERVICE_TYPE,
                name=service_name,
                port=MDNS_PORT,
                properties=properties,
                server=self.server_name,
                addresses=[socket.inet_aton(self.source_ip)],
            )
            self._zeroconf.register_service(service)
            self._registered_services.append(service)
        except Exception as exc:
            record["send_status"] = "failed"
            record["send_error"] = str(exc)
            self._append_record(record)
            raise

        self._append_record(record)
        print(f"       -> mDNS service announced for {event_id}", flush=True)

    def is_own_signal(self, pkt):
        """Ignore this sender's mDNS announcements during packet capture."""
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return False
        if (
            pkt[IP].src != self.source_ip
            or pkt[UDP].sport != MDNS_PORT
            or pkt[UDP].dport != MDNS_PORT
        ):
            return False
        return SIGNAL_SIGNATURE.encode("ascii") in bytes(pkt[UDP].payload)

    def close(self):
        """Withdraw registered services and stop the Zeroconf responder."""
        try:
            for service in reversed(self._registered_services):
                self._zeroconf.unregister_service(service)
        finally:
            self._registered_services.clear()
            self._zeroconf.close()
