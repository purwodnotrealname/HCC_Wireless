"""Identify pointer events from the receiver's local mDNS packet structure."""

from ipaddress import IPv4Address

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


MDNS_PORT = 5353
MDNS_GROUP_IP = "224.0.0.251"
POINTER_SERVICE_SUFFIX = "_hcc-pointer._udp.local"
POINTER_TXT_SIGNATURE = "app=hcc-pointer-v1"
DNS_TXT_TYPE = 16


class PointerRecognizer:
    def __init__(self, sender_ip):
        self.sender_ip = str(IPv4Address(sender_ip))

    def recognize(self, pkt):
        if not (
            pkt.haslayer(Ether)
            and pkt.haslayer(IP)
            and pkt.haslayer(UDP)
            and pkt.haslayer(DNS)
        ):
            return None
        if pkt[IP].src != self.sender_ip or pkt[IP].dst != MDNS_GROUP_IP:
            return None
        if pkt[UDP].sport != MDNS_PORT or pkt[UDP].dport != MDNS_PORT:
            return None

        dns = pkt[DNS]
        if not dns.qr or not dns.aa or not dns.ancount:
            return None

        pointer_record_name = self._find_pointer_txt_record(dns)
        if pointer_record_name is None:
            return None

        return {
            "packet_type": "mDNS",
            "src_ip": pkt[IP].src,
            "src_mac": pkt[Ether].src,
            "dst_ip": pkt[IP].dst,
            "dst_mac": pkt[Ether].dst,
            "src_port": pkt[UDP].sport,
            "dst_port": pkt[UDP].dport,
            "dns_record_name": pointer_record_name,
            "dns_record_type": "TXT",
        }

    @classmethod
    def _find_pointer_txt_record(cls, dns):
        answer = dns.an
        answer_count = int(dns.ancount)
        for _ in range(answer_count):
            if not hasattr(answer, "rrname"):
                break

            record_name = cls._text(answer.rrname).rstrip(".").lower()
            record_type = int(answer.type)
            if record_type == DNS_TXT_TYPE and record_name.endswith(
                POINTER_SERVICE_SUFFIX
            ) and cls._has_pointer_signature(answer.rdata):
                return record_name

            answer = answer.payload
        return None

    @classmethod
    def _has_pointer_signature(cls, rdata):
        signature = POINTER_TXT_SIGNATURE.encode("ascii")
        if isinstance(rdata, bytes):
            return signature in rdata.lower()

        fields = rdata if isinstance(rdata, (list, tuple)) else [rdata]
        for field in fields:
            value = cls._text(field).strip().lower()
            if value == POINTER_TXT_SIGNATURE or POINTER_TXT_SIGNATURE in value:
                return True
        return False

    @staticmethod
    def _text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)
