from ipaddress import IPv4Address

from scapy.all import conf, get_if_addr, get_if_hwaddr, sendp
from scapy.layers.l2 import ARP, Ether


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


class ARPMatchNotifier:
    def __init__(self, iface=None, target_ip="192.168.1.99"): #mac
        self.iface = iface if iface is not None else conf.iface
        self.target_ip = str(IPv4Address(target_ip))
        self.source_ip = get_if_addr(self.iface)
        self.source_mac = get_if_hwaddr(self.iface)

        if self.source_ip == "0.0.0.0":
            raise RuntimeError(
                f"Interface {self.iface!r} has no usable IPv4 address; "
                "cannot build an ARP request."
            )

    def send_for_match(self, attempt):
        packet = (
            Ether(src=self.source_mac, dst=BROADCAST_MAC)
            / ARP(
                op=1,
                hwsrc=self.source_mac,
                psrc=self.source_ip,
                hwdst=ZERO_MAC,
                pdst=self.target_ip,
            )
        )
        sendp(packet, iface=self.iface, count=1, verbose=False)
        print(
            f"       -> ARP request broadcast for {self.target_ip} "
            f"(match #{attempt['window_index'] + 1})"
        )