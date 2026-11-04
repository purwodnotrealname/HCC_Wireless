"""Capture filters for the sender's supported observable packet types."""


GROUP_DESTINATION_FILTER = "(ether broadcast or ether multicast)"
ARP_BROADCAST_FILTER = "(arp and ether broadcast)"
DHCP_FILTER = (
    "(udp and (port 67 or port 68) and "
    f"{GROUP_DESTINATION_FILTER})"
)
MDNS_FILTER = (
    "(udp and dst port 5353 and "
    f"{GROUP_DESTINATION_FILTER})"
)
SSDP_FILTER = (
    "(udp and dst port 1900 and "
    f"{GROUP_DESTINATION_FILTER})"
)

CAPTURE_FILTER = (
    f"({ARP_BROADCAST_FILTER} or {DHCP_FILTER} or "
    f"{MDNS_FILTER} or {SSDP_FILTER})"
)


def get_packet_filter():
    """Return the testEnv protocol filter, excluding Ethernet unicast."""
    return CAPTURE_FILTER
