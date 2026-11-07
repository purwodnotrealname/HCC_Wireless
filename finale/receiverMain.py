import sys
from ipaddress import IPv4Address
from pathlib import Path

from engine.rEngine.history_extract import (
    ReceiverHistoryExtractor,
    describe_interface,
    list_interfaces,
)


BASE_DIR = Path(__file__).resolve().parent
RECEIVER_LOG_DIR = BASE_DIR / "engine" / "rEngine" / "receiverlogdump"
BUFFER_FILE = RECEIVER_LOG_DIR / "receiver_history_buffer.json"
LOG_FILE = RECEIVER_LOG_DIR / "receiver_history.log"
SECRET_BITS_FILE = RECEIVER_LOG_DIR / "receiver_secret_bits.json"


def choose_interface():
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces found")
        sys.exit(1)

    print("Available network interfaces:")
    for idx, name in enumerate(interfaces):
        print(f"  [{idx}] {describe_interface(name)}")
        print(f"      Npcap capture ID: {name}")

    while True:
        choice = input("\nSelect the adapter index to capture on: ").strip()
        try:
            return interfaces[int(choice)]
        except (ValueError, IndexError):
            print("Invalid selection. Enter one of the listed indexes.")


def choose_pointer_source_ip():
    while True:
        entered = input(
            "Enter the sender's IPv4 address for pointer recognition: "
        ).strip()
        try:
            return str(IPv4Address(entered))
        except ValueError:
            print("Invalid IPv4 address. Enter the sender's interface address.")


def choose_poi_mode():
    print("Select the packet-of-interest (PoI) mode:")
    print("  [1] Legacy (ARP, DHCP, mDNS, and SSDP)")
    print("  [2] ARP only (mDNS pointer packets are still recognized)")
    while True:
        choice = input("Choose PoI mode [1/2]: ").strip()
        if choice == "1":
            return "legacy"
        if choice == "2":
            return "arp"
        print("Invalid selection. Enter 1 or 2.")


def main():
    poi_mode = choose_poi_mode()
    iface = choose_interface()
    pointer_source_ip = choose_pointer_source_ip()
    receiver = ReceiverHistoryExtractor(
        iface=iface,
        buffer_path=BUFFER_FILE,
        log_path=LOG_FILE,
        secret_bits_path=SECRET_BITS_FILE,
        pointer_source_ip=pointer_source_ip,
        poi_mode=poi_mode,
    )

    try:
        receiver.start()
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.", flush=True)


if __name__ == "__main__":
    main()
