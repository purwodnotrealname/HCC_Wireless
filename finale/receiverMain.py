import sys
import math
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
PERIODIC_BUFFER_FILE = RECEIVER_LOG_DIR / "receiver_periodic_history_buffer.json"
PERIODIC_LOG_FILE = RECEIVER_LOG_DIR / "receiver_periodic_history.log"
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
    print("  [3] SSDP only (mDNS pointer packets are still recognized)")
    while True:
        choice = input("Choose PoI mode [1/2/3]: ").strip()
        if choice == "1":
            return "legacy"
        if choice == "2":
            return "arp"
        if choice == "3":
            return "ssdp"
        print("Invalid selection. Enter 1, 2, or 3.")


def choose_counter_mode():
    print("Select how counter values are generated:")
    print("  [1] Legacy (derive values from selected network packets)")
    print("  [2] Periodic (packet independent; one value every 2 seconds)")
    while True:
        choice = input("Choose counter mode [1/2]: ").strip()
        if choice == "1":
            return "packet"
        if choice == "2":
            return "periodic"
        print("Invalid selection. Enter 1 or 2.")


def choose_silent_interval():
    while True:
        enabled = input(
            "Enable silent interval race guard? [y/N]: "
        ).strip().lower()
        if enabled in ("", "n", "no"):
            return None
        if enabled in ("y", "yes"):
            break
        print("Enter y or n.")

    while True:
        value = input("Silent interval threshold in milliseconds: ").strip()
        try:
            interval_ms = float(value)
        except ValueError:
            print("Enter a positive number of milliseconds.")
            continue
        if math.isfinite(interval_ms) and interval_ms > 0:
            return interval_ms
        print("Enter a positive finite number of milliseconds.")


def main():
    counter_mode = choose_counter_mode()
    if counter_mode == "packet":
        poi_mode = choose_poi_mode()
        silent_interval_ms = None
    else:
        poi_mode = None
        silent_interval_ms = None
    iface = choose_interface()
    pointer_source_ip = choose_pointer_source_ip()
    if counter_mode == "packet":
        silent_interval_ms = choose_silent_interval()
        buffer_path = BUFFER_FILE
        log_path = LOG_FILE
    else:
        buffer_path = PERIODIC_BUFFER_FILE
        log_path = PERIODIC_LOG_FILE
    receiver = ReceiverHistoryExtractor(
        iface=iface,
        buffer_path=buffer_path,
        log_path=log_path,
        secret_bits_path=SECRET_BITS_FILE,
        pointer_source_ip=pointer_source_ip,
        poi_mode=poi_mode,
        silent_interval_ms=silent_interval_ms,
        counter_mode=counter_mode,
    )

    try:
        receiver.start()
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.", flush=True)


if __name__ == "__main__":
    main()
