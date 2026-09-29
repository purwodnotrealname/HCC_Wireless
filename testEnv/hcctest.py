import sys

from ICD_extract import ICDExtractor, list_interfaces
from icd_bits import transform_json_file
from icd_match import SequentialBitMatcher
from arp_signal import ARPMatchNotifier

OUTPUT_FILE = "icd_results.json"
BITS_OUTPUT_FILE = "icd_bits_results.json"
MATCH_OUTPUT_FILE = "icd_match_results.json"
ARP_TARGET_IP = "192.168.1.99" 

# hardcoded 100 bits msg
HARDCODED_MESSAGE_BITS = (
    "101001110010110101111000110001011010001111101001"
    "001110101111010001010011100111001011000101011110"
    "1011"
)
assert all(ch in "01" for ch in HARDCODED_MESSAGE_BITS), (
    "HARDCODED_MESSAGE_BITS'0'/'1'"
)


def choose_interface():
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces found")
        sys.exit(1)

    print("Available network interfaces:")
    for idx, name in enumerate(interfaces):
        print(f"  [{idx}] {name}")

    choice = input(
        "\nPress Enter for default: "
    ).strip()

    if choice == "":
        return None 

    try:
        idx = int(choice)
        return interfaces[idx]
    except (ValueError, IndexError):
        print("Invalid selection, using default interface.")
        return None


def main():
    iface = choose_interface()
    matcher = SequentialBitMatcher(HARDCODED_MESSAGE_BITS, window_size=4)
    arp_notifier = ARPMatchNotifier(iface=iface, target_ip=ARP_TARGET_IP)
    extractor = ICDExtractor(
        iface=iface,
        matcher=matcher,
        on_match=arp_notifier.send_for_match,
        ignore_arp_marker=(ARP_TARGET_IP, arp_notifier.source_ip, arp_notifier.source_mac),
    )

    try:
        extractor.start()
    except KeyboardInterrupt:
        pass
    finally:
        extractor.save_json(OUTPUT_FILE)
        if extractor.packet_count > 0:
            transform_json_file(OUTPUT_FILE, BITS_OUTPUT_FILE)

        matcher.save_json(MATCH_OUTPUT_FILE)
        if matcher.is_complete:
            print(f"\nevery {len(matcher.windows)} window successfully "
                  f"matched. Sniffing terminated.")
        else:
            print(f"\nSniffing terminated Progres: "
                  f"{matcher.match_count}/{len(matcher.windows)} window valid.")


if __name__ == "__main__":
    main()