import json
import sys

from ICD_extract import ICDExtractor, list_interfaces
from icd_bits import OUTPUT_BITS, transform_json_file
from icd_match import SequentialBitMatcher
from arp_signal import ARPMatchNotifier

OUTPUT_FILE = "icd_results.json"
BITS_OUTPUT_FILE = "icd_bits_results.json"
MATCH_OUTPUT_FILE = "icd_match_results.json"
POI_ADDRESS_OUTPUT_FILE = "poi_addresses.json"
ARP_TARGET_IP = "192.168.1.99" 

#test message 
HARDCODED_MESSAGE_VALUE = (
    0b1010011100101101011110001100010110100011111010010011101011110100010100111001110010110001010111101011
)
HARDCODED_MESSAGE_BIT_LENGTH = 100
assert HARDCODED_MESSAGE_VALUE.bit_length() == HARDCODED_MESSAGE_BIT_LENGTH


def save_poi_addresses_json(
    extractor, matcher, filepath=POI_ADDRESS_OUTPUT_FILE
):
    """Save source addresses for packets that matched a message window."""
    packets_by_number = {
        packet["packet_no"]: packet for packet in extractor.records
    }
    poi_packets = []

    for attempt in matcher.attempts:
        if attempt["status"] != "matched":
            continue

        packet = packets_by_number.get(attempt["packet_no"])
        if packet is None:
            continue

        poi_packets.append({
            "packet_no": packet["packet_no"],
            "window_index": attempt["window_index"],
            "src_ip": packet["src_ip"],
            "src_mac": packet["src_mac"],
        })

    output = {
        "poi_definition": "packets that matched a message window",
        "total_poi_packets": len(poi_packets),
        "packets": poi_packets,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(poi_packets)} PoI address record(s) to {filepath}")
    return output


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
    matcher = SequentialBitMatcher(
        HARDCODED_MESSAGE_VALUE,
        bit_length=HARDCODED_MESSAGE_BIT_LENGTH,
        window_size=OUTPUT_BITS,
        input_bit_width=OUTPUT_BITS,
    )
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
        save_poi_addresses_json(extractor, matcher, POI_ADDRESS_OUTPUT_FILE)
        if matcher.is_complete:
            print(f"\nevery {len(matcher.windows)} window successfully "
                  f"matched. Sniffing terminated.")
        else:
            print(f"\nSniffing terminated Progres: "
                  f"{matcher.match_count}/{len(matcher.windows)} window valid.")


if __name__ == "__main__":
    main()
