import json
import sys

from engine.sEngine.history_extract import (
    ICDExtractor,
    describe_interface,
    list_interfaces,
)
from engine.sEngine.history_bits import OUTPUT_BITS, transform_json_file
from engine.sEngine.history_match import SequentialBitMatcher
from engine.sEngine.pointer_signal import PointerSignalSender

OUTPUT_FILE = "engineDump/history_results.json"
BITS_OUTPUT_FILE = "engineDump/history_bits_results.json"
MATCH_OUTPUT_FILE = "engineDump/history_match_results.json"
POI_ADDRESS_OUTPUT_FILE = "engineDump/poi_addresses.json"


def save_poi_addresses_json(
    extractor, matcher, filepath=POI_ADDRESS_OUTPUT_FILE, verbose=True
):
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
        "poi_mode": extractor.poi_mode,
        "poi_definition": (
            "matched ARP packets only"
            if extractor.poi_mode == "arp"
            else "matched packets from legacy group-destination ARP/DHCP/mDNS/SSDP capture"
        ),
        "total_poi_packets": len(poi_packets),
        "packets": poi_packets,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    if verbose:
        print(f"Saved {len(poi_packets)} PoI address record(s) to {filepath}")
    return output


def choose_sender_mode():
    print("Select the sender mode:")
    print("  [1] Legacy (full packet and comparison logs)")
    print("  [2] Silent (log matches only; still send the legacy pointer)")

    while True:
        choice = input("Choose mode [1/2]: ").strip()
        if choice == "1":
            return "legacy"
        if choice == "2":
            return "silent"
        print("Invalid selection. Enter 1 or 2.")


def choose_poi_mode():
    print("Select the packet-of-interest (PoI) mode:")
    print("  [1] Legacy (ARP, DHCP, mDNS, and SSDP)")
    print("  [2] ARP only")
    while True:
        choice = input("Choose PoI mode [1/2]: ").strip()
        if choice == "1":
            return "legacy"
        if choice == "2":
            return "arp"
        print("Invalid selection. Enter 1 or 2.")


def choose_message_bits():
    while True:
        entered = input(
            "Enter message bits (0/1; spaces, underscores, and 0b prefix are optional): "
        )
        message_bits = "".join(entered.split()).replace("_", "")
        if message_bits.lower().startswith("0b"):
            message_bits = message_bits[2:]

        if not message_bits:
            print("Message cannot be empty. Enter at least one bit.")
            continue
        if any(bit not in "01" for bit in message_bits):
            print("Invalid message. Enter only 0 and 1.")
            continue

        return int(message_bits, 2), len(message_bits), message_bits


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


def main():
    mode = choose_sender_mode()
    poi_mode = choose_poi_mode()
    message_value, message_bit_length, message_bits = choose_message_bits()
    iface = choose_interface()

    signal_sender = PointerSignalSender(
        iface=iface,
        message_bits=message_bits,
        report_status=(mode == "legacy"),
    )
    matcher = SequentialBitMatcher(
        message_value,
        bit_length=message_bit_length,
        window_size=OUTPUT_BITS,
        input_bit_width=OUTPUT_BITS,
    )
    extractor = ICDExtractor(
        iface=iface,
        matcher=matcher,
        on_match=signal_sender.send_for_match,
        ignore_packet=signal_sender.is_own_signal,
        matched_only_output=(mode == "silent"),
        poi_mode=poi_mode,
    )

    try:
        extractor.start()
    except KeyboardInterrupt:
        pass
    finally:
        quiet = mode == "silent"
        extractor.save_json(OUTPUT_FILE, verbose=not quiet)
        if extractor.packet_count > 0:
            matched_packet_nos = {
                attempt["packet_no"]
                for attempt in matcher.attempts
                if attempt["status"] == "matched"
            }
            transform_json_file(
                OUTPUT_FILE,
                BITS_OUTPUT_FILE,
                reset_after_packet_nos=matched_packet_nos,
                verbose=not quiet,
            )

        matcher.save_json(MATCH_OUTPUT_FILE, verbose=not quiet)
        save_poi_addresses_json(
            extractor,
            matcher,
            POI_ADDRESS_OUTPUT_FILE,
            verbose=not quiet,
        )
        if matcher.is_complete:
            print(
                f"\nevery {len(matcher.windows)} window successfully matched. "
                "Sniffing terminated."
            )
        else:
            print(
                f"\nSniffing terminated Progress: "
                f"{matcher.match_count}/{len(matcher.windows)} windows matched."
            )


if __name__ == "__main__":
    main()
