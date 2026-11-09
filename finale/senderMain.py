import json
import math
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
    if extractor.counter_mode == "periodic":
        output = {
            "counter_mode": "periodic",
            "poi_mode": None,
            "silent_interval_ms": None,
            "poi_definition": "not used by periodic counter mode",
            "total_poi_packets": 0,
            "packets": [],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        if verbose:
            print(f"Saved periodic-mode PoI summary to {filepath}")
        return output

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
        "counter_mode": extractor.counter_mode,
        "poi_mode": extractor.poi_mode,
        "silent_interval_ms": extractor.silent_interval_ms,
        "poi_definition": {
            "arp": "matched ARP packets only",
            "ssdp": "matched group-destination SSDP packets only",
            "legacy": "matched packets from legacy group-destination ARP/DHCP/mDNS/SSDP capture",
        }[extractor.poi_mode],
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


def choose_poi_mode():
    print("Select the packet-of-interest (PoI) mode:")
    print("  [1] Legacy (ARP, DHCP, mDNS, and SSDP)")
    print("  [2] ARP only")
    print("  [3] SSDP only")
    while True:
        choice = input("Choose PoI mode [1/2/3]: ").strip()
        if choice == "1":
            return "legacy"
        if choice == "2":
            return "arp"
        if choice == "3":
            return "ssdp"
        print("Invalid selection. Enter 1, 2, or 3.")


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
        choice = input(
            "\nSelect the adapter for capture or pointer signals: "
        ).strip()
        try:
            return interfaces[int(choice)]
        except (ValueError, IndexError):
            print("Invalid selection. Enter one of the listed indexes.")


def main():
    mode = choose_sender_mode()
    counter_mode = choose_counter_mode()
    if counter_mode == "packet":
        poi_mode = choose_poi_mode()
        silent_interval_ms = choose_silent_interval()
    else:
        poi_mode = None
        silent_interval_ms = None
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
        silent_interval_ms=silent_interval_ms,
        counter_mode=counter_mode,
    )

    try:
        extractor.start()
    except KeyboardInterrupt:
        pass
    finally:
        quiet = mode == "silent"
        extractor.save_json(OUTPUT_FILE, verbose=not quiet)
        if extractor.packet_count > 0:
            matched_packet_nos = (
                {
                    attempt["packet_no"]
                    for attempt in matcher.attempts
                    if attempt["status"] == "matched"
                }
                if counter_mode == "packet"
                else set()
            )
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
        run_subject = (
            "Periodic counter run"
            if counter_mode == "periodic"
            else "Sniffing"
        )
        if matcher.is_complete:
            print(
                f"\nevery {len(matcher.windows)} window successfully matched. "
                f"{run_subject} terminated."
            )
        else:
            print(
                f"\n{run_subject} terminated. Progress: "
                f"{matcher.match_count}/{len(matcher.windows)} windows matched."
            )


if __name__ == "__main__":
    main()
