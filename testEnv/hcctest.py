import sys

from ICD_extract import ICDExtractor, list_interfaces
from icd_bits import transform_json_file
from icd_match import SequentialBitMatcher

OUTPUT_FILE = "icd_results.json"
BITS_OUTPUT_FILE = "icd_bits_results.json"
MATCH_OUTPUT_FILE = "icd_match_results.json"

# hardcoded 100 bits msg
HARDCODED_MESSAGE_BITS = (
    "010010010100001101000100001000000100110101000001"
    "010101000100001101001000001100010011001000110011"
    "0001"
)
assert all(ch in "01" for ch in HARDCODED_MESSAGE_BITS), (
    "HARDCODED_MESSAGE_BITS hanya boleh berisi karakter '0'/'1'"
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
    extractor = ICDExtractor(iface=iface, matcher=matcher)

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
            print(f"\nSeluruh {len(matcher.windows)} window pesan berhasil "
                  f"dicocokkan. Sniffing berhenti otomatis.")
        else:
            print(f"\nSniffing dihentikan manual. Progres: "
                  f"{matcher.match_count}/{len(matcher.windows)} window cocok.")


if __name__ == "__main__":
    main()