import sys

from ICD_extract import ICDExtractor, list_interfaces

OUTPUT_FILE = "icd_results.json"


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
    extractor = ICDExtractor(iface=iface)

    try:
        extractor.start()
    except KeyboardInterrupt:
        pass
    finally:
        extractor.save_json(OUTPUT_FILE)


if __name__ == "__main__":
    main()