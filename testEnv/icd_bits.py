import json
import math

ICD_SCALE = 1

OUTPUT_BITS = 4
NIBBLE_SPACE = 2 ** OUTPUT_BITS     


COUNTER_MIN = 1
COUNTER_MAX = NIBBLE_SPACE           

ROUND_STEP = 100                      


def icd_to_int(icd_ms):
    return int(round(icd_ms * ICD_SCALE))


def ceil_round(icd_ms, step=ROUND_STEP):
    if icd_ms <= 0:
        return 0
    return math.ceil(icd_ms / step) * step


def build_counter_table(counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
    size = counter_max - counter_min + 1
    if size != NIBBLE_SPACE:
        raise ValueError(
            f"Rentang counter harus {NIBBLE_SPACE} nilai "
            f"(2^{OUTPUT_BITS}), dapat {size}"
        )

    table = {}
    counter = counter_min
    first_index = 0
    last_index = size - 1

    while first_index <= last_index:
        table[counter] = first_index
        counter += 1

        if first_index < last_index:
            table[counter] = last_index
            counter += 1

        first_index += 1
        last_index -= 1

    return table


COUNTER_TABLE = build_counter_table()


class CounterState:
    def __init__(self, counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
        self.counter_min = counter_min
        self.counter_max = counter_max
        self.counter = counter_min

    def next_value(self, icd_ms, round_step=ROUND_STEP):
        """Ambil counter saat ini lalu majukan (wrap 16 -> 1).

        icd_ms hanya dipakai untuk 'rounded' (logging); tidak memengaruhi bit.
        Setelah wrap, pemetaan kembali menghasilkan nilai bit 0.
        """
        rounded = ceil_round(icd_ms, step=round_step)
        counter = self.counter

        self.counter += 1
        if self.counter > self.counter_max:
            self.counter = self.counter_min

        return rounded, counter


def counter_to_nibble(counter):
    return COUNTER_TABLE[counter]


def icd_to_bits(icd_ms, counter_state):
    icd_int = icd_to_int(icd_ms)
    rounded, counter = counter_state.next_value(icd_ms)
    nibble_val = counter_to_nibble(counter)

    return {
        "icd_ms": icd_ms,
        "icd_int_ms": icd_int,
        "rounded": rounded,
        "counter": counter,
        "bit_value": nibble_val,
    }


def transform_records(records, counter_state=None):
    if counter_state is None:
        counter_state = CounterState()

    transformed = []
    for rec in records:
        bits = icd_to_bits(rec["icd_ms"], counter_state)
        transformed.append({
            "packet_no": rec.get("packet_no"),
            "protocol": rec.get("protocol"),
            "src_mac": rec.get("src_mac"),
            "src_ip": rec.get("src_ip"),
            "timestamp": rec.get("timestamp"),
            **bits,
        })
    return transformed


def transform_json_file(input_path, output_path):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    transformed_packets = transform_records(data.get("packets", []))

    output = {
        "source_file": input_path,
        "interface": data.get("interface"),
        "initialization_time": data.get("initialization_time"),
        "total_packets": data.get("total_packets"),
        "mapping": "static counter sequence",
        "output_bits_per_icd": OUTPUT_BITS,
        "icd_scale": "1 unit = 1 ms",
        "counter_range": [COUNTER_MIN, COUNTER_MAX],
        "counter_table": {
            str(c): v for c, v in COUNTER_TABLE.items()
        },
        "packets": transformed_packets,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Transformed {len(transformed_packets)} record(s).")
    print(f"Saved to {output_path}")

    return output


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python icd_bits.py <input_json> <output_json>")
        print("Contoh: python icd_bits.py icd_results.json icd_bits_results.json")
        sys.exit(1)

    transform_json_file(sys.argv[1], sys.argv[2])
