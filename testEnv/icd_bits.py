import hashlib
import json
import math

ICD_SCALE = 1

DIGEST_BYTES = 1

OUTPUT_BITS = 4

ICD_INT_BYTES = 4

ROUND_STEP = 100000         
COUNTER_MIN = 1
COUNTER_MAX = 9             


def icd_to_int(icd_ms):
    return int(round(icd_ms * ICD_SCALE))


def ceil_round(icd_ms, step=ROUND_STEP):
    if icd_ms <= 0:
        return 0
    return math.ceil(icd_ms / step) * step


class CounterState:
    def __init__(self, counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
        self.counter_min = counter_min
        self.counter_max = counter_max
        self.counter = counter_min

    def next_value(self, icd_ms, round_step=ROUND_STEP):
        rounded = ceil_round(icd_ms, step=round_step)
        counter = self.counter
        rounded_with_counter = rounded + counter

        self.counter += 1
        if self.counter > self.counter_max:
            self.counter = self.counter_min

        return rounded, counter, rounded_with_counter


def icd_to_hash_bytes(rounded_with_counter):
    icd_bytes = rounded_with_counter.to_bytes(
        ICD_INT_BYTES, byteorder="big", signed=False
    )

    shake = hashlib.shake_128()
    shake.update(icd_bytes)
    return shake.digest(DIGEST_BYTES)


def icd_to_bits(icd_ms, counter_state):
    icd_int = icd_to_int(icd_ms)
    rounded, counter, rounded_with_counter = counter_state.next_value(icd_ms)
    digest = icd_to_hash_bytes(rounded_with_counter)
    byte_val = digest[0]

    nibble_val = byte_val & 0xF

    return {
        "icd_ms": icd_ms,                       
        "icd_int_ms": icd_int,                   
        "rounded": rounded,
        "icd_counter_added": rounded_with_counter,  # hash source
        "bit_string": format(nibble_val, "04b"),  # 4-bit binary string
        "bit_int": nibble_val,  # Integer 0-15
    }


def add_sequential_counter(records, round_step=ROUND_STEP,
                            counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
    counter = counter_min
    for rec in records:
        rounded = ceil_round(rec["icd_ms"], step=round_step)
        rec["rounded"] = rounded
        rec["icd_counter_added"] = rounded + counter

        counter += 1
        if counter > counter_max:
            counter = counter_min

    return records


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
        "hash_algorithm": "SHAKE-128",
        "digest_bits_per_icd": OUTPUT_BITS,
        "icd_scale": "1 unit = 1 ms",
        "round_step": ROUND_STEP,
        "counter_range": [COUNTER_MIN, COUNTER_MAX],
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