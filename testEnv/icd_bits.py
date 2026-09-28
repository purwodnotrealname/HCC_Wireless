import hashlib
import json
import math

ICD_SCALE = 1

OUTPUT_BITS = 4
NIBBLE_SPACE = 2 ** OUTPUT_BITS     


COUNTER_MIN = 1
COUNTER_MAX = NIBBLE_SPACE           

COUNTER_BYTES = 4                      
KEY_DIGEST_BYTES = 8                  

ROUND_STEP = 100                      


def icd_to_int(icd_ms):
    return int(round(icd_ms * ICD_SCALE))


def ceil_round(icd_ms, step=ROUND_STEP):
    if icd_ms <= 0:
        return 0
    return math.ceil(icd_ms / step) * step


def _counter_digest(counter):
    """SHAKE-128 dari counter saja (tanpa nilai ICD)."""
    shake = hashlib.shake_128()
    shake.update(counter.to_bytes(COUNTER_BYTES, byteorder="big", signed=False))
    return shake.digest(KEY_DIGEST_BYTES)


def build_counter_table(counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
    size = counter_max - counter_min + 1
    if size != NIBBLE_SPACE:
        raise ValueError(
            f"Rentang counter harus {NIBBLE_SPACE} nilai "
            f"(2^{OUTPUT_BITS}), dapat {size}"
        )

    keyed = []
    for c in range(counter_min, counter_max + 1):
        keyed.append((_counter_digest(c), c - counter_min))

    keys = [k for k, _ in keyed]
    if len(set(keys)) != len(keys):
        raise RuntimeError("Tabrakan digest pada kunci urutan; naikkan KEY_DIGEST_BYTES")

    keyed.sort(key=lambda kv: kv[0])
    order = [idx for _, idx in keyed]        


    table = {}
    for pos, counter in enumerate(range(counter_min, counter_max + 1)):
        table[counter] = order[pos]
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
        "counter": counter,                      # sumber hash (satu-satunya)
        "bit_string": format(nibble_val, "04b"),
        "bit_int": nibble_val,
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
        "hash_algorithm": "SHAKE-128",
        "hash_input": "counter only",
        "digest_bits_per_icd": OUTPUT_BITS,
        "icd_scale": "1 unit = 1 ms",
        "counter_range": [COUNTER_MIN, COUNTER_MAX],
        "counter_table": {
            str(c): format(v, "04b") for c, v in COUNTER_TABLE.items()
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