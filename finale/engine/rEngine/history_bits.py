"""Generate fixed-width history values from the receiver counter."""

OUTPUT_BITS = 4
NIBBLE_SPACE = 2 ** OUTPUT_BITS
COUNTER_MIN = 1
COUNTER_MAX = NIBBLE_SPACE


def build_counter_table(counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
    size = counter_max - counter_min + 1
    if size != NIBBLE_SPACE:
        raise ValueError(
            f"Counter range must contain {NIBBLE_SPACE} values "
            f"(2^{OUTPUT_BITS}); got {size}"
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


class ReceiverCounterState:
    def __init__(self, counter_min=COUNTER_MIN, counter_max=COUNTER_MAX):
        self.counter_min = counter_min
        self.counter_max = counter_max
        self.counter = counter_min

    def next_counter(self):
        if self.counter < self.counter_min:
            self.counter = self.counter_min

        counter = self.counter
        self.counter += 1
        if self.counter > self.counter_max:
            self.counter = self.counter_min
        return counter

    def reset(self):
        self.counter = 0


def counter_to_nibble(counter):
    return COUNTER_TABLE[counter]


def next_counter_value(counter_state):
    counter = counter_state.next_counter()
    nibble = counter_to_nibble(counter)
    return {
        "counter": counter,
        "counter_bits": f"{nibble:0{OUTPUT_BITS}b}",
    }
