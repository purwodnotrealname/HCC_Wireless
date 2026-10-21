import json


def split_message_windows(message_value, bit_length, window_size=4):
    """Split an integer bit pattern into left-to-right integer windows."""
    if isinstance(message_value, bool) or not isinstance(message_value, int):
        raise TypeError("message_value must be an integer")
    if message_value < 0:
        raise ValueError("message_value cannot be negative")
    if (isinstance(bit_length, bool) or not isinstance(bit_length, int)
            or bit_length <= 0):
        raise ValueError("bit_length must be a positive integer")
    if message_value.bit_length() > bit_length:
        raise ValueError("message_value does not fit in bit_length bits")
    if (isinstance(window_size, bool) or not isinstance(window_size, int)
            or window_size <= 0):
        raise ValueError("window_size must be a positive integer")

    windows = []
    for start in range(0, bit_length, window_size):
        width = min(window_size, bit_length - start)
        shift = bit_length - start - width
        value = (message_value >> shift) & ((1 << width) - 1)
        windows.append((value, width))
    return windows


class SequentialBitMatcher:
    def __init__(self, message_value, bit_length, window_size=4,
                 input_bit_width=4):
        if (isinstance(input_bit_width, bool)
                or not isinstance(input_bit_width, int)
                or input_bit_width <= 0):
            raise ValueError("input_bit_width must be a positive integer")
        if (isinstance(window_size, bool) or not isinstance(window_size, int)
                or window_size <= 0):
            raise ValueError("window_size must be a positive integer")
        if window_size > input_bit_width:
            raise ValueError("window_size cannot exceed input_bit_width")

        self.message_value = message_value
        self.bit_length = bit_length
        self.window_size = window_size
        self.input_bit_width = input_bit_width
        self.windows = split_message_windows(
            message_value, bit_length, window_size
        )

        self.pointer = 0          # index window 
        self.attempts = []        # history (matched & unmatched)
        self.match_count = 0      # Matched window count

    @property
    def is_complete(self):
        return self.pointer >= len(self.windows)

    @property
    def current_window(self):
        if self.is_complete:
            return None
        return self.windows[self.pointer]

    def try_match(self, packet_no, bit_value):
        if self.is_complete:
            return None
        if isinstance(bit_value, bool) or not isinstance(bit_value, int):
            raise TypeError("bit_value must be an integer")
        if not 0 <= bit_value < (1 << self.input_bit_width):
            raise ValueError(
                f"bit_value must fit in {self.input_bit_width} bits"
            )

        window_value, window_width = self.current_window
        shift = self.input_bit_width - window_width
        candidate = (bit_value >> shift) & ((1 << window_width) - 1)

        matched = candidate == window_value

        attempt = {
            "packet_no": packet_no,
            "window_index": self.pointer,
            "window_value": window_value,
            "window_width": window_width,
            "packet_bit_value": bit_value,
            "compared_value": candidate,
            "status": "matched" if matched else "unmatched",
        }
        self.attempts.append(attempt)

        if matched:
            self.match_count += 1
            self.pointer += 1

        return attempt

    def summary(self):
        return {
            "message_value": self.message_value,
            "message_bit_length": self.bit_length,
            "window_size": self.window_size,
            "total_windows": len(self.windows),
            "windows_matched": self.match_count,
            "current_pointer": self.pointer,
            "is_complete": self.is_complete,
            "total_attempts": len(self.attempts),
        }

    def save_json(self, filepath="icd_match_results.json"):
        output = {
            **self.summary(),
            "attempts": self.attempts,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"Saved {len(self.attempts)} attempt record(s) to {filepath}")
        return output
