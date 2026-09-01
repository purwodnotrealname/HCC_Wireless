import json


def split_message_windows(message_bits, window_size=4):
    if not message_bits:
        raise ValueError("message_bits cannot be empty")

    if any(ch not in "01" for ch in message_bits):
        raise ValueError("message_bits hanya boleh berisi karakter '0'/'1'")

    windows = []
    for i in range(0, len(message_bits), window_size):
        windows.append(message_bits[i:i + window_size])
    return windows


class SequentialBitMatcher:
    def __init__(self, message_bits, window_size=4):
        self.message_bits = message_bits
        self.window_size = window_size
        self.windows = split_message_windows(message_bits, window_size)

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

    def try_match(self, packet_no, bit_string):
        if self.is_complete:
            return None

        window = self.current_window
        compare_len = len(window)  
        candidate = bit_string[:compare_len]

        matched = (candidate == window)

        attempt = {
            "packet_no": packet_no,
            "window_index": self.pointer,
            "window_bits": window,
            "icd_bit_string": bit_string,
            "compared_bits": candidate,
            "status": "matched" if matched else "unmatched",
        }
        self.attempts.append(attempt)

        if matched:
            self.match_count += 1
            self.pointer += 1

        return attempt

    def summary(self):
        return {
            "message_bits": self.message_bits,
            "message_length": len(self.message_bits),
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