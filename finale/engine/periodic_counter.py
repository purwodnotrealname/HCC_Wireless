"""Shared deterministic counter sequence for packet independent mode."""

from datetime import datetime


PERIODIC_COUNTER_INTERVAL_SECONDS = 2.0
PERIODIC_COUNTER_VALUES = (
    0, 15, 1, 14, 2, 13, 3, 12,
    4, 11, 5, 10, 6, 9, 7, 8,
)


class PeriodicCounterState:
    """Cycle through the 16 four bit values in legacy history bit order."""

    def __init__(self):
        self.index = 0

    def next_value(self):
        value = PERIODIC_COUNTER_VALUES[self.index]
        self.index = (self.index + 1) % len(PERIODIC_COUNTER_VALUES)
        return value

    def reset(self):
        self.index = 0


def timestamp_now():
    return datetime.now().isoformat(timespec="milliseconds")
