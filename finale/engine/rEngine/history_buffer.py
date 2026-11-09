"""Persist a rolling counter buffer and an append-only counter log."""

import json
import os
from collections import deque
from pathlib import Path


BUFFER_CAPACITY = 4


class ReceiverHistoryStore:
    def __init__(
        self, buffer_path, log_path, capacity=BUFFER_CAPACITY,
        counter_mode="packet",
    ):
        self.buffer_path = Path(buffer_path)
        self.log_path = Path(log_path)
        self.capacity = capacity
        self.counter_mode = counter_mode
        self.buffer_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        existing, needs_rewrite = self._load_existing()
        self._buffer = deque(existing[:capacity], maxlen=capacity)
        if needs_rewrite:
            self._save_buffer()

    def _load_existing(self):
        if not self.buffer_path.exists():
            return [], False

        with self.buffer_path.open("r", encoding="utf-8") as handle:
            saved = json.load(handle)
        if saved.get("counter_mode", "packet") != self.counter_mode:
            return [], True
        records = saved.get("counters")
        needs_rewrite = records is None
        if needs_rewrite:
            records = saved.get("history_bits", [])
        if not isinstance(records, list):
            raise ValueError(
                f"Invalid receiver history buffer format: {self.buffer_path}"
            )

        clean_records = []
        for record in records:
            if not isinstance(record, dict) or "counter" not in record:
                continue
            record_mode = record.get("counter_mode", "packet")
            if record_mode != self.counter_mode:
                needs_rewrite = True
                continue
            counter_bits = record.get("counter_bits", record.get("history_bits"))
            if (
                not isinstance(counter_bits, str)
                or len(counter_bits) != 4
                or any(bit not in "01" for bit in counter_bits)
            ):
                continue
            clean_records.append({
                "session_id": record.get("session_id"),
                "packet_no": record.get("packet_no"),
                "sample_no": record.get("sample_no"),
                "protocol": record.get("protocol"),
                "counter_mode": record_mode,
                "poi_mode": record.get("poi_mode"),
                "src_mac": record.get("src_mac"),
                "dst_mac": record.get("dst_mac"),
                "src_ip": record.get("src_ip"),
                "timestamp": record.get("timestamp"),
                "counter": record["counter"],
                "counter_bits": counter_bits,
            })
        return clean_records, needs_rewrite

    @property
    def newest_first(self):
        return list(self._buffer)

    @property
    def latest(self):
        return self._buffer[0] if self._buffer else None

    def _save_buffer(self):
        output = {
            "counter_mode": self.counter_mode,
            "capacity": self.capacity,
            "order": "newest_first",
            "buffered_count": len(self._buffer),
            "counters": self.newest_first,
        }
        temporary_path = self.buffer_path.with_name(
            self.buffer_path.name + f".{os.getpid()}.tmp"
        )
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, ensure_ascii=False)
        os.replace(temporary_path, self.buffer_path)

    def add(self, record):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        if len(self._buffer) == self.capacity:
            self._buffer.clear()
        self._buffer.appendleft(record)
        self._save_buffer()

    def append_event(self, record):
        """Append a receiver event that does not consume a counter value."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def pop_latest(self):
        if not self._buffer:
            return None
        record = self._buffer.popleft()
        self._save_buffer()
        return record
