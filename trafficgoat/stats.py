"""Live statistics collector for TrafficGoat."""

import logging
import threading
import time
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class GeneratorStats:
    """Stats for a single generator."""
    name: str = ""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    connections: int = 0
    start_time: float = 0.0
    last_update: float = 0.0

    @property
    def elapsed(self) -> float:
        if self.start_time == 0:
            return 0
        return max((self.last_update or time.monotonic()) - self.start_time, 0.0)

    @property
    def pps(self) -> float:
        """Packets per second."""
        elapsed = self.elapsed
        return self.packets_sent / elapsed if elapsed > 0 else 0

    @property
    def bps(self) -> float:
        """Bytes per second."""
        elapsed = self.elapsed
        return self.bytes_sent / elapsed if elapsed > 0 else 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "errors": self.errors,
            "connections": self.connections,
            "elapsed": round(self.elapsed, 1),
            "pps": round(self.pps, 1),
            "bps": round(self.bps, 1),
        }


class StatsCollector:
    """Thread-safe statistics collector aggregating all generator stats."""

    def __init__(self):
        self._lock = threading.Lock()
        self._generators: dict[str, GeneratorStats] = {}
        self._running = False
        self._start_time = 0.0
        self._log_lines: list[str] = []
        self._log_callbacks: list = []
        self._stats_callbacks: list = []

    def register_generator(self, name: str):
        with self._lock:
            self._generators[name] = GeneratorStats(name=name, start_time=time.monotonic())

    def unregister_generator(self, name: str):
        with self._lock:
            self._generators.pop(name, None)

    def update(self, name: str, packets: int = 0, bytes_sent: int = 0,
               errors: int = 0, connections: int = 0):
        with self._lock:
            stats = self._generators.get(name)
            if stats:
                stats.packets_sent += packets
                stats.bytes_sent += bytes_sent
                stats.errors += errors
                stats.connections += connections
                stats.last_update = time.monotonic()

    def log(self, message: str):
        # Wall-clock timestamp is intentional here — these are user-facing log
        # lines. Durations elsewhere use monotonic.
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        with self._lock:
            self._log_lines.append(line)
            if len(self._log_lines) > 1000:
                self._log_lines = self._log_lines[-500:]
        for cb in self._log_callbacks:
            try:
                cb(line)
            except Exception:
                logger.warning("log callback raised", exc_info=True)

    def on_log(self, callback):
        self._log_callbacks.append(callback)

    def on_stats(self, callback):
        self._stats_callbacks.append(callback)

    def get_logs(self, last_n: int = 100) -> list[str]:
        with self._lock:
            return self._log_lines[-last_n:]

    def get_stats(self) -> dict:
        with self._lock:
            gen_stats = {name: s.to_dict() for name, s in self._generators.items()}
            total_packets = sum(s.packets_sent for s in self._generators.values())
            total_bytes = sum(s.bytes_sent for s in self._generators.values())
            total_errors = sum(s.errors for s in self._generators.values())
            elapsed = time.monotonic() - self._start_time if self._start_time else 0
            running = self._running

        return {
            "running": running,
            "elapsed": round(elapsed, 1),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_errors": total_errors,
            "total_pps": round(total_packets / elapsed, 1) if elapsed > 0 else 0,
            "total_bps": round(total_bytes / elapsed, 1) if elapsed > 0 else 0,
            "generators": gen_stats,
        }

    def start(self):
        with self._lock:
            self._running = True
            self._start_time = time.monotonic()

    def stop(self):
        with self._lock:
            self._running = False

    def reset(self):
        with self._lock:
            self._generators.clear()
            self._log_lines.clear()
            self._start_time = 0.0
            self._running = False

    def emit_stats(self):
        """Push current stats to all callbacks."""
        stats = self.get_stats()
        for cb in self._stats_callbacks:
            try:
                cb(stats)
            except Exception:
                logger.warning("stats callback raised", exc_info=True)
