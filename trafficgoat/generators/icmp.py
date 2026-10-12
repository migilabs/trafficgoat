"""ICMP traffic generator - ping flood, various ICMP types."""

import os
import random
import time

from scapy.all import IP, ICMP

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.generators._netio import packet_sender
from trafficgoat.config import GeneratorConfig
from trafficgoat.stats import StatsCollector


class ICMPGenerator(BaseGenerator):
    """Generate ICMP traffic: echo requests, various ICMP types."""

    name = "icmp"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector, dry_run: bool = False):
        super().__init__(config, stats, dry_run)
        self.subtype = config.subtype or "echo"
        self.name = f"icmp:{self.subtype}"

    def generate(self):
        if self.subtype == "mixed":
            self._mixed_icmp()
        else:
            self._ping_flood()

    def _ping_flood(self):
        """Send ICMP echo requests (ping flood)."""
        self.stats.log(f"{self.name}: Ping flood to {self.target}")
        seq = 0
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                payload = os.urandom(random.randint(56, 512))
                pkt = IP(dst=self.target) / ICMP(
                    type=8, code=0, id=random.randint(1, 65535), seq=seq
                ) / payload
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                seq = (seq + 1) % 65536
                self.throttle()

    def _mixed_icmp(self):
        """Send various ICMP types."""
        icmp_types = [
            (8, 0, "Echo Request"),
            (3, 0, "Dest Unreachable - Net"),
            (3, 1, "Dest Unreachable - Host"),
            (3, 3, "Dest Unreachable - Port"),
            (11, 0, "Time Exceeded"),
            (5, 0, "Redirect - Network"),
            (13, 0, "Timestamp Request"),
            (17, 0, "Address Mask Request"),
        ]
        self.stats.log(f"{self.name}: Mixed ICMP types to {self.target}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                icmp_type, icmp_code, desc = random.choice(icmp_types)
                pkt = IP(dst=self.target) / ICMP(type=icmp_type, code=icmp_code) / os.urandom(56)
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()
