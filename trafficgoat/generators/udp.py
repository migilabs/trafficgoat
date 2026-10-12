"""UDP traffic generator - random payloads, DNS, NTP."""

import os
import random
import time

from scapy.all import IP, UDP, DNS, DNSQR, NTP, RandShort

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.generators._netio import packet_sender
from trafficgoat.config import GeneratorConfig, parse_ports
from trafficgoat.stats import StatsCollector


class UDPGenerator(BaseGenerator):
    """Generate UDP traffic: random payloads, DNS queries, NTP requests."""

    name = "udp"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector, dry_run: bool = False):
        super().__init__(config, stats, dry_run)
        self.subtype = config.subtype or "random"
        self.name = f"udp:{self.subtype}"
        self.port_list = parse_ports(self.ports)

    def generate(self):
        if self.subtype == "dns":
            self._dns_queries()
        elif self.subtype == "ntp":
            self._ntp_requests()
        else:
            self._random_udp()

    def _random_udp(self):
        """Send random UDP packets."""
        self.stats.log(f"{self.name}: Random UDP to {self.target} ports {self.ports}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                port = random.choice(self.port_list)
                payload = os.urandom(random.randint(512, 1400))
                pkt = IP(dst=self.target) / UDP(
                    sport=int(RandShort()),
                    dport=port,
                ) / payload
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()

    def _dns_queries(self):
        """Send DNS query packets."""
        domains = [
            "example.com", "google.com", "github.com", "test.local",
            "mail.example.org", "ns1.example.net", "ftp.test.com",
            "admin.internal.local", "api.service.io", "cdn.static.net",
        ]
        self.stats.log(f"{self.name}: DNS queries to {self.target}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                domain = random.choice(domains)
                qtype = random.choice(["A", "AAAA", "MX", "NS", "TXT", "CNAME"])
                pkt = IP(dst=self.target) / UDP(dport=53) / DNS(
                    rd=1, qd=DNSQR(qname=domain, qtype=qtype)
                )
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()

    def _ntp_requests(self):
        """Send NTP requests."""
        self.stats.log(f"{self.name}: NTP requests to {self.target}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                pkt = IP(dst=self.target) / UDP(dport=123) / NTP(version=3)
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()
