"""DNS traffic generator - valid queries, random subdomains, NXDOMAIN flood."""

import random
import string
import time

from scapy.all import IP, UDP, DNS, DNSQR

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.generators._netio import packet_sender
from trafficgoat.config import GeneratorConfig
from trafficgoat.stats import StatsCollector

VALID_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "reddit.com", "twitter.com", "linkedin.com", "netflix.com",
    "cloudflare.com", "debian.org", "ubuntu.com", "kernel.org",
]

QUERY_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]


class DNSGenerator(BaseGenerator):
    """Generate DNS traffic: valid queries, random subdomains, NXDOMAIN floods."""

    name = "dns"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector, dry_run: bool = False):
        super().__init__(config, stats, dry_run)
        self.subtype = config.subtype or "mixed"
        self.name = f"dns:{self.subtype}"
        # Set for the duration of generate() so the per-query helper can reuse
        # a single socket instead of opening one per packet.
        self._send_pkt = None

    def generate(self):
        with packet_sender(self.dry_run) as send_pkt:
            self._send_pkt = send_pkt
            if self.subtype == "valid":
                self._valid_queries()
            elif self.subtype == "random":
                self._random_subdomain()
            elif self.subtype == "nxdomain":
                self._nxdomain_flood()
            else:
                self._mixed_dns()

    def _send_dns_query(self, domain: str, qtype: str = "A"):
        """Send a single DNS query packet (only valid while generate() runs)."""
        pkt = IP(dst=self.target) / UDP(dport=53, sport=random.randint(1024, 65535)) / DNS(
            id=random.randint(0, 65535),
            rd=1,
            qd=DNSQR(qname=domain, qtype=qtype),
        )
        self._send_pkt(pkt)
        self.stats.update(self.name, packets=1, bytes_sent=len(pkt))

    def _valid_queries(self):
        """Send queries for well-known domains."""
        self.stats.log(f"{self.name}: Valid DNS queries to {self.target}")
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            domain = random.choice(VALID_DOMAINS)
            qtype = random.choice(QUERY_TYPES[:4])
            self._send_dns_query(domain, qtype)
            self.throttle()

    def _random_subdomain(self):
        """Send queries with random subdomains (triggers DNS amplification patterns)."""
        self.stats.log(f"{self.name}: Random subdomain queries to {self.target}")
        base_domains = ["example.com", "test.local", "internal.corp"]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8, 24)))
            domain = f"{sub}.{random.choice(base_domains)}"
            self._send_dns_query(domain, random.choice(QUERY_TYPES))
            self.throttle()

    def _nxdomain_flood(self):
        """Send queries for non-existent domains."""
        self.stats.log(f"{self.name}: NXDOMAIN flood to {self.target}")
        tlds = [".xyz", ".invalid", ".nxdomain", ".fake", ".notreal"]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 16)))
            domain = name + random.choice(tlds)
            self._send_dns_query(domain, "A")
            self.throttle()

    def _mixed_dns(self):
        """Mix of all DNS query types."""
        self.stats.log(f"{self.name}: Mixed DNS queries to {self.target}")
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            choice = random.random()
            if choice < 0.4:
                domain = random.choice(VALID_DOMAINS)
                qtype = random.choice(QUERY_TYPES[:4])
            elif choice < 0.7:
                sub = ''.join(random.choices(string.ascii_lowercase, k=12))
                domain = f"{sub}.example.com"
                qtype = random.choice(QUERY_TYPES)
            else:
                domain = ''.join(random.choices(string.ascii_lowercase, k=10)) + ".invalid"
                qtype = "A"
            self._send_dns_query(domain, qtype)
            self.throttle()
