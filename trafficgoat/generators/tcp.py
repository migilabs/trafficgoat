"""TCP traffic generator - SYN flood, full connect, custom flags."""

import random
import socket
import time

from scapy.all import IP, TCP, RandShort

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.generators._netio import packet_sender
from trafficgoat.config import GeneratorConfig, parse_ports
from trafficgoat.stats import StatsCollector


class TCPGenerator(BaseGenerator):
    """Generate TCP traffic: SYN floods, full connections, custom flag packets."""

    name = "tcp"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector, dry_run: bool = False):
        super().__init__(config, stats, dry_run)
        self.subtype = config.subtype or config.type  # tcp_syn, tcp_connect, tcp
        self.name = f"tcp:{self.subtype}"
        self.port_list = parse_ports(self.ports)

    def generate(self):
        if "syn" in self.subtype or self.subtype == "tcp":
            self._syn_flood()
        elif "connect" in self.subtype:
            self._full_connect()
        elif "xmas" in self.subtype:
            self._flag_scan("FPU")  # FIN+PSH+URG
        elif "fin" in self.subtype:
            self._flag_scan("F")
        elif "null" in self.subtype:
            self._flag_scan("")
        elif "rst" in self.subtype:
            self._flag_scan("R")
        else:
            self._syn_flood()

    def _syn_flood(self):
        """Send TCP SYN packets using scapy."""
        self.stats.log(f"{self.name}: SYN flood to {self.target} ports {self.ports}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                port = random.choice(self.port_list)
                pkt = IP(dst=self.target) / TCP(
                    sport=int(RandShort()),
                    dport=port,
                    flags="S",
                    seq=random.randint(0, 2**32 - 1),
                )
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()

    def _full_connect(self):
        """Full TCP connect using socket."""
        self.stats.log(f"{self.name}: Full connect to {self.target} ports {self.ports}")
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            port = random.choice(self.port_list)
            sock: socket.socket | None = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if not self.dry_run:
                    sock.connect((self.target, port))
                    self.stats.update(self.name, packets=1, bytes_sent=64, connections=1)
                else:
                    self.stats.update(self.name, packets=1, bytes_sent=64)
            except (ConnectionRefusedError, socket.timeout, socket.gaierror, OSError):
                self.stats.update(self.name, packets=1, errors=1)
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self.throttle()

    def _flag_scan(self, flags: str):
        """Send TCP packets with custom flags."""
        flag_name = flags if flags else "NULL"
        self.stats.log(f"{self.name}: {flag_name} scan to {self.target} ports {self.ports}")
        start = time.monotonic()
        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break
                port = random.choice(self.port_list)
                pkt = IP(dst=self.target) / TCP(
                    sport=int(RandShort()),
                    dport=port,
                    flags=flags,
                )
                send_pkt(pkt)
                self.stats.update(self.name, packets=1, bytes_sent=len(pkt))
                self.throttle()
