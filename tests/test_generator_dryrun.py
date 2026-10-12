"""Dry-run smoke tests: scapy generators count packets without sending.

These exercise the packet_sender dry-run path end-to-end inside real
generators, so they need neither root nor a network.
"""

from trafficgoat.config import GeneratorConfig
from trafficgoat.generators.icmp import ICMPGenerator
from trafficgoat.generators.tcp import TCPGenerator
from trafficgoat.stats import StatsCollector


def _run_one_cycle(gen, stats, monkeypatch):
    """Register, then run generate() stopping after the first throttle()."""
    stats.register_generator(gen.name)
    stats.start()
    monkeypatch.setattr(gen, "throttle", gen.signal_stop)
    gen.generate()
    return stats.get_stats()["generators"]


def test_icmp_dryrun_counts_packets(monkeypatch):
    cfg = GeneratorConfig(type="icmp", subtype="echo", target="127.0.0.1",
                          rate=1000, duration=60)
    stats = StatsCollector()
    gen = ICMPGenerator(cfg, stats, dry_run=True)
    snap = _run_one_cycle(gen, stats, monkeypatch)
    assert snap[gen.name]["packets_sent"] >= 1
    assert snap[gen.name]["bytes_sent"] > 0


def test_tcp_syn_dryrun_counts_packets(monkeypatch):
    cfg = GeneratorConfig(type="tcp_syn", subtype="syn", target="127.0.0.1",
                          ports="80,443", rate=1000, duration=60)
    stats = StatsCollector()
    gen = TCPGenerator(cfg, stats, dry_run=True)
    snap = _run_one_cycle(gen, stats, monkeypatch)
    assert snap[gen.name]["packets_sent"] >= 1
    assert snap[gen.name]["bytes_sent"] > 0
