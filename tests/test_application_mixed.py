"""Regression test: ApplicationGenerator mixed subtype must report stats
under the name it registered with.

Before the fix, ``_mixed_app`` rewrote ``self.name`` to ``app:ftp`` /
``app:ssh`` / ``app:smtp`` mid-loop. Those names were never registered with
the StatsCollector, so every ``stats.update()`` was silently dropped and the
``mixed`` subtype (used by ``mixed`` mode's application layer) reported zero
traffic.
"""

from trafficgoat.config import GeneratorConfig
from trafficgoat.generators.application import ApplicationGenerator
from trafficgoat.stats import StatsCollector


def test_mixed_app_counts_under_registered_name(monkeypatch):
    cfg = GeneratorConfig(
        type="application", subtype="mixed",
        target="127.0.0.1", rate=1000, duration=60,
    )
    stats = StatsCollector()
    gen = ApplicationGenerator(cfg, stats, dry_run=True)
    registered_name = gen.name
    assert registered_name == "app:mixed"
    stats.register_generator(registered_name)
    stats.start()

    # Stop the loop deterministically after the first connection.
    real_send = gen._tcp_connect_send

    def stop_after_one(port, data, recv=True):
        result = real_send(port, data, recv=recv)
        gen.signal_stop()
        return result

    monkeypatch.setattr(gen, "_tcp_connect_send", stop_after_one)

    gen.generate()  # runs in this thread, stops after one cycle

    # Name must not have drifted off the registered value.
    assert gen.name == "app:mixed"

    snapshot = stats.get_stats()["generators"]
    assert "app:mixed" in snapshot
    assert snapshot["app:mixed"]["packets_sent"] >= 1, (
        "mixed application traffic must be counted under app:mixed"
    )
