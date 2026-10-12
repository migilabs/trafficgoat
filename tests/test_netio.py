"""Tests for the reusable packet-send helper (trafficgoat.generators._netio).

These avoid real raw sockets by mocking scapy, so they run without root.
"""

from unittest import mock

from trafficgoat.generators import _netio


class _FakeSocket:
    """Records send()/close() calls."""

    def __init__(self):
        self.sent = []
        self.closed = False

    def send(self, pkt):
        self.sent.append(pkt)

    def close(self):
        self.closed = True


def test_dry_run_sender_is_noop():
    with _netio.packet_sender(dry_run=True) as send_pkt:
        # Accepts a single packet and a batch; sends nothing, raises nothing.
        send_pkt("pkt")
        send_pkt(["pkt1", "pkt2"])


def test_reuse_path_sends_single_and_batch_then_closes():
    fake = _FakeSocket()
    with mock.patch.object(_netio.conf, "L3socket", return_value=fake):
        with _netio.packet_sender(dry_run=False) as send_pkt:
            send_pkt("a")                 # single packet -> one send
            send_pkt(["b", "c", "d"])     # batch -> one send per packet
            assert not fake.closed, "socket must stay open for the lifetime"
    assert fake.sent == ["a", "b", "c", "d"]
    assert fake.closed, "socket must be closed on context exit"


def test_socket_closed_even_if_caller_raises():
    fake = _FakeSocket()
    with mock.patch.object(_netio.conf, "L3socket", return_value=fake):
        try:
            with _netio.packet_sender(dry_run=False) as send_pkt:
                send_pkt("a")
                raise RuntimeError("boom")
        except RuntimeError:
            pass
    assert fake.closed, "socket must be closed when the with-body raises"


def test_falls_back_to_module_send_when_socket_unavailable():
    """If a persistent socket can't be created, degrade to scapy's send()."""
    calls = []

    def fake_module_send(pkt, **kwargs):
        calls.append((pkt, kwargs))

    with mock.patch.object(_netio.conf, "L3socket", side_effect=OSError("no priv")):
        with mock.patch.object(_netio, "_scapy_send", fake_module_send):
            with _netio.packet_sender(dry_run=False) as send_pkt:
                send_pkt("single")
                send_pkt(["x", "y"])

    # Single packet and batch each map to one module-level send() call.
    assert calls[0][0] == "single"
    assert calls[1][0] == ["x", "y"]
    assert calls[1][1].get("inter") == 0
