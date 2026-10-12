"""Shared packet-send helper for the scapy-based generators.

scapy's module-level :func:`scapy.all.send` opens a fresh layer-3 socket on
*every* call and tears it down again when it returns. In a tight generation
loop that means one raw-socket open/close per packet (or per batch), which
wastes CPU and thrashes file descriptors at high rates.

:func:`packet_sender` hands back a ``send(pkt)`` callable backed by a single
socket held open for the generator's lifetime, removing that per-call churn.
It is a context manager so the socket is always closed, even on error:

    with packet_sender(self.dry_run) as send_pkt:
        while not self.should_stop():
            send_pkt(pkt)            # single packet
            send_pkt([pkt1, pkt2])   # or a batch

Behaviour is intentionally conservative:

* **dry-run** yields a no-op sender, so callers never special-case it.
* if a persistent socket can't be created (e.g. missing privileges on some
  platform), it falls back to scapy's module-level ``send`` so the tool keeps
  working — it just loses the efficiency gain. The reuse path never silently
  changes what is sent.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator

from scapy.all import conf, send as _scapy_send

# A sender accepts a single packet or an iterable (batch) of packets.
Sender = Callable[[object], None]


def _module_send(pkt) -> None:
    """Fallback sender using scapy's module-level send (socket per call)."""
    if isinstance(pkt, (list, tuple)):
        _scapy_send(pkt, verbose=0, inter=0)
    else:
        _scapy_send(pkt, verbose=0)


@contextmanager
def packet_sender(dry_run: bool) -> Iterator[Sender]:
    """Yield a ``send(pkt)`` callable backed by one reused L3 socket.

    Accepts either a single packet or a list/tuple of packets.
    """
    if dry_run:
        yield lambda pkt: None
        return

    sock = None
    try:
        sock = conf.L3socket()
    except Exception:
        sock = None

    if sock is None:
        # Could not hold a socket open; degrade to per-call sends.
        yield _module_send
        return

    try:
        def _send(pkt) -> None:
            if isinstance(pkt, (list, tuple)):
                for p in pkt:
                    sock.send(p)
            else:
                sock.send(pkt)

        yield _send
    finally:
        try:
            sock.close()
        except Exception:
            pass
