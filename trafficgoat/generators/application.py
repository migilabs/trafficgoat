"""Application layer traffic generator - FTP, SSH, SMTP simulation."""

import random
import socket
import time

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.config import GeneratorConfig
from trafficgoat.stats import StatsCollector


class ApplicationGenerator(BaseGenerator):
    """Generate application-layer traffic: FTP, SSH, SMTP connection simulations."""

    name = "application"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector, dry_run: bool = False):
        super().__init__(config, stats, dry_run)
        self.subtype = config.subtype or config.type
        if self.subtype in ("ftp", "ssh", "smtp", "application"):
            pass
        else:
            self.subtype = "mixed"
        self.name = f"app:{self.subtype}"

    def generate(self):
        if self.subtype == "ftp":
            self._ftp_sim()
        elif self.subtype == "ssh":
            self._ssh_sim()
        elif self.subtype == "smtp":
            self._smtp_sim()
        else:
            self._mixed_app()

    def _tcp_connect_send(self, port: int, data: bytes, recv: bool = True) -> int:
        """Connect, send data, optionally receive, return bytes transferred."""
        total_bytes = 0
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if not self.dry_run:
                sock.connect((self.target, port))
                if recv:
                    try:
                        banner = sock.recv(1024)
                        total_bytes += len(banner)
                    except socket.timeout:
                        pass
                sock.sendall(data)
                total_bytes += len(data)
                if recv:
                    try:
                        resp = sock.recv(4096)
                        total_bytes += len(resp)
                    except socket.timeout:
                        pass
            else:
                total_bytes = len(data)
            self.stats.update(self.name, packets=1, bytes_sent=total_bytes, connections=1)
        except (ConnectionRefusedError, socket.timeout, socket.gaierror, OSError):
            self.stats.update(self.name, packets=1, errors=1)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return total_bytes

    def _ftp_sim(self):
        """Simulate FTP login attempts."""
        self.stats.log(f"{self.name}: FTP simulation to {self.target}:21")
        users = ["admin", "root", "ftp", "anonymous", "user", "test", "backup"]
        passwords = ["admin", "password", "123456", "root", "ftp", "anonymous", "test123"]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            user = random.choice(users)
            passwd = random.choice(passwords)
            self._tcp_connect_send(21, f"USER {user}\r\nPASS {passwd}\r\nQUIT\r\n".encode())
            self.throttle()

    def _ssh_sim(self):
        """Simulate SSH connection attempts (banner grab + version exchange)."""
        self.stats.log(f"{self.name}: SSH simulation to {self.target}:22")
        client_versions = [
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "SSH-2.0-OpenSSH_9.0",
            "SSH-2.0-PuTTY_Release_0.80",
            "SSH-2.0-libssh2_1.11.0",
            "SSH-2.0-paramiko_3.4.0",
        ]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            version = random.choice(client_versions)
            self._tcp_connect_send(22, f"{version}\r\n".encode())
            self.throttle()

    def _smtp_sim(self):
        """Simulate SMTP connection attempts."""
        self.stats.log(f"{self.name}: SMTP simulation to {self.target}:25")
        senders = ["test@example.com", "admin@local.host", "user@mail.test", "noreply@spam.test"]
        recipients = ["admin@target.local", "root@target.local", "info@target.local"]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            sender = random.choice(senders)
            rcpt = random.choice(recipients)
            smtp_data = (
                f"EHLO mail.example.com\r\n"
                f"MAIL FROM:<{sender}>\r\n"
                f"RCPT TO:<{rcpt}>\r\n"
                f"QUIT\r\n"
            )
            self._tcp_connect_send(25, smtp_data.encode())
            self.throttle()

    def _mixed_app(self):
        """Randomly alternate between FTP, SSH, SMTP (one connection per cycle).

        Do NOT reassign ``self.name`` here. The generator registered itself with
        StatsCollector under the stable ``app:mixed`` name in ``start()``; writing
        ``app:ftp`` / ``app:ssh`` / ``app:smtp`` into ``self.name`` would send
        every ``stats.update()`` to a name that was never registered, so the
        counts would be silently dropped and the generator would never be
        unregistered under its real name on stop.
        """
        self.stats.log(f"{self.name}: Mixed application traffic to {self.target}")
        # (port, payload factory) for each application protocol in the mix.
        variants = [
            (21, lambda: "USER {}\r\nPASS test\r\nQUIT\r\n".format(
                random.choice(["admin", "root", "ftp", "anonymous"])).encode()),
            (22, lambda: b"SSH-2.0-OpenSSH_9.0\r\n"),
            (25, lambda: b"EHLO test\r\nQUIT\r\n"),
        ]
        start = time.monotonic()
        while not self.should_stop():
            if self.deadline_reached(start):
                break
            port, make_payload = random.choice(variants)
            self._tcp_connect_send(port, make_payload())
            self.throttle()
