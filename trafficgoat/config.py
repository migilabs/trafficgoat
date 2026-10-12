"""Configuration loading and validation for TrafficGoat."""

import yaml
from dataclasses import dataclass, field
from typing import Optional


# Bounds for user-supplied numeric config. Generous but finite.
MAX_RATE = 1_000_000          # packets per second
MAX_THREADS = 256
MAX_DURATION = 86_400         # 1 day
MAX_PORT = 65_535


class ConfigError(ValueError):
    """Raised when a TrafficConfig fails validation."""


@dataclass
class GeneratorConfig:
    """Configuration for a single traffic generator."""
    type: str
    target: str = ""
    ports: str = "80"
    rate: int = 100
    weight: float = 1.0
    duration: int = 60
    count: int = 0  # 0 = unlimited (use duration)
    # HTTP-specific
    urls: list = field(default_factory=list)
    methods: list = field(default_factory=lambda: ["GET"])
    # Application-specific
    subtype: str = ""  # ftp, ssh, smtp, portscan, bruteforce
    # Extra kwargs
    options: dict = field(default_factory=dict)
    # Safety: allow this generator to run aggressive/malicious patterns
    enable_malicious: bool = False


@dataclass
class TrafficConfig:
    """Main traffic configuration."""
    target: str = "127.0.0.1"
    ports: str = "80"
    duration: int = 60
    rate: int = 100
    threads: int = 4
    interface: Optional[str] = None
    verbose: bool = False
    quiet: bool = False
    dry_run: bool = False
    mode: str = "stress"
    protocol: str = ""
    generators: list = field(default_factory=list)
    # Auto-mode load level (light / medium / heavy). Was a dynamic attribute.
    auto_load: str = "medium"
    # Safety flags
    allow_public: bool = False
    enable_malicious: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "TrafficConfig":
        """Create config from dictionary.

        Does not mutate ``data`` (previously ``generators`` was popped out of
        the caller's dict as a side effect).
        """
        generators = [GeneratorConfig(**gen_data) for gen_data in data.get("generators", [])]
        config = cls(**{
            k: v for k, v in data.items()
            if k != "generators" and k in cls.__dataclass_fields__
        })
        config.generators = generators
        return config

    @classmethod
    def from_yaml(cls, path: str) -> "TrafficConfig":
        """Load config from YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_args(cls, args) -> "TrafficConfig":
        """Create config from argparse namespace."""
        config = cls(
            target=getattr(args, "target", "127.0.0.1"),
            ports=getattr(args, "ports", "80"),
            duration=getattr(args, "duration", 60),
            rate=getattr(args, "rate", 100),
            threads=getattr(args, "threads", 4),
            interface=getattr(args, "interface", None),
            verbose=getattr(args, "verbose", False),
            quiet=getattr(args, "quiet", False),
            dry_run=getattr(args, "dry_run", False),
            mode=getattr(args, "mode", "stress"),
            protocol=getattr(args, "protocol", ""),
            allow_public=getattr(args, "allow_public", False),
            enable_malicious=getattr(args, "enable_malicious", False),
        )
        # Load from config file if specified
        config_file = getattr(args, "config", None)
        if config_file:
            file_config = cls.from_yaml(config_file)
            # CLI args override file config for explicitly set values
            if not args.target and file_config.target:
                config.target = file_config.target
            config.generators = file_config.generators
        return config

    def validate(self) -> None:
        """Range-check user-supplied numeric fields. Raises ConfigError on failure.

        Target allowlist enforcement lives in `trafficgoat.safety.check_target`
        and is called separately so it can be skipped in pure dry-run unit
        tests if needed.
        """
        if not (1 <= self.rate <= MAX_RATE):
            raise ConfigError(f"rate must be 1..{MAX_RATE}, got {self.rate}")
        if not (1 <= self.threads <= MAX_THREADS):
            raise ConfigError(f"threads must be 1..{MAX_THREADS}, got {self.threads}")
        # duration=0 means "run until stopped"; allow it explicitly.
        if not (0 <= self.duration <= MAX_DURATION):
            raise ConfigError(f"duration must be 0..{MAX_DURATION}, got {self.duration}")
        if self.ports:
            for p in parse_ports(self.ports):
                if not (1 <= p <= MAX_PORT):
                    raise ConfigError(f"port out of range: {p}")


def parse_ports(port_str: str) -> list[int]:
    """Parse port string like '80', '1-1024', '80,443,8080' into list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports
