"""CLI interface for TrafficGoat."""

import argparse
import os
import sys

from trafficgoat import __version__
from trafficgoat.config import TrafficConfig, ConfigError
from trafficgoat.engine import TrafficEngine
from trafficgoat.stats import StatsCollector
from trafficgoat.modes import MODES
from trafficgoat.safety import check_target, UnsafeTargetError


BANNER = r"""
  _____ _____  ___  _____ _____ _____ _____  _____ _____  ___  _____
 |_   _| ___ \/ _ \|  ___|  ___|_   _/  __ \|  __ \  _  |/ _ \|_   _|
   | | | |_/ / /_\ \ |_  | |_    | | | /  \/| |  \/ | | / /_\ \ | |
   | | |    /|  _  |  _| |  _|   | | | |    | | __| | | |  _  | | |
   | | | |\ \| | | | |   | |    _| |_| \__/\| |_\ \ \_/ / | | | | |
   \_/ \_| \_\_| |_\_|   \_|    \___/ \____/ \____/\___/\_| |_/ \_/
"""


def format_bytes(n: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_stats(stats_data: dict, quiet: bool = False):
    """Print live stats to terminal."""
    if quiet:
        return
    sys.stdout.write("\r\033[K")
    sys.stdout.write(
        f"  Packets: {stats_data['total_packets']:>8,}  |  "
        f"Rate: {stats_data['total_pps']:>8,.1f} pps  |  "
        f"Data: {format_bytes(stats_data['total_bytes']):>10}  |  "
        f"Errors: {stats_data['total_errors']:>6}  |  "
        f"Time: {stats_data['elapsed']:>6.1f}s"
    )
    sys.stdout.flush()


def _add_safety_flags(parser: argparse.ArgumentParser) -> None:
    """Add --allow-public / --enable-malicious to a subparser."""
    parser.add_argument(
        "--allow-public", action="store_true",
        help="Permit non-private target IPs (default: only loopback/RFC1918/link-local).",
    )
    parser.add_argument(
        "--enable-malicious", action="store_true",
        help="Permit MaliciousGenerator subtypes (bruteforce/ddos/amplification). "
             "Off by default; portscan is allowed without this flag.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trafficgoat",
        description="TrafficGoat - Advanced network traffic generator for firewall testing and log generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo trafficgoat auto -l heavy -d 300
  sudo trafficgoat auto -l light -d 60
  sudo trafficgoat stress -t 192.168.1.1 -d 60 -r 500
  sudo trafficgoat scan -t 10.0.0.1 -p 1-1024
  sudo trafficgoat protocol -t 192.168.1.1 --protocol icmp -d 30
  sudo trafficgoat mixed -t 192.168.1.1 -r 200 -d 120
  sudo trafficgoat stealth -t 192.168.1.1 -d 300
  sudo trafficgoat custom -t 192.168.1.1 -c config.yaml
  sudo trafficgoat web --web-port 8080
        """,
    )

    parser.add_argument("--version", action="version", version=f"trafficgoat {__version__}")

    subparsers = parser.add_subparsers(dest="mode", help="Traffic generation mode")

    # Common arguments for all modes
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    common.add_argument("-p", "--ports", default="80", help="Ports: single, range (1-1024), or comma-separated (default: 80)")
    common.add_argument("-d", "--duration", type=int, default=60, help="Duration in seconds (default: 60)")
    common.add_argument("-r", "--rate", type=int, default=100, help="Packets per second (default: 100)")
    common.add_argument("--threads", type=int, default=4, help="Worker threads (default: 4)")
    common.add_argument("-i", "--interface", help="Network interface to use")
    common.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    common.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    common.add_argument("--dry-run", action="store_true", help="Show what would be generated without sending")
    _add_safety_flags(common)

    # Mode subcommands
    subparsers.add_parser("stress", parents=[common], help="High-volume stress test")
    subparsers.add_parser("scan", parents=[common], help="Port scanning simulation")
    subparsers.add_parser("mixed", parents=[common], help="Realistic mixed traffic")

    proto_parser = subparsers.add_parser("protocol", parents=[common], help="Single protocol test")
    proto_parser.add_argument(
        "--protocol", default="tcp",
        choices=["tcp", "tcp_syn", "tcp_connect", "udp", "icmp", "http", "dns", "ftp", "ssh", "smtp"],
        help="Protocol to test (default: tcp)",
    )

    subparsers.add_parser("stealth", parents=[common], help="Low-and-slow attack simulation")

    custom_parser = subparsers.add_parser("custom", parents=[common], help="Custom config from YAML")
    custom_parser.add_argument("-c", "--config", required=True, help="YAML configuration file")

    # Auto mode (no target required)
    auto_common = argparse.ArgumentParser(add_help=False)
    auto_common.add_argument("-d", "--duration", type=int, default=120, help="Duration in seconds (default: 120)")
    auto_common.add_argument("--dry-run", action="store_true", help="Show what would be generated without sending")
    auto_common.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    auto_common.add_argument("-q", "--quiet", action="store_true", help="Minimal output")
    _add_safety_flags(auto_common)

    auto_parser = subparsers.add_parser("auto", parents=[auto_common], help="Zero-config multi-destination traffic")
    auto_parser.add_argument(
        "-l", "--load", default="medium",
        choices=["light", "medium", "heavy"],
        help="Load level (default: medium)",
    )

    # Web UI mode
    web_parser = subparsers.add_parser("web", help="Start the Web UI")
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1; use 0.0.0.0 with care)")
    web_parser.add_argument("--web-port", type=int, default=8080, help="Web UI port (default: 8080)")
    web_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    web_parser.add_argument("--dev", action="store_true",
                            help="Enable the Werkzeug debugger (development only).")
    _add_safety_flags(web_parser)

    return parser


def _validate_and_check(config: TrafficConfig, *, quiet: bool = False) -> None:
    """Run validate() and the target allowlist; exit(2) on failure."""
    try:
        config.validate()
    except ConfigError as e:
        print(f"[!] Invalid configuration: {e}")
        sys.exit(2)
    try:
        check_target(config.target, allow_public=config.allow_public)
    except UnsafeTargetError as e:
        print(f"[!] {e}")
        sys.exit(2)
    if not quiet and config.allow_public and config.target not in ("0.0.0.0", ""):
        print(f"[!] --allow-public is set: traffic will be sent to {config.target}")


def run_cli(args):
    """Run traffic generation in CLI mode."""
    if args.mode == "auto":
        # Auto mode targets a built-in pool of public domains. The user opting
        # into `auto` is opting into public targets by definition.
        config = TrafficConfig(
            target="0.0.0.0",
            duration=getattr(args, "duration", 120),
            dry_run=getattr(args, "dry_run", False),
            mode="auto",
            verbose=getattr(args, "verbose", False),
            quiet=getattr(args, "quiet", False),
            allow_public=True,
            enable_malicious=getattr(args, "enable_malicious", False),
        )
        config.auto_load = getattr(args, "load", "medium")
    else:
        config = TrafficConfig.from_args(args)
    if config.mode == "scan":
        # Port scanning is the whole point of `scan` mode.
        config.enable_malicious = True

    _validate_and_check(config, quiet=config.quiet)

    stats = StatsCollector()

    # Setup live stats printing
    if not config.quiet:
        stats.on_stats(lambda s: print_stats(s, config.quiet))
    if config.verbose:
        stats.on_log(lambda msg: print(f"\n  {msg}"))

    mode_class = MODES.get(config.mode)
    if not mode_class:
        print(f"[!] Unknown mode: {config.mode}")
        sys.exit(1)

    engine = TrafficEngine(config, stats)
    mode_class.configure(config, engine, stats)
    # Propagate enable_malicious to gated generators created by the mode.
    for gen in engine._generators:
        if hasattr(gen, "config"):
            gen.config.enable_malicious = config.enable_malicious
            if hasattr(gen, "enable_malicious"):
                gen.enable_malicious = config.enable_malicious

    if not config.quiet:
        print(f"\n  Mode: {mode_class.name} - {mode_class.description}")
        print(f"  Target: {config.target}")
        print(f"  Duration: {config.duration}s | Rate: {config.rate} pps | Dry-run: {config.dry_run}")
        print(f"  {'=' * 70}")
        print()

    engine.start()
    engine.wait()

    # Final stats
    final = stats.get_stats()
    if not config.quiet:
        print("\n")
        print(f"  {'=' * 70}")
        print(f"  Final Results:")
        print(f"  Packets sent:  {final['total_packets']:>12,}")
        print(f"  Data sent:     {format_bytes(final['total_bytes']):>12}")
        print(f"  Errors:        {final['total_errors']:>12,}")
        print(f"  Duration:      {final['elapsed']:>11.1f}s")
        print(f"  Avg rate:      {final['total_pps']:>11.1f} pps")
        print(f"  {'=' * 70}")


def run_web(args):
    """Start the Web UI."""
    from trafficgoat.web.app import create_app, socketio

    host = args.host
    port = args.web_port

    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] WARNING: binding to {host} exposes the web UI on the network.")
        print(f"[!] Anyone who can reach this host can launch root-privileged traffic.")
        if not args.allow_public:
            print(f"[!] Targets are still restricted to private IPs unless --allow-public is set.")

    if not args.verbose:
        print(BANNER)
    print(f"  Starting TrafficGoat Web UI on http://{host}:{port}")
    print(f"  Press Ctrl+C to stop\n")

    app = create_app(
        allow_public=args.allow_public,
        enable_malicious=args.enable_malicious,
        host=host,
        port=port,
    )
    # In threading async mode, Flask-SocketIO serves requests through Werkzeug's
    # WSGI server (with threaded=True). That's fine for this local, root-run
    # testing tool, but Werkzeug refuses to start outside an interactive TTY
    # (e.g. under systemd/Docker) unless we opt in, so pass
    # allow_unsafe_werkzeug=True. --dev turns on the Werkzeug debugger; the
    # auto-reloader stays off so a root process holding raw sockets never
    # re-execs itself mid-run.
    socketio.run(app, host=host, port=port, debug=bool(args.dev),
                 use_reloader=False, allow_unsafe_werkzeug=True)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.mode:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    # Check root for non-web modes (raw sockets need root)
    if args.mode not in ("web",) and os.geteuid() != 0:
        print("[!] TrafficGoat requires root privileges for raw socket access.")
        print("[!] Run with: sudo trafficgoat ...")
        sys.exit(1)

    if args.mode == "web":
        run_web(args)
    else:
        if not getattr(args, "quiet", False):
            print(BANNER)
        run_cli(args)


if __name__ == "__main__":
    main()
