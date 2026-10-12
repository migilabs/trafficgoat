# CLAUDE.md - TrafficGoat Development Guide

> **Documentation policy (read first):** any code change that adds, removes
> or renames a generator, mode, CLI flag, web endpoint, env var, dependency,
> or that bumps the version MUST update **this file**, **README.md**, and —
> if user-visible — `configs/example.yaml`. See "Keeping docs in sync" at
> the bottom for the exact checklist.

## Project Overview

TrafficGoat is an advanced network traffic generator for Linux designed for authorized firewall testing, IDS/IPS validation, and log generation. It generates realistic multi-protocol traffic via CLI or a real-time web dashboard.

Current version: **see `trafficgoat/__init__.py`** (single source of truth; `setup.py` reads it dynamically). Do not duplicate the version anywhere else.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run web UI (requires root for raw sockets)
sudo trafficgoat web --web-port 8080

# Run CLI auto mode
sudo trafficgoat auto -l heavy -d 120

# Dry run (no packets sent, good for testing)
sudo trafficgoat stress -t 127.0.0.1 --dry-run
```

## Project Structure

```
trafficgoat/
├── trafficgoat/              # Main package
│   ├── __init__.py           # __version__ (source of truth)
│   ├── __main__.py           # Entry point
│   ├── cli.py                # CLI argument parsing and execution
│   ├── config.py             # TrafficConfig / GeneratorConfig dataclasses
│   ├── engine.py             # TrafficEngine - orchestrates generators
│   ├── stats.py              # StatsCollector - thread-safe stats aggregation
│   ├── safety.py             # Target allowlist (RFC1918/loopback) + UnsafeTargetError
│   ├── generators/           # Traffic generator implementations
│   │   ├── base.py           # BaseGenerator ABC (threading, throttling)
│   │   ├── _netio.py         # packet_sender(): reused L3 socket for scapy generators
│   │   ├── tcp.py            # TCP SYN, connect, flag scans
│   │   ├── udp.py            # UDP random, DNS, NTP
│   │   ├── icmp.py           # ICMP echo, mixed types
│   │   ├── http.py           # HTTP/HTTPS requests
│   │   ├── dns.py            # DNS queries (A, AAAA, MX, etc.)
│   │   ├── application.py    # FTP, SSH, SMTP simulation
│   │   ├── malicious.py      # Port scans, brute force, DDoS patterns (gated)
│   │   └── auto.py           # Auto-mode: raw / bulk / http / curl / saas / tcp-connect
│   ├── modes/                # Traffic generation modes
│   │   ├── stress.py         # High-volume stress test
│   │   ├── scan.py           # Port scanning simulation
│   │   ├── mixed.py          # Realistic mixed traffic
│   │   ├── protocol.py       # Single protocol test
│   │   ├── stealth.py        # Low-and-slow evasion
│   │   ├── custom.py         # YAML-configured
│   │   └── auto.py           # Zero-config multi-destination
│   └── web/                  # Flask + Socket.IO web UI
│       ├── app.py            # Flask factory, Socket.IO setup, auth token wiring
│       ├── routes.py         # REST API + /metrics + Socket.IO events
│       ├── templates/        # Jinja2 HTML templates (dashboard / generate / modes / logs)
│       └── static/           # CSS + JavaScript
├── configs/
│   └── example.yaml          # Example YAML configuration
├── docs/
│   ├── architecture.svg      # Architecture diagram (referenced from README)
│   └── logo.svg              # Project logo
├── tests/                    # Test suite (pytest)
├── setup.py                  # Package setup (reads __version__ from package)
├── requirements.txt          # Python dependencies
└── install.sh                # Installation script
```

## Architecture

The system follows a layered architecture:

1. **CLI/Web Layer** - User interfaces (argparse CLI or Flask web dashboard)
2. **Safety Layer** - `safety.check_target()` enforces the private-IP allowlist before any generator starts
3. **Engine Layer** - `TrafficEngine` orchestrates generators in background threads
4. **Mode Layer** - Mode classes configure which generators to use and at what rates
5. **Generator Layer** - `BaseGenerator` subclasses produce packets using Scapy/requests/sockets
6. **Stats Layer** - `StatsCollector` aggregates metrics thread-safely, broadcasts via Socket.IO

### Key Data Flow
```
User Input (CLI/Web) -> safety.check_target() -> Mode.configure() -> Engine.add_generator()
Generator threads -> stats.update() -> StatsCollector -> Socket.IO -> Dashboard / /metrics
```

## Key Files to Understand

- **`engine.py`** - Central orchestrator. Starts/stops generators, runs stats loop.
- **`stats.py`** - Thread-safe statistics. Uses locks, supports callbacks for real-time broadcasting.
- **`safety.py`** - `check_target()` / `UnsafeTargetError`. Default-denies non-private IPs; `--allow-public` opts in. Hostnames that resolve to a mix of public+private are rejected.
- **`generators/base.py`** - Abstract base with `generate()`, `throttle()`, `should_stop()`.
- **`generators/_netio.py`** - `packet_sender(dry_run)` context manager: hands back a `send(pkt)` callable backed by a single reused scapy L3 socket (avoids a socket open/close per packet). No-op in dry-run; falls back to scapy's module-level `send()` if a persistent socket can't be created.
- **`generators/auto.py`** - Multi-destination generators: `AutoRawGenerator`, `AutoBulkGenerator`, `AutoHTTPGenerator`, `AutoTCPConnectGenerator`, `AutoCurlGenerator`, `AutoSaaSGenerator`. `AutoRawGenerator` builds 18 raw protocols: TCP SYN, UDP, ICMP, DNS, NTP, SNMP, SIP, LDAP, RADIUS, MQTT, Syslog, Memcached, Modbus, BGP, QUIC, STUN, Kerberos, NetFlow.
- **`generators/malicious.py`** - Aggressive patterns (bruteforce / ddos / amplification). Gated behind `enable_malicious=True` (CLI: `--enable-malicious`); `portscan` is allowed without the flag.
- **`modes/auto.py`** - Load presets (light/medium/heavy) with tuned rates and batch sizes.
- **`web/app.py`** - Flask factory with Socket.IO; reads `TRAFFICGOAT_TOKEN` / `TRAFFICGOAT_SECRET_KEY`; auto-generates an auth token if neither is set.
- **`web/routes.py`** - REST API (`/api/start`, `/api/stop`, `/api/status`, `/api/modes`, `/api/logs`, `/api/history`, `/api/version`) + `/metrics` (Prometheus) + Socket.IO events. All endpoints require the bearer token (X-Auth-Token, `Authorization: Bearer …`, or `?token=`) unless auth is explicitly disabled.
- **`web/static/js/app.js`** - Dashboard JS with Socket.IO client + HTTP polling fallback.

## CLI Surface (keep README in sync)

Modes: `stress`, `scan`, `mixed`, `protocol`, `stealth`, `custom`, `auto`, `web`.

Common safety flags (most modes):
- `--allow-public` — permit non-private targets (default: deny).
- `--enable-malicious` — permit gated `malicious` subtypes (bruteforce/ddos/amplification).

Web flags: `--host`, `--web-port`, `--dev` (unsafe werkzeug dev server), plus the safety flags above.

Web environment variables:
- `TRAFFICGOAT_TOKEN` — set the API auth token. If unset, one is generated and
  written to a `0600` file (path printed at startup; the token itself is **never**
  printed to stdout). Set to empty string to disable auth (warning printed).
- `TRAFFICGOAT_SECRET_KEY` — Flask session secret (auto-generated if unset).
- `TRAFFICGOAT_CORS_ORIGINS` — comma-separated Socket.IO CORS allowlist (or
  `*`). Defaults to the configured `host:port`; `--allow-public` does *not*
  widen this.

Web API hardening:
- Rate limits (per-token-or-IP, per-endpoint, in-memory sliding window):
  `/api/start` 3/10s · `/api/stop` 5/10s · `/api/logs` 30/5s · `/api/history` 30/5s.
  Excess requests return `429` with a `Retry-After` header.
- Request body capped at 1 MiB (`MAX_CONTENT_LENGTH`).

## Development Notes

### Adding a New Generator
1. Create a class extending `BaseGenerator` in `generators/`.
2. Implement `generate()` with a loop that checks `self.should_stop()`.
3. Call `self.stats.update(self.name, packets=N, bytes_sent=N)` for each batch.
4. Call `self.throttle()` for rate limiting.
5. Register in `generators/__init__.py` `GENERATORS` dict and `__all__`.
6. **Update docs** (see "Keeping docs in sync").

### Adding a New Mode
1. Create a class in `modes/` with `name`, `description`, and `configure()` static method.
2. `configure()` creates `GeneratorConfig` instances and adds generators to the engine.
3. Register in `modes/__init__.py` `MODES` dict and `__all__`.
4. Add a subparser in `cli.py` if it needs custom flags.
5. **Update docs** (see "Keeping docs in sync").

### Adding a CLI flag or Web endpoint
1. Add it in `cli.py` (use `_add_safety_flags` if it's a destination-affecting mode) or `web/routes.py`.
2. If a web endpoint accepts state changes, decorate with `@require_auth`.
3. **Update docs** (see "Keeping docs in sync").

### Dashboard Real-Time Updates
- Engine emits stats every ~1 second via `StatsCollector.emit_stats()`.
- Socket.IO broadcasts `stats_update` events to all connected clients.
- JavaScript also polls `/api/status` every second as a fallback.

### Bandwidth Optimization
- `AutoBulkGenerator` sends large UDP packets (~1400 bytes, near MTU) in batches.
- Pre-generated payloads avoid per-packet `os.urandom()` overhead.
- Scapy generators send through `packet_sender()` (`generators/_netio.py`), which
  reuses one L3 socket for the generator's lifetime instead of opening/closing a
  raw socket per packet — less CPU and fd churn at high rates.
- Heavy preset: 16 bulk generators × 100k pps × 2000 batch.

### Testing
```bash
# Run unit tests
pytest tests/

# Dry run - tests generation logic without sending packets
sudo trafficgoat auto -l medium --dry-run -d 10

# Web UI dry run - check via browser
sudo trafficgoat web --web-port 8080
# then enable "Dry Run" in the dashboard

# Quick import sanity check
python -c "from trafficgoat.generators.auto import AutoBulkGenerator; print('OK')"
```

Test files live in `tests/` — `test_config.py`, `test_engine_concurrency.py`, `test_stats.py`, `test_safety.py`, `test_web_auth.py`, `test_web_hardening.py`, `test_metrics_endpoint.py`, `test_application_socket.py`, `test_application_mixed.py`, `test_netio.py`, `test_generator_dryrun.py`.

## Dependencies

Pinned versions live in `requirements.txt`. Current set:

- **scapy** — raw packet crafting and sending
- **flask** — web framework
- **flask-socketio** — real-time WebSocket support
- **eventlet** — async I/O backend for Socket.IO
- **requests** — HTTP client (sync) for application-layer traffic
- **aiohttp** — HTTP client (async) used by high-rate HTTP generators
- **pyyaml** — YAML config parsing

When changing dependencies, update `requirements.txt` AND this list AND mention it in the PR description.

## Important Constraints

- Requires **root privileges** for raw socket access (Scapy).
- Requires **Linux** (raw sockets, Scapy layer 3 sending).
- Python **3.10+** required (type hint syntax).
- Web UI uses **eventlet** async mode for Socket.IO.
- **Targets are private by default** — non-RFC1918/loopback/link-local targets require `--allow-public`.
- **Aggressive `malicious` subtypes are gated** — bruteforce/ddos/amplification need `--enable-malicious`.
- This tool is for **authorized security testing only**.

---

## Keeping docs in sync

Code and documentation must stay aligned. Before merging any change that
touches a public-facing surface, walk this checklist and update *every*
file that's affected. If a row applies to your change and you didn't
touch the listed docs, your change is incomplete.

| Change                                              | Update                                                                 |
| --------------------------------------------------- | ---------------------------------------------------------------------- |
| Add/remove/rename a **generator**                   | `generators/__init__.py` registry · README "Generators" list · CLAUDE.md "Project Structure" + "Key Files" |
| Add/remove/rename a **mode**                        | `modes/__init__.py` registry · `cli.py` subparser · README "Modes" table · CLAUDE.md "CLI Surface" |
| Add/remove a **CLI flag**                           | `cli.py` · README "CLI Options" / "CLI Usage" · CLAUDE.md "CLI Surface" |
| Add/remove a **web endpoint** or **env var**        | `web/routes.py` or `web/app.py` · README "Web UI" · CLAUDE.md "Key Files" + "CLI Surface" |
| Add/remove a **dependency**                         | `requirements.txt` · CLAUDE.md "Dependencies"                          |
| Bump **version**                                    | `trafficgoat/__init__.py` only (setup.py reads it dynamically)         |
| Change **load presets** (light/medium/heavy)        | `modes/auto.py` · README "Auto Mode Load Presets" table                |
| Change **YAML schema** for custom mode              | `config.py` · `configs/example.yaml` · README "Custom Configuration"   |
| Change **safety defaults** (allowlist, gating)      | `safety.py` / `cli.py` · README "Disclaimer" + CLI usage · CLAUDE.md "Important Constraints" |

Rules of thumb:
1. **Don't duplicate the version.** `__init__.py` is the only place; `setup.py` parses it.
2. **README is user-facing**; CLAUDE.md is contributor/agent-facing. Both must be kept current — they answer different questions.
3. **Add tests for new behaviour** in `tests/`. If you can't easily test something, say so in the PR rather than silently skipping.
4. **Never** introduce a new public-facing flag, endpoint, or generator without also updating the table above if a new "axis" of change appears.
