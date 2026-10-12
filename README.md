# TrafficGoat

Advanced network traffic generator for Linux - designed for firewall testing and log generation.

## Features

- **13 Traffic Generators**: TCP (SYN/connect/flags), UDP, ICMP, HTTP/HTTPS, DNS, Application (FTP/SSH/SMTP), Malicious patterns (gated), plus six "auto" generators: raw, bulk, HTTP, TCP-connect, curl, and SaaS.
- **18 raw protocols** in auto mode: TCP SYN, UDP, ICMP, DNS, NTP, SNMP, SIP, LDAP, RADIUS, MQTT, Syslog, Memcached, Modbus, BGP, QUIC, STUN, Kerberos, and NetFlow (crafted with Scapy + hand-built payloads).
- **8 Subcommands**: `auto`, `stress`, `scan`, `mixed`, `protocol`, `stealth`, `custom`, `web`.
- **Dual Interface**: Full CLI + Web UI with real-time dashboard, generate page, modes overview, live logs.
- **Live Statistics**: Packets/s, bytes/s, per-generator breakdowns via Socket.IO (auto-updates every second).
- **Prometheus `/metrics` endpoint** for scraping by observability stacks.
- **High Bandwidth**: Bulk data generators produce gigabytes of traffic using large UDP payloads.
- **Safe-by-default targeting**: only loopback / RFC1918 / link-local / ULA destinations are allowed; public IPs require an explicit opt-in (`--allow-public`).
- **Token-protected web API**: an auth token is generated on startup (or set via `TRAFFICGOAT_TOKEN`).
- **Highly Configurable**: YAML configs, per-generator rate control, port ranges.

## Architecture Overview

![TrafficGoat Architecture](docs/architecture.svg)

TrafficGoat is a small layered system. A request flows top-to-bottom; statistics
flow back up to whichever interface is attached:

```
User input (CLI argparse  |  Web REST/Socket.IO)
        │
        ▼
Safety layer      safety.check_target()  → default-deny public IPs (UnsafeTargetError)
        │
        ▼
Mode layer        Mode.configure()       → builds GeneratorConfig objects, adds them to the engine
        │
        ▼
Engine            TrafficEngine          → starts each generator in its own daemon thread,
        │                                   runs a duration timer + a ~1s stats-emit loop
        ▼
Generator layer   BaseGenerator subclasses → craft packets (Scapy / sockets / requests / curl)
        │                                    and call stats.update() per batch
        ▼
Stats layer       StatsCollector         → lock-protected aggregation; fans out to the CLI
                                            printer and/or Socket.IO + /metrics
```

**Key design points**

- **Layered & pluggable.** Generators and modes are registered in small
  dictionaries (`generators/__init__.py` `GENERATORS`, `modes/__init__.py`
  `MODES`), so adding one is a class plus a registry entry — no engine changes.
- **Thread-per-generator.** The engine runs every generator in a daemon thread,
  plus one duration-timer thread and one stats-emit thread. Shutdown is
  two-phase: signal all generators to stop, then join them with a bounded
  timeout, so a slow generator can't wedge the whole run.
- **Safety is enforced before any thread starts.** `check_target()` resolves
  hostnames (A + AAAA) and rejects the target if *any* resolved address is
  public unless `--allow-public` is set. Aggressive `malicious` subtypes are
  separately gated behind `--enable-malicious`.
- **One stats model, many sinks.** `StatsCollector` is the single source of
  truth. The CLI subscribes a terminal printer; the web app subscribes a
  Socket.IO broadcaster and also exposes `/metrics` for Prometheus.
- **Efficient send path.** Scapy generators hold one reused layer-3 socket open
  for their lifetime (`generators/_netio.py`) instead of opening and closing a
  raw socket per packet, which lowers CPU and file-descriptor churn at high
  packet rates. The send path degrades gracefully to scapy's module-level
  `send()` if a persistent socket can't be created.

## Requirements

- Linux (Debian/Ubuntu)
- Python 3.10+
- Root privileges (raw sockets)

## Installation

```bash
git clone <repo-url> && cd trafficgoat
sudo ./install.sh
```

Or manually:

```bash
pip install -r requirements.txt
pip install -e .
```

## CLI Usage

```bash
# Auto mode - zero-config, high bandwidth to thousands of destinations
sudo trafficgoat auto -l heavy -d 300
sudo trafficgoat auto -l medium -d 120
sudo trafficgoat auto -l light -d 60

# Stress test - all traffic types at high rate (private target by default)
sudo trafficgoat stress -t 192.168.1.1 -d 60 -r 500

# Port scan simulation
sudo trafficgoat scan -t 10.0.0.1 -p 1-1024

# Realistic mixed traffic
sudo trafficgoat mixed -t 192.168.1.1 -r 200 -d 120

# Single protocol test
sudo trafficgoat protocol -t 192.168.1.1 --protocol icmp -d 30

# Low-and-slow stealth test
sudo trafficgoat stealth -t 192.168.1.1 -d 300

# Custom config
sudo trafficgoat custom -t 192.168.1.1 -c configs/example.yaml

# Dry run (no packets sent)
sudo trafficgoat stress -t 192.168.1.1 --dry-run

# Hitting a public IP requires explicit opt-in
sudo trafficgoat stress -t 198.51.100.10 --allow-public

# Aggressive "malicious" patterns are gated behind a separate flag
sudo trafficgoat protocol -t 192.168.1.1 --protocol tcp --enable-malicious
```

## Web UI

```bash
# Bind defaults to 127.0.0.1; use --host 0.0.0.0 only when you mean it.
sudo trafficgoat web --web-port 8080
```

On startup, if `TRAFFICGOAT_TOKEN` isn't set, the server generates a token and
writes it to a `0600` file under `$XDG_RUNTIME_DIR` (falling back to
`/run/trafficgoat` or the system tempdir) — only the *path* is printed, never
the token itself, so it can't leak into syslog / container log aggregators.
Read it with `cat <path>` and pass it as `Authorization: Bearer <token>`,
`X-Auth-Token: <token>`, or `?token=<token>`.

Pin a stable token via the environment to skip the generated file:

```bash
export TRAFFICGOAT_TOKEN="your-long-random-token"
export TRAFFICGOAT_SECRET_KEY="another-long-random-secret"
sudo -E trafficgoat web --web-port 8080
```

Set `TRAFFICGOAT_TOKEN=""` (empty string) to disable auth entirely — only do this
on a trusted, isolated network. The server logs a warning when auth is off.

**Socket.IO CORS** is pinned to the configured `host:port` by default and is
*not* widened by `--allow-public` (which only affects the *target* allowlist).
To allow cross-origin dashboard access, set
`TRAFFICGOAT_CORS_ORIGINS="http://dash.example.com,http://other.example.com"`
(or `*` if you really want to open it).

**Rate limiting** (in-memory, per-token-or-IP, per-endpoint):
`/api/start` 3/10s · `/api/stop` 5/10s · `/api/logs` 30/5s · `/api/history` 30/5s.
Excess requests get `429` with a `Retry-After` header. Request bodies are
capped at 1 MiB.

The Web UI provides:

- **Dashboard**: Real-time statistics, start/stop controls, per-generator breakdown.
- **Generate**: One-click runs with mode/duration/rate selection.
- **Modes**: Visual overview of all available modes.
- **Logs**: Live log streaming with auto-scroll.

### Web API

All endpoints require the auth token (unless explicitly disabled):

| Endpoint            | Method | Purpose                                |
| ------------------- | ------ | -------------------------------------- |
| `/api/start`        | POST   | Start a traffic run                    |
| `/api/stop`         | POST   | Stop the current run                   |
| `/api/status`       | GET    | Current engine + stats snapshot        |
| `/api/modes`        | GET    | List available modes                   |
| `/api/logs`         | GET    | Recent log lines                       |
| `/api/history`      | GET    | Past session summaries                 |
| `/api/version`      | GET    | TrafficGoat version                    |
| `/metrics`          | GET    | Prometheus-formatted metrics           |

### Environment variables (web mode)

| Variable                   | Default                    | Purpose                                                                 |
| -------------------------- | -------------------------- | ----------------------------------------------------------------------- |
| `TRAFFICGOAT_TOKEN`        | *(generated to 0600 file)* | API auth token. Set to a fixed value to pin it; set to `""` to disable auth (warns loudly). |
| `TRAFFICGOAT_SECRET_KEY`   | *(random per process)*     | Flask session secret.                                                   |
| `TRAFFICGOAT_CORS_ORIGINS` | `host:port` of the server  | Comma-separated Socket.IO CORS allowlist, or `*` to open it. Not widened by `--allow-public`. |

## Modes

| Mode       | Description                                                                    |
| ---------- | ------------------------------------------------------------------------------ |
| `auto`     | Zero-config: multi-destination traffic to 1000s of targets with bulk bandwidth |
| `stress`   | High-volume: TCP SYN + UDP + ICMP + HTTP at max rate                           |
| `scan`     | Port scanning: SYN, FIN, and connect scans                                     |
| `mixed`    | Realistic: weighted distribution across all protocols                          |
| `protocol` | Single protocol with full parameter control                                    |
| `stealth`  | Low-and-slow with randomized timing                                            |
| `custom`   | User-defined via YAML config file                                              |
| `web`      | Start the Web UI                                                               |

### Auto Mode Load Presets

| Level    | PPS      | Destinations | Bulk Generators | Batch Size |
| -------- | -------- | ------------ | --------------- | ---------- |
| `light`  | ~2,000   | 500          | 4               | 500        |
| `medium` | ~10,000  | 1,500        | 8               | 1,000      |
| `heavy`  | ~50,000  | 3,000        | 16              | 2,000      |

Each bulk generator sends ~1,400-byte UDP packets in large batches for maximum
bandwidth. A 5-minute heavy run generates multiple gigabytes of traffic.

## Custom Configuration

`custom` mode is driven by a YAML file (`-c config.yaml`). The file has a few
top-level keys plus a `generators:` list; each list entry configures one
generator. See `configs/example.yaml` for a fully-commented reference.

```yaml
target: "192.168.1.1"   # inherited by generators that omit their own target
duration: 120           # seconds; inherited by generators left at the default
generators:
  - type: tcp_syn       # which generator to run (see table below)
    subtype: syn        # variant within that generator
    ports: "80,443"     # single / range (1-1024) / CSV
    rate: 200           # packets per second for THIS generator
    weight: 0.4         # advisory share, for your own documentation
  - type: http
    ports: "80,443"
    rate: 100
    methods: [GET, POST]
  - type: dns
    subtype: mixed
    rate: 50
```

### Top-level keys

| Key        | Default       | Meaning                                                        |
| ---------- | ------------- | -------------------------------------------------------------- |
| `target`   | `127.0.0.1`   | Default target; a generator without its own `target` inherits it. Must be private unless the run uses `--allow-public`. |
| `duration` | `60`          | Run length in seconds (`0` = run until stopped). A generator left at the default `60` inherits this value. |

### Per-generator keys (`GeneratorConfig`)

| Key                | Default   | Applies to        | Meaning                                                                 |
| ------------------ | --------- | ----------------- | ----------------------------------------------------------------------- |
| `type` *(required)*| —         | all               | Generator to instantiate (see valid values below).                      |
| `subtype`          | `""`      | tcp/udp/icmp/dns/application | Variant within the generator (e.g. `syn`, `connect`, `fin`, `xmas`, `null`, `rst` for TCP; `random`/`dns`/`ntp` for UDP; `echo`/`mixed` for ICMP; `valid`/`random`/`nxdomain`/`mixed` for DNS; `ftp`/`ssh`/`smtp`/`mixed` for application). |
| `target`           | `""`      | all               | Per-generator target; falls back to the top-level `target`.             |
| `ports`            | `"80"`    | tcp/udp/http      | Single port, range (`1-1024`) or CSV (`80,443,8080`).                   |
| `rate`             | `100`     | all               | Packets/requests per second for this generator (1..1,000,000).          |
| `duration`         | `60`      | all               | Per-generator run length; falls back to the top-level `duration`.       |
| `weight`           | `1.0`     | all               | Advisory traffic share for documentation; not auto-normalised.          |
| `count`            | `0`       | all               | Reserved (`0` = unlimited, driven by `duration`).                       |
| `methods`          | `[GET]`   | http              | HTTP methods to choose from (`GET`, `POST`, `PUT`, …).                   |
| `urls`             | `[]`      | http              | Explicit URL list; if empty, URLs are built from `target` + `ports`.    |
| `options`          | `{}`      | all               | Free-form extra options bag (reserved for generator-specific tuning).   |
| `enable_malicious` | `false`   | malicious         | Allow gated subtypes; normally set from the `--enable-malicious` flag.  |

### Valid `type` values

`tcp`, `tcp_syn`, `tcp_connect`, `udp`, `icmp`, `http`, `dns`, `ftp`, `ssh`,
`smtp`, `application`, `malicious`, `portscan`, `bruteforce`, `auto_raw`,
`auto_http`, `auto_tcp`, `auto_bulk`, `auto_curl`, `auto_saas`.

> `malicious` / `bruteforce` (and the `ddos` / `amplification` subtypes) only
> run when the engine is started with `--enable-malicious`. Plain `portscan`
> does not require the flag.

## CLI Options

```
Global Options (most modes):
  -t, --target           Target IP/hostname (required; must be private unless --allow-public)
  -p, --ports            Port(s): single, range, comma-separated (default: 80)
  -d, --duration         Duration in seconds (default: 60)
  -r, --rate             Packets per second (default: 100)
  --threads              Worker threads (default: 4)
  -i, --interface        Network interface
  -v, --verbose          Verbose output
  -q, --quiet            Minimal output
  --dry-run              Simulate without sending packets
  --allow-public         Permit non-private targets (default: deny)
  --enable-malicious     Permit gated malicious subtypes (bruteforce/ddos/amplification)

Web mode:
  --host                 Bind address (default: 127.0.0.1)
  --web-port             Listen port (default: 8080)
  --dev                  Use the unsafe werkzeug dev server (development only)
```

## Safety model

By default TrafficGoat refuses to send traffic to anything outside loopback,
RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), IPv6 loopback,
ULA (fc00::/7) and IPv6 link-local (fe80::/10). Hostnames are resolved (A + AAAA)
and **every** returned address must pass the check — a hostname that resolves to
a mix of public and private addresses is rejected.

To hit a public target you must pass `--allow-public` explicitly, and aggressive
attack patterns (`bruteforce`, `ddos`, `amplification`) additionally require
`--enable-malicious`. Plain `portscan` does not.

## Contributing

If you change a generator, mode, CLI flag, web endpoint, env var, or dependency,
**update both `README.md` and `CLAUDE.md`** in the same PR. The checklist lives at
the bottom of [`CLAUDE.md`](./CLAUDE.md#keeping-docs-in-sync).

## Disclaimer

This tool is intended for **authorized security testing, firewall validation, and log generation** only. Only use against systems you own or have explicit permission to test. Unauthorized use against third-party systems is illegal.
