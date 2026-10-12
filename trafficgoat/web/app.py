"""Flask application factory and Socket.IO setup."""

import logging
import os
import secrets
import tempfile
import threading
import time

from flask import Flask
from flask_socketio import SocketIO


logger = logging.getLogger(__name__)

socketio = SocketIO()

# Global engine reference for the web app
_engine = None
_stats = None
_engine_lock = threading.Lock()

# Session history - stores completed traffic generation sessions
_session_history = []
_current_session = None

# Auth token; populated by create_app(). Empty string disables auth (and
# triggers a loud warning at startup).
_auth_token: str = ""

# Safety / CORS settings exposed to routes
_settings: dict = {}


def get_engine():
    return _engine


def get_stats():
    return _stats


def set_engine(engine):
    global _engine
    _engine = engine


def set_stats(stats):
    global _stats
    _stats = stats


def get_engine_lock() -> threading.Lock:
    return _engine_lock


def get_auth_token() -> str:
    return _auth_token


def get_settings() -> dict:
    return _settings


def get_session_history():
    return _session_history


def start_session(mode, target, load_level=None, dry_run=False, duration=0):
    global _current_session
    _current_session = {
        "id": len(_session_history) + 1,
        "start_time": time.time(),
        "end_time": None,
        "mode": mode,
        "target": target,
        "load_level": load_level,
        "dry_run": dry_run,
        "duration_config": duration,
        "total_packets": 0,
        "total_bytes": 0,
        "total_errors": 0,
        "peak_pps": 0,
        "status": "running",
    }
    return _current_session


def end_session(stats_data=None):
    global _current_session
    if _current_session is None:
        return
    _current_session["end_time"] = time.time()
    _current_session["status"] = "completed"
    if stats_data:
        _current_session["total_packets"] = stats_data.get("total_packets", 0)
        _current_session["total_bytes"] = stats_data.get("total_bytes", 0)
        _current_session["total_errors"] = stats_data.get("total_errors", 0)
    _session_history.insert(0, _current_session)
    # Keep last 50 sessions
    if len(_session_history) > 50:
        _session_history[:] = _session_history[:50]
    _current_session = None


def get_current_session():
    return _current_session


def _write_token_file(token: str) -> str:
    """Persist a generated auth token to a 0600 file and return the path.

    Picks the first writable directory in: $XDG_RUNTIME_DIR, /run/trafficgoat,
    tempfile.gettempdir(). The file is created with mode 0600 so non-owners
    can't read it on shared hosts.
    """
    candidates = []
    if os.environ.get("XDG_RUNTIME_DIR"):
        candidates.append(os.environ["XDG_RUNTIME_DIR"])
    candidates.extend(["/run/trafficgoat", tempfile.gettempdir()])

    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            continue
        try:
            fd, path = tempfile.mkstemp(
                prefix="trafficgoat-token-", suffix=".txt", dir=d,
            )
        except OSError:
            continue
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(token + "\n")
            return path
        except OSError:
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
    # Should not happen — tempfile.gettempdir() is always writable in practice.
    raise RuntimeError("Could not write auth token file in any candidate dir")


def create_app(
    *,
    allow_public: bool = False,
    enable_malicious: bool = False,
    host: str = "127.0.0.1",
    port: int = 8080,
    auth_token: str | None = None,
) -> Flask:
    """Create and configure the Flask application.

    Args:
        allow_public: Allow non-private target IPs (default: False).
        enable_malicious: Allow MaliciousGenerator gated subtypes (default: False).
        host / port: Used to pin the Socket.IO CORS origin.
        auth_token: If None, read from $TRAFFICGOAT_TOKEN or generate one and
            print it. Empty string disables auth (NOT recommended).
    """
    global _auth_token, _settings

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    # Random per-process secret unless overridden via env.
    app.config["SECRET_KEY"] = os.environ.get("TRAFFICGOAT_SECRET_KEY") or secrets.token_hex(32)

    # Resolve auth token. When we generate one we write it to a 0600 file and
    # print only the path; printing the token to stdout would leak it into
    # syslog / journal / container log aggregators.
    if auth_token is None:
        auth_token = os.environ.get("TRAFFICGOAT_TOKEN")
    if auth_token is None:
        auth_token = secrets.token_urlsafe(24)
        token_path = _write_token_file(auth_token)
        prefix = auth_token[:4]
        print(f"  [auth] Generated auth token (starts with {prefix}…).")
        print(f"  [auth] Saved to: {token_path} (mode 0600)")
        print(f"  [auth] Read it via: cat {token_path}")
        print( "  [auth] Set $TRAFFICGOAT_TOKEN to pin a stable token and skip this file.")
    elif auth_token == "":
        print("  [auth] WARNING: auth disabled (TRAFFICGOAT_TOKEN=\"\"). "
              "Anyone reachable to this port can launch root-privileged traffic.")
    _auth_token = auth_token

    _settings = {
        "allow_public": bool(allow_public),
        "enable_malicious": bool(enable_malicious),
        "host": host,
        "port": port,
    }

    from trafficgoat import __version__

    @app.context_processor
    def inject_version():
        # `auth_token` is injected so the dashboard JS can read it from a
        # <meta> tag and attach it to fetch/Socket.IO requests. The token is
        # only useful to a client that can already render this page, so this
        # doesn't widen the trust boundary.
        return {"app_version": __version__, "auth_token": _auth_token}

    from trafficgoat.web.routes import bp
    app.register_blueprint(bp)

    # CORS origin pinned to the configured host:port. `--allow-public` only
    # widens the *target* allowlist — it must not also open the Socket.IO
    # origin to the world. Operators who need cross-origin access (e.g. a
    # separate dashboard host) can set $TRAFFICGOAT_CORS_ORIGINS to a
    # comma-separated list of origins (or `*` if they really mean it).
    cors_env = os.environ.get("TRAFFICGOAT_CORS_ORIGINS", "").strip()
    if cors_env == "*":
        cors_origins = "*"
        logger.warning("Socket.IO CORS set to '*' via $TRAFFICGOAT_CORS_ORIGINS")
    elif cors_env:
        cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    else:
        cors_origins = [
            f"http://{host}:{port}",
            f"http://localhost:{port}",
            f"http://127.0.0.1:{port}",
        ]
    # Threading async mode: no greenlet runtime, no monkey-patching. WebSocket
    # transport is provided by `simple-websocket` (pulled in via python-engineio);
    # without it Socket.IO still works over HTTP long-polling, and the dashboard
    # JS has its own polling fallback. This replaces the eventlet backend, which
    # upstream now maintains in bugfix-only mode (and which is outright broken on
    # Python 3.13).
    socketio.init_app(app, cors_allowed_origins=cors_origins, async_mode="threading")

    # Cap request body size; the API only accepts small JSON payloads.
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MiB

    # Setup stats collector for web
    from trafficgoat.stats import StatsCollector
    stats = StatsCollector()
    set_stats(stats)

    # Wire up Socket.IO broadcasting
    stats.on_stats(lambda s: socketio.emit("stats_update", s, namespace="/"))
    stats.on_log(lambda msg: socketio.emit("log_message", {"message": msg}, namespace="/"))

    return app
