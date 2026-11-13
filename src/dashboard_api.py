#!/usr/bin/env python3
"""HTTP API for the dashboard's data (see docs/react-native-port.md).

Each endpoint returns what one function in ``ids.dashboard_data`` returns, as
JSON, so the React page and a React Native app show the same data. Every
endpoint but /health asks for
``Authorization: Bearer <IDS_API_TOKEN>``, unless IDS_API_REQUIRE_TOKEN is
false (for testing on a trusted network). The React page (web/, built with
``npm run build``) is served at / when web/dist holds it.

    .venv/bin/python src/dashboard_api.py [--host 0.0.0.0] [--port 8501]
    .venv/bin/python src/dashboard_api.py --new-token
"""

from __future__ import annotations

import argparse
import hmac
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from ids.alert_archive import TooManyAlerts, archive_contents, archive_file
from ids.combined_detections import PKT, WINDOW_LENGTHS
from ids.config import (
    ENV_FILE,
    api_token_required,
    engine_sources,
    get_api_token,
    get_settings,
    llm_target,
)
from ids.dashboard_data import (
    CHART_STEPS,
    DEFAULT_CHART_STEP,
    DEFAULT_TOP_RULES_LENGTH,
    ENGINES,
    EXPORT_MAX_ALERTS,
    LAST_CHOICES,
    LIVE_STEP,
    MAX_LAST,
    PAGE_SIZES,
    TIME_RANGES,
    AlertFilter,
    alert_detail,
    alerts,
    combined_export,
    export_window,
    filter_values,
    live,
    offline_rule_intelligence,
    overview,
    parse_network,
    parse_rule,
    rule_pairs,
    selection,
    selection_export,
    status,
)
from ids.test_alert import result_path
from ids.uptime import machine_off_periods

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIST = PROJECT_ROOT / "web" / "dist"
DEFAULT_EXPORT_LENGTH = "15 minutes"
# SQLite's words for a damaged database file.
DAMAGED = re.compile(r"malformed|not a database|corrupt", re.IGNORECASE)
# The export's window and counts, for an app that does not read the whole
# file to show them.
EXPORT_HEADERS = (
    "X-Window-Start-Ms", "X-Window-End-Ms", "X-Alerts-Snort", "X-Alerts-Suricata",
    "X-Packets", "X-Both-Engine-Packets",
)
# Letters and digits that cannot be taken for one another (no i, l, o or u).
TOKEN_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
# How long Send waits for the LLM PC to take a file.
SEND_TIMEOUT_SECONDS = 60
# The filter choices change slowly: read them from the database this often.
FILTER_VALUES_SECONDS = 300


def post_file(url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, str]:
    """POSTs a file to ``url``: the answer's status and the start of its
    text. OSError when the address can't be reached."""
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=SEND_TIMEOUT_SECONDS) as answer:
            return answer.status, answer.read(500).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read(500).decode("utf-8", "replace")


def _target(url: str) -> str:
    """An address as the page shows it: host and port, without any password."""
    parts = urlsplit(url)
    host = parts.hostname or url
    return f"[{host}]:{parts.port}" if parts.port and ":" in host else (
        f"{host}:{parts.port}" if parts.port else host
    )


class PageFiles(StaticFiles):
    """The built page. Its HTML says no-cache, so a browser checks it again on
    every visit and a new build shows at once: each build deletes the old
    scripts and styles, which have a new name every build (so they can be
    kept)."""

    def file_response(
        self,
        full_path: str | os.PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        if os.fspath(full_path).endswith(".html"):
            response.headers["Cache-Control"] = "no-cache"
        return response


class BadRequest(ValueError):
    """A query parameter the API cannot use."""


def _int_param(
    request: Request,
    name: str,
    *,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
    raw = request.query_params.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"{name} must be a whole number") from None
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise BadRequest(f"{name} must be from {minimum} to {maximum}")
    return value


def _length(request: Request, name: str = "length", default: str = DEFAULT_EXPORT_LENGTH) -> str:
    length = request.query_params.get(name, default)
    if length not in WINDOW_LENGTHS:
        raise BadRequest(f"{name} must be one of: {', '.join(WINDOW_LENGTHS)}")
    return length


def _alert_filter(request: Request, engines: Sequence[str]) -> AlertFilter:
    """The Alert Explorer's filters in the query (see docs/react-native-port.md)."""
    params = request.query_params
    engine = params.get("engine") or None
    if engine not in (None, *engines):
        raise BadRequest(f"engine must be one of: {', '.join(engines)}")
    since_ms = _int_param(request, "since_ms")
    time_range = params.get("range")
    if time_range is not None:
        if since_ms is not None:
            raise BadRequest("give range or since_ms, not both")
        if time_range not in TIME_RANGES:
            raise BadRequest(f"range must be one of: {', '.join(TIME_RANGES)}")
        # From the server's clock, which the stored times follow.
        span = TIME_RANGES[time_range]
        since_ms = int((datetime.now(tz=PKT) - span).timestamp() * 1000) if span else None
    severities: set[int] = set()
    for part in params.get("severity", "").split(","):
        if part.strip():
            if part.strip() not in {"1", "2", "3", "4"}:
                raise BadRequest("severity must be numbers from 1 to 4, like 1,2")
            severities.add(int(part))
    try:
        rule = parse_rule(params.get("rule", ""))
        source = parse_network(params.get("source", ""), "source")
        destination = parse_network(params.get("destination", ""), "destination")
    except ValueError as error:
        raise BadRequest(str(error)) from None
    return AlertFilter(
        engine=engine,
        since_ms=since_ms,
        until_ms=_int_param(request, "until_ms"),
        search=params.get("search", "")[:200],
        severities=tuple(sorted(severities)),
        protocol=params.get("protocol", "")[:40],
        classification=params.get("class", "")[:200],
        service=params.get("service", "")[:40],
        app=params.get("app", "")[:80],
        rule=rule,
        source=source,
        destination=destination,
        port=_int_param(request, "port", minimum=0, maximum=65535),
        last=_int_param(request, "last", minimum=1, maximum=MAX_LAST),
        each=params.get("each", "").lower() in {"1", "true", "yes"},
    )


def create_app(
    *,
    db_path: Path | str,
    ids_sources: Mapping[str, Any],
    token: str | None,
    alert_retention: int | None = None,
    state_file: Path | str | None = None,
    rule_intelligence: Callable[..., Any] | None = offline_rule_intelligence,
    web_dist: Path | None = WEB_DIST,
    engines: Sequence[str] = ENGINES,
    archive_dir: Path | str | None = None,
    archive_settings: Mapping[str, int] | None = None,
    off_periods: Callable[[], list[tuple[int, int]]] | None = None,
    stats_files: Mapping[str, Path | str] | None = None,
    export_max_alerts: int = EXPORT_MAX_ALERTS,
    backup_dir: Path | str | None = None,
    send_url: str | None = None,
    send_token: str | None = None,
    sender: Callable[[str, bytes, Mapping[str, str]], tuple[int, str]] = post_file,
) -> Starlette:
    """The API over the live database at ``db_path``, answering requests
    that send ``token`` (every request when it is None), and the built React
    page in ``web_dist`` at /. ``state_file`` is the collector's, whose
    changes show it storing alerts. The screens show the ``engines`` this
    machine runs (IDS_ENGINES), the alerts that have left the database from
    ``archive_dir`` (kept as ``archive_settings`` says), when the machine was
    off from ``off_periods``, and each engine's drops from its statistics
    file in ``stats_files``. One export holds at most ``export_max_alerts``.
    Send POSTs the chosen alerts' file to ``send_url`` (none: Send is off)
    with ``send_token``, through ``sender``."""
    if token == "":
        raise ValueError("the API needs a token, or None to let every request in")

    # The past boots don't change while the API runs, which starts after
    # this one: read them once, on the first request that needs them.
    off_cache: list[list[tuple[int, int]]] = []

    def machine_off() -> list[tuple[int, int]]:
        if not off_cache:
            off_cache.append(off_periods() if off_periods is not None else [])
        return off_cache[0]

    def guarded(handler: Callable[[Request], Response], *, public: bool = False):
        def endpoint(request: Request) -> Response:
            scheme, _, given = request.headers.get("authorization", "").partition(" ")
            if not public and token is not None and not (
                scheme.lower() == "bearer" and hmac.compare_digest(given.strip(), token)
            ):
                return JSONResponse(
                    {"error": "missing or wrong token"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            try:
                return handler(request)
            except BadRequest as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except sqlite3.Error as exc:
                error = f"could not read the live database: {exc}"
                if isinstance(exc, sqlite3.DatabaseError) and DAMAGED.search(str(exc)):
                    error += " (the database is damaged: restore a backup with scripts/restore_backup.py)"
                return JSONResponse({"error": error}, status_code=503)

        return endpoint

    def health(request: Request) -> Response:
        return JSONResponse({"ok": True})

    def options(request: Request) -> Response:
        """The choices the screens offer."""
        return JSONResponse({
            "engines": list(engines),
            "export_lengths": list(WINDOW_LENGTHS),
            "default_export_length": DEFAULT_EXPORT_LENGTH,
            "time_ranges": [
                {"label": label, "ms": int(span.total_seconds() * 1000) if span else None}
                for label, span in TIME_RANGES.items()
            ],
            "page_sizes": list(PAGE_SIZES),
            "last_choices": list(LAST_CHOICES),
            "max_last": MAX_LAST,
            # Where Send sends the chosen alerts; null when it is off.
            "send_to": _target(send_url) if send_url else None,
            "chart_steps": list(CHART_STEPS),
            "default_chart_step": DEFAULT_CHART_STEP,
            "live_step_seconds": int(LIVE_STEP.total_seconds()),
            "default_top_rules_length": DEFAULT_TOP_RULES_LENGTH,
            "time_zone": "Asia/Karachi",
        })

    def overview_screen(request: Request) -> Response:
        step = _int_param(request, "step_minutes", default=DEFAULT_CHART_STEP)
        if step not in CHART_STEPS:
            raise BadRequest(f"step_minutes must be one of: {', '.join(map(str, CHART_STEPS))}")
        return JSONResponse(overview(
            db_path, ids_sources, alert_retention=alert_retention, step_minutes=step,
            top_rules_length=_length(request, "top_rules_length", DEFAULT_TOP_RULES_LENGTH),
            engines=engines, off_periods=machine_off(),
        ))

    def status_screen(request: Request) -> Response:
        return JSONResponse(status(
            db_path, state_file, ids_sources, alert_retention=alert_retention, engines=engines,
            stats_files=stats_files, archive_dir=archive_dir, backup_dir=backup_dir,
            # The hourly test alert's result, beside the collector's state.
            test_alert_file=result_path(state_file) if state_file else None,
        ))

    def live_chart(request: Request) -> Response:
        return JSONResponse(live(db_path, engines=engines, off_periods=machine_off()))

    def archive_list(request: Request) -> Response:
        """The archive's zips and day files, and how long it keeps them."""
        found = archive_contents(archive_dir) if archive_dir is not None else {"zips": [], "days": []}
        return JSONResponse({**found, **(archive_settings or {})})

    def archive_download(request: Request) -> Response:
        name = request.path_params["name"]
        path = archive_file(archive_dir, name) if archive_dir is not None else None
        if path is None:
            return JSONResponse({"error": f"no archive file named {name}"}, status_code=404)
        return FileResponse(path, filename=name)

    def alert_list(request: Request) -> Response:
        return JSONResponse(alerts(
            db_path,
            filters=_alert_filter(request, engines),
            page=_int_param(request, "page", default=1, minimum=1),
            page_size=_int_param(
                request, "page_size", default=25, minimum=1, maximum=max(PAGE_SIZES)
            ),
            engines=engines,
        ))

    def alert_screen(request: Request) -> Response:
        """Everything about one alert, for the Alert Explorer's side panel."""
        found = alert_detail(
            db_path, request.path_params["alert_id"], rule_intelligence=rule_intelligence,
            engines=engines,
        )
        if found is None:
            return JSONResponse({"error": "no such alert"}, status_code=404)
        return JSONResponse(found)

    # When the filter choices were read, and what they were.
    values_cache: dict[str, Any] = {}

    def alert_values(request: Request) -> Response:
        """The protocols, classes, services and apps the filters offer."""
        if time.monotonic() - values_cache.get("read", -FILTER_VALUES_SECONDS) >= FILTER_VALUES_SECONDS:
            values_cache.update(values=filter_values(db_path, engines=engines), read=time.monotonic())
        return JSONResponse(values_cache["values"])

    def selection_screen(request: Request) -> Response:
        """What a download or send of the filtered alerts would hold."""
        return JSONResponse(selection(
            db_path, _alert_filter(request, engines), engines=engines, max_alerts=export_max_alerts,
        ))

    def built_selection(request: Request) -> dict[str, Any] | Response:
        """The filtered alerts' file, or the answer saying why there is none."""
        try:
            built = selection_export(
                db_path, _alert_filter(request, engines), rule_intelligence=rule_intelligence,
                engines=engines, max_alerts=export_max_alerts,
            )
        except TooManyAlerts as exc:
            return JSONResponse({"error": str(exc)}, status_code=413)
        if built is None:
            return JSONResponse({"error": "no alerts match the filters"}, status_code=404)
        return built

    def selection_headers(built: Mapping[str, Any]) -> dict[str, str]:
        counts = built["alerts"]
        values = (
            built["start_ms"], built["end_ms"], counts.get("snort", 0),
            counts.get("suricata", 0), built["packets"], built["both_engine_packets"],
        )
        return {name: str(value) for name, value in zip(EXPORT_HEADERS, values)}

    def selection_file(request: Request) -> Response:
        """The combined JSON file of the filtered alerts."""
        built = built_selection(request)
        if isinstance(built, Response):
            return built
        return Response(
            built["json"],
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{built["filename"]}"',
                **selection_headers(built),
            },
        )

    def send_selection(request: Request) -> Response:
        """Sends the filtered alerts' file to the LLM PC (IDS_LLM_URL)."""
        if not send_url:
            return JSONResponse(
                {"error": "Send is off: put the LLM PC's address in IDS_LLM_URL in .env "
                          "and restart the dashboard"},
                status_code=503,
            )
        built = built_selection(request)
        if isinstance(built, Response):
            return built
        body = built["json"].encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Filename": built["filename"],
            **selection_headers(built),
        }
        if send_token:
            headers["Authorization"] = f"Bearer {send_token}"
        target = _target(send_url)
        try:
            answer, text = sender(send_url, body, headers)
        except OSError as exc:
            reason = getattr(exc, "reason", exc)
            return JSONResponse(
                {"error": f"could not reach the LLM PC at {target}: {reason}"}, status_code=502,
            )
        if not 200 <= answer < 300:
            return JSONResponse(
                {"error": f"the LLM PC at {target} answered {answer}: {text.strip()[:200]}"},
                status_code=502,
            )
        return JSONResponse({
            "sent": True,
            "to": target,
            "filename": built["filename"],
            "bytes": len(body),
            "alerts": built["alerts"],
            "packets": built["packets"],
            "both_engine_packets": built["both_engine_packets"],
        })

    def rule_pair_list(request: Request) -> Response:
        return JSONResponse(rule_pairs(db_path, engines=engines))

    def window(request: Request) -> dict[str, Any] | None:
        return export_window(
            db_path, _length(request), _int_param(request, "end_ms"), engines=engines,
            max_alerts=export_max_alerts, archive_dir=archive_dir,
        )

    def export_window_screen(request: Request) -> Response:
        found = window(request)
        if found is None:
            return JSONResponse({"error": "no alerts stored yet"}, status_code=404)
        return JSONResponse(found)

    def export_file(request: Request) -> Response:
        """The combined JSON file for the window /export/window gives."""
        found = window(request)
        if found is None:
            return JSONResponse({"error": "no alerts stored yet"}, status_code=404)
        try:
            built = combined_export(
                db_path, found["start_ms"], found["end_ms"], _length(request),
                rule_intelligence=rule_intelligence, engines=engines,
                archive_dir=archive_dir, max_alerts=export_max_alerts,
            )
        except TooManyAlerts as exc:
            return JSONResponse({"error": str(exc)}, status_code=413)
        counts = built["alerts"]
        values = (
            found["start_ms"], found["end_ms"], counts.get("snort", 0),
            counts.get("suricata", 0), built["packets"], built["both_engine_packets"],
        )
        return Response(
            built["json"],
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{built["filename"]}"',
                **{name: str(value) for name, value in zip(EXPORT_HEADERS, values)},
            },
        )

    routes: list[Route | Mount] = [
        Route("/health", guarded(health, public=True)),
        Route("/options", guarded(options)),
        Route("/overview", guarded(overview_screen)),
        Route("/status", guarded(status_screen)),
        Route("/live", guarded(live_chart)),
        Route("/alerts", guarded(alert_list)),
        Route("/alerts/values", guarded(alert_values)),
        Route("/alerts/{alert_id:int}", guarded(alert_screen)),
        Route("/rule-pairs", guarded(rule_pair_list)),
        Route("/export/window", guarded(export_window_screen)),
        Route("/export", guarded(export_file)),
        Route("/export/selection", guarded(selection_screen)),
        Route("/export/selection/file", guarded(selection_file)),
        Route("/export/selection/send", guarded(send_selection), methods=["POST"]),
        Route("/archive", guarded(archive_list)),
        Route("/archive/{name}", guarded(archive_download)),
    ]
    if web_dist is not None and (Path(web_dist) / "index.html").is_file():
        # Everything the routes above do not answer: the page and its files.
        # The page asks for the token itself, so its files need none.
        routes.append(Mount("/", app=PageFiles(directory=web_dist, html=True), name="web"))
    return Starlette(
        routes=routes,
        # For the app in a web browser (Expo web); the token protects the data.
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET", "POST"],
                allow_headers=["Authorization"],
                expose_headers=["Content-Disposition", *EXPORT_HEADERS],
            ),
        ],
    )


def new_token() -> str:
    """A token short enough to type: four groups of four letters and digits,
    such as k7m2-x9qa-3fz8-p4wd (80 random bits)."""
    return "-".join(
        "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(4)) for _ in range(4)
    )


def _env_name(line: str) -> str:
    """The name a .env line sets, read as ids.config reads it; "" for none."""
    line = line.strip()
    if line.startswith("export "):
        line = line[7:].strip()
    if not line or line.startswith("#") or "=" not in line:
        return ""
    return line.split("=", 1)[0].strip()


def save_new_token(env_file: Path = ENV_FILE) -> str:
    """Puts a new token in env_file (which git ignores) as IDS_API_TOKEN, in
    place of the old one and keeping the other lines, and returns it."""
    token = new_token()
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.is_file() else []
    places = [index for index, line in enumerate(lines) if _env_name(line) == "IDS_API_TOKEN"]
    if places:
        lines[places[0]] = f"IDS_API_TOKEN={token}"
        # A later IDS_API_TOKEN line would win over this one.
        lines = [line for index, line in enumerate(lines) if index not in places[1:]]
    else:
        lines.append(f"IDS_API_TOKEN={token}")
    written = env_file.with_name(f"{env_file.name}.new")
    written.unlink(missing_ok=True)
    # Readable by its owner only, from the start.
    with os.fdopen(
        os.open(written, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8"
    ) as handle:
        handle.write("\n".join(lines) + "\n")
    written.replace(env_file)
    return token


def _token() -> str:
    """IDS_API_TOKEN, or a new one kept in .env (which git ignores)."""
    token = get_api_token()
    if token:
        return token
    token = save_new_token()
    print(f"Created an API token: IDS_API_TOKEN in {ENV_FILE}")
    return token


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="HTTP API for the IDS dashboard's data.")
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8501, help="port to listen on (default 8501)")
    parser.add_argument(
        "--new-token",
        action="store_true",
        help="put a new, short IDS_API_TOKEN in .env in place of the old one, and stop",
    )
    args = parser.parse_args(argv)

    if args.new_token:
        save_new_token()
        print(
            f"Saved a new API token as IDS_API_TOKEN in {ENV_FILE}. Restart the API to use it; "
            f"see it with: grep IDS_API_TOKEN {ENV_FILE}"
        )
        return

    import uvicorn

    settings = get_settings()
    send_url, send_token = llm_target()
    token = _token() if api_token_required() else None
    if token is None:
        print(
            "No token needed (IDS_API_REQUIRE_TOKEN=false in .env): anyone who can reach "
            f"port {args.port} can see the alerts."
        )
    app = create_app(
        db_path=settings.db_file,
        ids_sources=engine_sources(settings),
        token=token,
        alert_retention=settings.alert_retention,
        state_file=settings.state_file,
        engines=settings.engines,
        archive_dir=settings.alert_archive_dir if settings.alert_archive_days else None,
        archive_settings={
            "keep_days": settings.alert_archive_days,
            "zip_days": settings.alert_archive_zip_days,
        },
        off_periods=machine_off_periods,
        stats_files={
            "snort": settings.snort_perf_file,
            "suricata": settings.suricata_stats_file,
        },
        export_max_alerts=settings.export_max_alerts,
        backup_dir=settings.backup_dir if settings.backup_keep else None,
        send_url=send_url,
        send_token=send_token,
    )
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
