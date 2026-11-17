#!/usr/bin/env python3
"""Receive the dashboard's Send on the LLM PC: each combined JSON file the
Alert Explorer sends is saved in a folder, under the name the dashboard gives
it, for the LLM to read from there.

Copy this one file to the LLM PC (Windows or Linux; Python 3.8 or newer, no
packages) and run it there:

    python llm_receiver.py                      # port 8000, into ./received
    python llm_receiver.py --port 8000 --folder D:\\ids-received --token SECRET

Then, on the IDS machine, in .env (and restart the dashboard):

    IDS_LLM_URL=http://<the LLM PC's address>:8000/
    IDS_LLM_TOKEN=SECRET        # only with --token

Windows asks once whether Python may accept connections: allow it on the
network the IDS machine reaches the PC through. A GET of / answers "ready",
to check the address from a browser.

Each file is written under a temporary name and renamed when complete, so
a program watching the folder never reads half a file. A name already there
gets a number (``…_2.json``); nothing is overwritten. With --token, a send
without "Authorization: Bearer <token>" is refused (401). A body that isn't
JSON is refused (400) and not saved.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The largest file accepted. The dashboard's biggest export (150,000 alerts)
# is a few hundred MB.
MAX_BYTES = 1 << 30
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str | None) -> str:
    """The X-Filename the dashboard gives, as a plain .json file name: no
    folders, only letters, digits, dots, dashes and underscores."""
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    base = _SAFE_NAME.sub("_", base).strip("._")
    if not base:
        base = datetime.now().strftime("ids_send_%Y%m%d_%H%M%S")
    return base if base.lower().endswith(".json") else base + ".json"


def free_path(folder: Path, name: str) -> Path:
    """name in folder, or name_2, name_3, … when it's taken."""
    path = folder / name
    stem, suffix = path.stem, path.suffix
    number = 2
    while path.exists():
        path = folder / f"{stem}_{number}{suffix}"
        number += 1
    return path


def save(folder: Path, name: str, body: bytes) -> Path:
    """body as a new file in folder: written whole under a temporary name,
    then renamed."""
    folder.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=folder, prefix=".receiving-", suffix=".part")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(body)
        # mkstemp makes it readable by its owner only; the LLM may run as
        # another user.
        os.chmod(temporary, 0o644)
        path = free_path(folder, name)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise
    return path


def make_handler(folder: Path, token: str | None):
    class Receiver(BaseHTTPRequestHandler):
        server_version = "IDSReceiver/1"

        def answer(self, status: int, document: dict) -> None:
            body = json.dumps(document).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.answer(200, {"ready": True, "folder": str(folder)})

        def do_POST(self) -> None:
            if token is not None:
                given = self.headers.get("Authorization", "")
                if not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
                    self.answer(401, {"error": "wrong or missing token"})
                    return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.answer(411, {"error": "Content-Length is needed"})
                return
            if not 0 < length <= MAX_BYTES:
                self.answer(413, {"error": f"the body must be 1 byte to {MAX_BYTES} bytes"})
                return
            body = self.rfile.read(length)
            try:
                json.loads(body)
            except ValueError:
                self.answer(400, {"error": "the body isn't JSON"})
                return
            path = save(folder, safe_filename(self.headers.get("X-Filename")), body)
            counts = {
                name[2:].lower().replace("-", "_"): value
                for name, value in self.headers.items()
                if name.lower().startswith("x-") and name.lower() != "x-filename"
            }
            self.log_message("saved %s (%d bytes) %s", path.name, len(body), json.dumps(counts))
            self.answer(200, {"saved": path.name, "bytes": len(body)})

    return Receiver


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="0.0.0.0", help="address to listen on (default: all)")
    parser.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    parser.add_argument("--folder", default="received", help="where files go (default: ./received)")
    parser.add_argument(
        "--token", default=os.environ.get("IDS_LLM_TOKEN") or None,
        help="refuse sends without this bearer token (default: IDS_LLM_TOKEN, else none)",
    )
    args = parser.parse_args(argv)
    folder = Path(args.folder).expanduser().resolve()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(folder, args.token))
    print(f"Receiving on port {args.port} into {folder}"
          f"{' (token required)' if args.token else ''}; Ctrl+C stops.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
