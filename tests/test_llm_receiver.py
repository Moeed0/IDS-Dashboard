import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from scripts.llm_receiver import make_handler, safe_filename


@pytest.fixture
def receiver(tmp_path):
    """A receiver on a free local port; (its URL, its folder, a token setter)."""
    state = {"token": None}
    servers = []

    def start(token=None):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(tmp_path / "in", token))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    state["start"] = start
    yield state, tmp_path / "in"
    for server in servers:
        server.shutdown()
        server.server_close()


def _send(url, body, headers=None):
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", **(headers or {}),
    })
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_a_send_is_saved_under_its_name_and_never_overwritten(receiver):
    state, folder = receiver
    url = state["start"]()
    body = json.dumps({"schema": "ids.combined-detections"}).encode()
    headers = {"X-Filename": "snort_suricata_combined_20261117_1430_newest_20.json", "X-Alerts-Snort": "3"}

    assert _send(url, body, headers) == (200, {
        "saved": "snort_suricata_combined_20261117_1430_newest_20.json", "bytes": len(body),
    })
    assert _send(url, body, headers)[1]["saved"] == "snort_suricata_combined_20261117_1430_newest_20_2.json"
    assert sorted(path.name for path in folder.iterdir()) == [
        "snort_suricata_combined_20261117_1430_newest_20.json",
        "snort_suricata_combined_20261117_1430_newest_20_2.json",
    ]
    assert (folder / "snort_suricata_combined_20261117_1430_newest_20.json").read_bytes() == body
    # A browser's GET says it's ready.
    with urllib.request.urlopen(url, timeout=5) as answer:
        assert json.loads(answer.read())["ready"] is True


def test_a_token_is_required_when_one_is_set(receiver):
    state, folder = receiver
    url = state["start"](token="s3cret")

    assert _send(url, b"{}", {"X-Filename": "a.json"})[0] == 401
    assert _send(url, b"{}", {"X-Filename": "a.json", "Authorization": "Bearer wrong"})[0] == 401
    assert _send(url, b"{}", {"X-Filename": "a.json", "Authorization": "Bearer s3cret"})[0] == 200
    assert [path.name for path in folder.iterdir()] == ["a.json"]


def test_a_body_that_isnt_json_is_refused_and_not_saved(receiver):
    state, folder = receiver
    url = state["start"]()

    assert _send(url, b"not json", {"X-Filename": "a.json"})[0] == 400
    assert not folder.exists() or not any(folder.iterdir())


def test_file_names_stay_inside_the_folder():
    assert safe_filename("../../etc/passwd") == "passwd.json"
    assert safe_filename("..\\..\\Windows\\win.ini") == "win.ini.json"
    assert safe_filename("a b;c.json") == "a_b_c.json"
    assert safe_filename(None).startswith("ids_send_")
