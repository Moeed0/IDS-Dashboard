#!/usr/bin/env python3
"""Send the hourly test alert and check that each engine's alert on it gets
stored (src/ids/test_alert.py). The ids-test-alert timer runs it every hour
(deploy/systemd/ids-test-alert.timer); by hand:
    .venv/bin/python scripts/send_test_alert.py
It pings IDS_TEST_ALERT_TARGET (a machine on the capture network) out of
IDS_INTERFACE; with no target set, there is no test. The result goes to
.runtime/test_alert.json, which the Overview shows. Ends with an error when
an engine's alert didn't come, so systemd marks the run as failed too.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ids.config import get_settings, test_alert_target  # noqa: E402
from ids.test_alert import result_path, run_test  # noqa: E402


def main() -> None:
    settings = get_settings()
    target = test_alert_target()
    if target is None:
        print("IDS_TEST_ALERT_TARGET is empty: no test alert.")
        return
    result = run_test(
        settings.db_file, settings.engines, target, settings.interface, result_path(settings.state_file),
    )
    sent = datetime.fromtimestamp(result["sent_ms"] / 1000).strftime("%H:%M:%S")
    print(f"Pinged {target} from {result['source']} on {settings.interface} at {sent}"
          f" ({'answered' if result['answered'] else 'no answer'})")
    for engine, alert in result["engines"].items():
        if alert:
            print(f"  {engine}: alert {alert['rule']}, stored {alert['stored_after_s']} s after the ping")
        else:
            print(f"  {engine}: NO ALERT within {result['wait_seconds']} s")
    if not result["ok"]:
        sys.exit("The test alert failed: see which engine above, and check it and the collector.")


if __name__ == "__main__":
    main()
