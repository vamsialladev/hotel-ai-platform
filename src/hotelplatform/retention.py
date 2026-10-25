"""Delete ops rows older than the retention period, for one or more apps.

    python -m hotelplatform.retention --apps hotel-ops-assistant,guest-request-agent --days 30

The apps already purge their own rows once a day while they run; this covers apps that sleep for weeks.
"""

import argparse
import sys

from hotelplatform.oplog import OpsStore, safe_error


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", required=True)
    ap.add_argument("--days", type=int, default=30)
    args = ap.parse_args(argv)
    for app in [a.strip() for a in args.apps.split(",") if a.strip()]:
        store = OpsStore(app, retention_days=args.days)
        try:
            print(f"{app}: deleted {store.purge()} rows older than {args.days} days ({store.backend})")
        except Exception as exc:
            print(f"{app}: purge failed ({safe_error(exc)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
