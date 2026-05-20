#!/usr/bin/env python3
"""
K-12 Open Source Security Operations - Proxy Pivot Mocking Engine
License: Apache-2.0

Description:
    Emulates standard output CSV data schemas returned by the Google Admin SDK
    Reports API to simulate a validated geo-fencing bypass evasion loop.
"""

import sys
import csv
from datetime import datetime, timedelta, timezone

# Capture the runtime command line flags to identify targeted logging reports
args = " ".join(sys.argv)

# Establish a sliding reference time metric
base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
base_ts_str = base_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

# Pivot authentication milestone trailing exactly 180 seconds behind
pivot_time = base_time + timedelta(seconds=180)
pivot_ts_str = pivot_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

if "contextawareaccess" in args:
    # Match the case-sensitive matrix fields emitted during a context-aware block
    writer = csv.DictWriter(sys.stdout, fieldnames=["email", "ipaddress", "time", "event"])
    writer.writeheader()
    writer.writerow({
        "email": "adversary-test-account@domain.edu",
        "ipaddress": "185.220.101.5",  # Foreign node signature
        "time": base_ts_str,
        "event": "ACCESS_DENY_EVENT"
    })

elif "logins" in args:
    # Match the case-sensitive matrix fields emitted during a successful login sequence
    writer = csv.DictWriter(sys.stdout, fieldnames=["email", "ipaddress", "time", "event"])
    writer.writeheader()
    writer.writerow({
        "email": "adversary-test-account@domain.edu",
        "ipaddress": "104.244.75.12",  # Domestic US proxy server signature
        "time": pivot_ts_str,          # Bounded explicitly within the trigger limits
        "event": "login_success"
    })