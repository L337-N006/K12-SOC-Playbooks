#!/usr/bin/env python3
"""
K-12 Open Source Security Operations - Context-Aware Access Proxy Pivot Alerter
License: Apache-2.0

Description:
    Streams Google Workspace directory logging architecture to identify high-velocity 
    geographic policy bypass patterns (ACCESS_DENY_EVENT followed by login_success).
    
    Compatible natively with Windows Command Shell, Linux Terminal, and Ubuntu WSL.
"""

import os
import csv
import sys
import json
import logging
import shutil
import subprocess
import urllib.request
from datetime import datetime, timedelta, timezone

# --- Setup Logging conforming to District SecOps standards ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("SecOps.CAA.ProxyAlerter")

# --- OS Detection & Path Resolution ---
IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    logger.info("[*] Detected Windows Environment execution context.")
    # REPLACE: Update this path if your Windows GAM installation directory is different
    DEFAULT_GAM = r"C:\GAMADV-XTD3\gam.exe"
    DEFAULT_STATE = r"C:\SecurityOPS\Logs\alert_state.json"
    DEFAULT_TEMP = r"C:\SecurityOPS\Temp"
else:
    logger.info("[*] Detected POSIX/Linux/WSL Environment execution context.")
    # REPLACE: Change "/home/YOUR_USER/" to match your actual service account or execution user's home path
    DEFAULT_GAM = "/home/YOUR_SERVICE_ACCOUNT/bin/gam7/gam" if os.path.exists("/home/YOUR_SERVICE_ACCOUNT/bin/gam7/gam") else "gam"
    DEFAULT_STATE = os.path.expanduser("~/.gam/alert_state.json")
    DEFAULT_TEMP = "/tmp/secops_caa"

# --- Configurable Environment Variables ---
GAM_PATH = os.environ.get("GAM_PATH", DEFAULT_GAM)
RESOLVED_GAM_PATH = shutil.which(GAM_PATH) or GAM_PATH

LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "360"))
MIN_WINDOW_SEC = int(os.environ.get("MIN_WINDOW_SEC", "120"))
MAX_WINDOW_SEC = int(os.environ.get("MAX_WINDOW_SEC", "300"))

# REPLACE: Insert your production Google Chat Space Incoming Webhook URL here
SOC_ALERTS_WEBHOOK = os.environ.get(
    "SOC_ALERTS_WEBHOOK", 
    "https://chat.googleapis.com/v1/spaces/AAAAXXXX/webhooks/YOUR_WEBHOOK_TOKEN_HERE"
)

STATE_FILE_PATH = os.environ.get("STATE_FILE_PATH", DEFAULT_STATE)
TEMP_DIR = os.environ.get("TEMP_DIR", DEFAULT_TEMP)

def load_alert_state():
    """Loads previously alerted event signatures from disk storage cache."""
    if not os.path.exists(STATE_FILE_PATH):
        return []
    try:
        with open(STATE_FILE_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read alert state file cache: {e}")
        return []

def save_alert_state(state_data):
    """Persists unique event signatures back to disk to enforce idempotency."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE_PATH), exist_ok=True)
        # Cap state array size to protect execution speed
        with open(STATE_FILE_PATH, "w") as f:
            json.dump(state_data[-1000:], f, indent=4)
    except Exception as e:
        logger.error(f"Failed to write alert state file persistence layer: {e}")

def parse_iso_timestamp(ts_str):
    """Normalizes string inputs and parses ISO 8601 strings cleanly into datetime objects."""
    if not ts_str:
        return None
    try:
        ts_str = ts_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except ValueError as e:
        logger.error(f"Failed to parse timestamp '{ts_str}': {e}")
        return None

def get_normalized_field(row, keys_list):
    """Normalizes keys case-insensitively to prevent mapping failures during upstream structural changes."""
    normalized_row = {k.lower().strip() if k else "": v for k, v in row.items()}
    for key in keys_list:
        val = normalized_row.get(key.lower())
        if val is not None:
            return val.strip()
    return None

def send_chat_alert(user_email, deny_time, deny_ip, login_time, login_ip, delta_sec):
    """Constructs and delivers an advanced Cards v2 visualization directly into the SOC environment."""
    if not SOC_ALERTS_WEBHOOK:
        logger.warning(f"Bypass target caught for {user_email} but Webhook variable missing.")
        return

    delta_str = f"{delta_sec // 60}m {delta_sec % 60}s"
    payload = {
        "cardsV2": [
            {
                "cardId": f"caa-proxy-pivot-{int(datetime.now(timezone.utc).timestamp())}",
                "card": {
                    "header": {
                        "title": "🚨 SecOps Alert: Suspicious Proxy Pivot",
                        "subtitle": "Context-Aware Access Bypass Attempt Detected"
                    },
                    "sections": [
                        {
                            "header": "Incident Overview",
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "startIcon": {"knownIcon": "PERSON"},
                                        "text": f"<b>User:</b> {user_email}"
                                    }
                                },
                                {
                                    "decoratedText": {
                                        "startIcon": {"knownIcon": "CLOCK"},
                                        "text": f"<b>Time Delta:</b> {delta_str} ({delta_sec} seconds)"
                                    }
                                }
                            ]
                        },
                        {
                            "header": "Event Sequence",
                            "widgets": [
                                {
                                    "decoratedText": {
                                        "startIcon": {"knownIcon": "CAUTION"},
                                        "text": (
                                            f"<b>1. Blocked Access (Outside Allowed Geo)</b><br>"
                                            f"Time: {deny_time}<br>"
                                            f"IP: {deny_ip}"
                                        )
                                    }
                                },
                                {
                                    "decoratedText": {
                                        "startIcon": {"knownIcon": "SHIELD"},
                                        "text": (
                                            f"<b>2. Successful Login (Inside Allowed Geo/Proxy)</b><br>"
                                            f"Time: {login_time}<br>"
                                            f"IP: {login_ip}"
                                        )
                                    }
                                }
                            ]
                        },
                        {
                            "widgets": [
                                {
                                    "buttonList": {
                                        "buttons": [
                                            {
                                                "text": "Open User Profile",
                                                "onClick": {
                                                    "openLink": {
                                                        "url": f"https://admin.google.com/ac/users/{user_email}"
                                                    }
                                                }
                                            },
                                            {
                                                "text": "Investigate Security Center",
                                                "onClick": {
                                                    "openLink": {
                                                        "url": f"https://admin.google.com/ac/securitycenter/investigation?query=user:%22{user_email}%22"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
    try:
        req = urllib.request.Request(
            SOC_ALERTS_WEBHOOK,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as res:
            logger.info(f"Dispatched alert card successfully. Response Code: {res.getcode()}")
    except Exception as e:
        logger.error(f"Failed to post alert card to Google Chat Webhook: {e}")

def run_gam_to_file(cmd_args, target_file):
    """Executes GAM command and writes the output directly to a temporary file path."""
    os.makedirs(TEMP_DIR, exist_ok=True)
    full_cmd = f'"{RESOLVED_GAM_PATH}" redirect csv "{target_file}" ' + " ".join(cmd_args[4:])
    logger.debug(f"Invoking background command processor: {full_cmd}")
    try:
        process = subprocess.run(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=True
        )
        if process.returncode != 0 and "0 records" not in process.stderr:
            logger.warning(f"GAM operational diagnostic logs: {process.stderr.strip()}")
        return True
    except Exception as e:
        logger.error(f"Subprocess wrapper crash: {e}")
        return False

def fetch_caa_denials(start_str, end_str):
    """Queries context-aware logs and pulls metrics on explicit ACCESS_DENY_EVENT conditions."""
    target_file = os.path.join(TEMP_DIR, "caa_temp.csv")
    cmd_args = [RESOLVED_GAM_PATH, "redirect", "csv", target_file, "report", "contextawareaccess", "start", start_str, "end", end_str]
    
    denials = {}
    if not run_gam_to_file(cmd_args, target_file):
        return denials

    if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
        return denials

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = get_normalized_field(row, ["email", "actor.email", "actor_email"])
                ip = get_normalized_field(row, ["ipaddress", "ip_address", "ip"])
                ts_str = get_normalized_field(row, ["time", "timestamp"])
                event = get_normalized_field(row, ["event", "event_name"])
                if not email or not ts_str:
                    continue
                if event == "ACCESS_DENY_EVENT":
                    dt = parse_iso_timestamp(ts_str)
                    if dt:
                        denials.setdefault(email, []).append((dt, ip, ts_str))
    except Exception as e:
        logger.error(f"Error parsing contextawareaccess file: {e}")
    finally:
        if os.path.exists(target_file):
            try:
                os.remove(target_file)
            except OSError:
                pass
    return denials

def correlate_logins(denials, start_str, end_str):
    """Maps login success indices to identify accounts bouncing geo targets inside the timeline threshold."""
    target_file = os.path.join(TEMP_DIR, "logins_temp.csv")
    cmd_args = [RESOLVED_GAM_PATH, "redirect", "csv", target_file, "report", "logins", "start", start_str, "end", end_str]
    
    if not run_gam_to_file(cmd_args, target_file):
        return

    if not os.path.exists(target_file) or os.path.getsize(target_file) == 0:
        return

    alerted_cache = load_alert_state()
    state_updated = False

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                email = get_normalized_field(row, ["email", "actor.email", "actor_email"])
                ip = get_normalized_field(row, ["ipaddress", "ip_address", "ip"])
                ts_str = get_normalized_field(row, ["time", "timestamp"])
                event = get_normalized_field(row, ["event", "event_name"])
                if not email or not ts_str:
                    continue
                if event == "login_success" and email in denials:
                    login_dt = parse_iso_timestamp(ts_str)
                    if not login_dt:
                        continue
                    for deny_dt, deny_ip, deny_ts_str in denials[email]:
                        delta = (login_dt - deny_dt).total_seconds()
                        if MIN_WINDOW_SEC <= delta <= MAX_WINDOW_SEC:
                            event_fingerprint = f"{email}_{deny_ts_str}_{ts_str}"
                            
                            if event_fingerprint in alerted_cache:
                                logger.info(f"Suppressed duplicate alert signature for user: {email}")
                                continue

                            logger.warning(f"[!!!] PROXY PIVOT MATCHED: {email} bypassed CAA geofencing parameters.")
                            
                            send_chat_alert(
                                user_email=email,
                                deny_time=deny_ts_str,
                                deny_ip=deny_ip,
                                login_time=ts_str,
                                login_ip=ip,
                                delta_sec=int(delta)
                            )
                            
                            alerted_cache.append(event_fingerprint)
                            state_updated = True
                            break
    except Exception as e:
        logger.error(f"Error parsing logins file: {e}")
    finally:
        if os.path.exists(target_file):
            try:
                os.remove(target_file)
            except OSError:
                pass
        if state_updated:
            save_alert_state(alerted_cache)

def main():
    logger.info("Initializing SecOps CAA Proxy Pivot correlation engine.")
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(minutes=LOOKBACK_MINUTES)
    
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    
    logger.info(f"Query Range: {start_str} to {end_str}")
    denials = fetch_caa_denials(start_str, end_str)
    deny_count =
