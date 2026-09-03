#!/usr/bin/env python3
"""HPE iLO 5 minimum-fan-speed enforcer with authenticated web UI.

Mechanism (verified on iLO 5 v3.20 / DL360 Gen10):
  PATCH https://<ilo>/redfish/v1/Chassis/1/Thermal/
        {"Oem": {"Hpe": {"FanPercentMinimum": <0|10..100>}}}

Features:
  - periodic enforcement loop with thermal-guard override (CPU >= threshold -> 100%),
    with a confirmation re-read before escalating so a single noisy sample can't
    spin fans to 100% overnight
  - fan-fault detection: a Redundant-flagged fan stuck at 0% for 2+ cycles forces
    max airflow on the rest and raises an alert, independent of the thermal guard
  - optional quiet-hours window (config-only) that swaps in a lower target during
    a configured time range, reverting automatically outside it
  - optional webhook alerting (ntfy/Discord/generic) on guard activation/release,
    fan faults, and sustained cycle failures
  - force-cycle via GUI button, auto-apply after target change, or SIGUSR1
  - live status panel (fans, temps, guard state, recent activity) served from the
    loop's own GETs, polled by the dashboard over a small JSON API every few
    seconds -- no full-page reloads
  - trend history persists across restarts (history.json)
  - GUI management of dashboard login (PBKDF2) and iLO credentials (apply-verify-revert)
  - optional HTTPS for the dashboard (self-signed via openssl), served by cheroot
    (a real WSGI server) when installed

Usage:
  fan_control.py                 run the service (default)
  fan_control.py set-password    set/generate dashboard password
  fan_control.py set-auto        apply 0% once (restore automatic control) and exit
  fan_control.py check           one-shot: log in, read thermal state, exit
"""
import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from functools import wraps

import requests
import urllib3
from flask import Flask, Response, abort, make_response, redirect, render_template_string, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = "/srv/ilo-fan-control/config.json"
HISTORY_FILE = "/srv/ilo-fan-control/history.json"
TLS_DIR = "/srv/ilo-fan-control/tls"
THERMAL_URI = "/redfish/v1/Chassis/{chassis}/Thermal/"
SESSION_URI = "/redfish/v1/SessionService/Sessions/"
MIN_PCT = 10
MAX_PCT = 100
PBKDF2_ITERATIONS = 200_000
MIN_SECRET_LEN = 8
HISTORY_LEN = 90
ACTIVITY_LOG_LEN = 30
FAN_FAULT_CONFIRM_CYCLES = 2

ACCENT_COLOR = "#3b9eff"
OK_COLOR = "#34c759"
WARN_COLOR = "#ffb020"
DANGER_COLOR = "#ff4d4f"
COLOR_CLASS = {DANGER_COLOR: "c-danger", WARN_COLOR: "c-warn", OK_COLOR: "c-ok"}
HOSTNAME = socket.gethostname()

log = logging.getLogger("ilo-fan-control")

config_lock = threading.Lock()
_last_good_config = None

state_lock = threading.Lock()
shared_state = {
    "fans": [],
    "temps": [],
    "inlet_celsius": None,
    "cpu_max_celsius": None,
    "ilo_min_pct": None,
    "last_enforced_pct": None,
    "resolved_target_pct": None,
    "last_cycle_str": None,
    "last_result": "starting",
    "guard_active": False,
    "fan_fault_ids": [],
    "quiet_hours_active": False,
}
history = deque(maxlen=HISTORY_LEN)
activity_log = deque(maxlen=ACTIVITY_LOG_LEN)
_fan_fault_counts = {}

force_event = threading.Event()
stop_event = threading.Event()

_rate_lock = threading.Lock()
_rate_buckets = {}


def load_config():
    global _last_good_config
    try:
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
        _last_good_config = cfg
        return dict(cfg)
    except (OSError, ValueError) as e:
        log.error("Config load failed (%s); using last known good copy", e)
        if _last_good_config is None:
            raise
        return dict(_last_good_config)


def save_config(cfg):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=4)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def load_history():
    """Restore trend history across restarts so the charts don't reset to
    'Collecting data...' on every deploy/restart."""
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return deque(data[-HISTORY_LEN:], maxlen=HISTORY_LEN)
    except (OSError, ValueError) as e:
        log.info("No usable history file to restore (%s)", e)
    return deque(maxlen=HISTORY_LEN)


def save_history():
    try:
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(list(history), f)
        os.replace(tmp, HISTORY_FILE)
    except OSError as e:
        log.warning("Failed to persist history (%s)", e)


def log_activity(text):
    with state_lock:
        activity_log.appendleft({"t": time.strftime("%Y-%m-%d %H:%M:%S"), "text": text})


def send_alert(cfg, title, message):
    """Best-effort webhook notification. Never raises -- a notification
    failure must not interrupt the control loop. Disabled unless
    alert_webhook_url is set in config.json."""
    url = cfg.get("alert_webhook_url")
    if not url:
        return
    fmt = (cfg.get("alert_webhook_format") or "ntfy").lower()
    try:
        if fmt == "discord":
            requests.post(url, json={"content": "**{}**\n{}".format(title, message)}, timeout=8)
        elif fmt == "generic":
            requests.post(url, json={"title": title, "message": message}, timeout=8)
        else:
            requests.post(url, data=message.encode("utf-8"),
                          headers={"Title": title, "Priority": "high"}, timeout=8)
        log_activity("Alert sent: {}".format(title))
    except requests.RequestException as e:
        log.warning("Alert webhook failed (format=%s): %s", fmt, e)


def clamp_interval(seconds):
    try:
        v = int(seconds)
    except (TypeError, ValueError):
        return 60
    return max(15, min(3600, v))


def c_to_f(celsius):
    """Absolute Celsius reading -> Fahrenheit, for display only. All guard
    logic and config stay in Celsius (thermal_guard_threshold_celsius is the
    source of truth iLO/HPE hardware limits are reasoned about in)."""
    return celsius * 9.0 / 5.0 + 32.0


def c_delta_to_f(delta_celsius):
    """A temperature *difference* (e.g. headroom) -> Fahrenheit degrees.
    No +32 offset -- that only applies to absolute readings."""
    return delta_celsius * 9.0 / 5.0


def hash_password(password, salt_hex):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS
    ).hex()


class IloClient:
    def __init__(self):
        self.http = requests.Session()
        self.http.verify = False
        self.token = None
        self.session_uri = None
        self.ip = None

    def login(self, cfg, username=None, password=None):
        self.ip = cfg["ilo_ip"]
        r = self.http.post(
            "https://" + self.ip + SESSION_URI,
            json={"UserName": username or cfg["ilo_user"],
                  "Password": password or cfg["ilo_password"]},
            headers={"Content-Type": "application/json"},
            timeout=cfg.get("request_timeout_seconds", 15),
        )
        if r.status_code != 201:
            self.token = None
            raise RuntimeError(
                "iLO login failed HTTP {}: {}".format(r.status_code, r.text[:200])
            )
        self.token = r.headers.get("X-Auth-Token")
        self.session_uri = r.headers.get("Location")
        if not self.token:
            raise RuntimeError("iLO login returned no X-Auth-Token")

    def logout(self):
        if self.session_uri and self.ip:
            try:
                self.http.delete("https://" + self.ip + self.session_uri, timeout=5)
            except requests.RequestException:
                pass
        self.token = None
        self.session_uri = None

    def _retry(self, method, url, **kw):
        attempts = int(kw.pop("attempts", 3))
        delay = 2
        last_exc = None
        for i in range(attempts):
            try:
                return self.http.request(method, url, **kw)
            except requests.RequestException as e:
                last_exc = e
                log.warning("%s %s failed (attempt %d/%d): %s",
                            method, url, i + 1, attempts, e)
                time.sleep(delay)
                delay *= 2
        raise last_exc

    def get_thermal(self, cfg):
        url = "https://" + self.ip + THERMAL_URI.format(chassis=cfg.get("chassis_id", 1))
        r = self._retry(
            "GET", url,
            headers={"X-Auth-Token": self.token},
            timeout=cfg.get("request_timeout_seconds", 15),
        )
        if r.status_code != 200:
            raise RuntimeError(
                "GET Thermal failed HTTP {}: {}".format(r.status_code, r.text[:200])
            )
        return r.json(), r.headers.get("ETag")

    def patch_minimum(self, cfg, etag, pct):
        url = "https://" + self.ip + THERMAL_URI.format(chassis=cfg.get("chassis_id", 1))
        headers = {"X-Auth-Token": self.token, "Content-Type": "application/json"}
        if etag:
            headers["If-Match"] = etag
        r = self._retry(
            "PATCH", url,
            json={"Oem": {"Hpe": {"FanPercentMinimum": pct}}},
            headers=headers,
            timeout=cfg.get("request_timeout_seconds", 15),
        )
        ok = r.status_code in (200, 204)
        if not ok:
            log.error("PATCH FanPercentMinimum=%s%% failed HTTP %s: %s",
                      pct, r.status_code, r.text[:300])
        return ok

    def close(self):
        self.logout()
        self.http.close()


def probe_ilo_login(ip, username, password):
    s = requests.Session()
    s.verify = False
    try:
        r = s.post(
            "https://" + ip + SESSION_URI,
            json={"UserName": username, "Password": password},
            headers={"Content-Type": "application/json"},
            timeout=12,
        )
    except requests.RequestException as e:
        return False, str(e)[:150]
    loc = r.headers.get("Location")
    if r.status_code == 201 and loc:
        try:
            s.delete("https://" + ip + loc, timeout=5)
        except requests.RequestException:
            pass
        return True, "login succeeded"
    return False, "HTTP {} ({})".format(r.status_code, r.text[:120])


def set_ilo_account_credentials(ip, admin_user, admin_pass, target_user,
                                new_user, new_password):
    """Apply credential change on the iLO, verify with a fresh login,
    and automatically revert if verification fails."""
    base = "https://" + ip
    s = requests.Session()
    s.verify = False

    def patch_acct(token, uri, payload, etag=None):
        headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
        if etag:
            headers["If-Match"] = etag
        return s.patch(base + uri, json=payload, headers=headers, timeout=15)

    def find_account(token, username):
        ra = s.get(base + "/redfish/v1/AccountService/Accounts/",
                   headers={"X-Auth-Token": token}, timeout=15)
        if ra.status_code != 200:
            return None, None
        for m in ra.json().get("Members", []):
            u = s.get(base + m["@odata.id"], headers={"X-Auth-Token": token}, timeout=15)
            if u.status_code == 200 and u.json().get("UserName") == username:
                return m["@odata.id"], u.headers.get("ETag")
        return None, None

    try:
        r = s.post(base + SESSION_URI,
                   json={"UserName": admin_user, "Password": admin_pass},
                   headers={"Content-Type": "application/json"}, timeout=15)
        if r.status_code != 201:
            return False, "admin login failed HTTP {}".format(r.status_code)
        token = r.headers.get("X-Auth-Token")
        admin_loc = r.headers.get("Location")
        try:
            acct_uri, etag = find_account(token, target_user)
            if not acct_uri:
                return False, "account {} not found on iLO".format(target_user)

            payload = {}
            if new_user and new_user != target_user:
                payload["UserName"] = new_user
            payload["Password"] = new_password
            rp = patch_acct(token, acct_uri, payload, etag)
            if rp.status_code not in (200, 204):
                return False, "iLO rejected change: HTTP {} {}".format(
                    rp.status_code, rp.text[:150])

            ok, detail = probe_ilo_login(ip, new_user or target_user, new_password)
            if ok:
                return True, "applied and verified"
            log.error("iLO credential verification FAILED (%s); reverting", detail)
            rr = patch_acct(token, acct_uri,
                            {"UserName": target_user, "Password": admin_pass})
            if rr.status_code in (200, 204) and probe_ilo_login(ip, target_user, admin_pass)[0]:
                return False, "verification failed; change reverted ({})".format(detail)
            log.critical("iLO REVERT FAILED - restore access manually via iLO web UI!")
            return False, "verification failed AND revert failed; fix via iLO web UI"
        finally:
            if admin_loc:
                try:
                    s.delete(base + admin_loc, timeout=5)
                except requests.RequestException:
                    pass
    except requests.RequestException as e:
        return False, str(e)[:150]


def summarize_thermal(thermal):
    fans = []
    for f in thermal.get("Fans", []):
        reading = f.get("Reading")
        fans.append({
            "id": f.get("MemberId"),
            "percent": reading if isinstance(reading, (int, float)) else 0,
            "redundant": bool(f.get("Oem", {}).get("Hpe", {}).get("Redundant")),
        })
    temps = []
    inlet = None
    cpu_vals = []
    for t in thermal.get("Temperatures", []):
        c = t.get("ReadingCelsius")
        if not isinstance(c, (int, float)) or c <= 0:
            continue
        name = str(t.get("Name", ""))
        temps.append({"name": name, "celsius": c})
        if "inlet" in name.lower():
            inlet = c
        name_l = name.lower()
        if "cpu" in name_l and "fan" not in name_l:
            cpu_vals.append(c)
    temps.sort(key=lambda x: x["celsius"], reverse=True)
    return {
        "fans": fans,
        "temps": temps[:8],
        "inlet_celsius": inlet,
        "cpu_max_celsius": max(cpu_vals) if cpu_vals else None,
        "ilo_min_pct": thermal.get("Oem", {}).get("Hpe", {}).get("FanPercentMinimum"),
    }


def record_state(summary, **kw):
    with state_lock:
        shared_state.update(summary)
        shared_state.update(kw)
        shared_state["last_cycle_str"] = time.strftime("%Y-%m-%d %H:%M:%S")
        history.append({
            "t": time.time(),
            "cpu": shared_state.get("cpu_max_celsius"),
            "enforced": shared_state.get("last_enforced_pct"),
        })
    save_history()


def threshold_color(value, warn_at, danger_at):
    if value is None:
        return None
    if value >= danger_at:
        return DANGER_COLOR
    if value >= warn_at:
        return WARN_COLOR
    return OK_COLOR


def _smooth_path(points):
    """Catmull-Rom -> cubic Bezier through `points` ([(x, y), ...]) so trend
    lines read as smooth curves instead of jagged straight segments."""
    if len(points) < 2:
        x, y = points[0]
        return "M {:.1f},{:.1f}".format(x, y)
    if len(points) == 2:
        (x0, y0), (x1, y1) = points
        return "M {:.1f},{:.1f} L {:.1f},{:.1f}".format(x0, y0, x1, y1)
    pts = [points[0]] + list(points) + [points[-1]]
    d = "M {:.1f},{:.1f}".format(*points[0])
    for i in range(1, len(pts) - 2):
        p0, p1, p2, p3 = pts[i - 1], pts[i], pts[i + 1], pts[i + 2]
        c1x = p1[0] + (p2[0] - p0[0]) / 6.0
        c1y = p1[1] + (p2[1] - p0[1]) / 6.0
        c2x = p2[0] - (p3[0] - p1[0]) / 6.0
        c2y = p2[1] - (p3[1] - p1[1]) / 6.0
        d += " C {:.1f},{:.1f} {:.1f},{:.1f} {:.1f},{:.1f}".format(c1x, c1y, c2x, c2y, p2[0], p2[1])
    return d


def render_stat_spark(values, width=140, height=36, color=ACCENT_COLOR):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return ""
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    pad = 2
    n = len(vals)
    pts = []
    for i, v in enumerate(vals):
        x = pad + (i / (n - 1)) * (width - 2 * pad) if n > 1 else width / 2
        y = height - ((v - lo) / span) * (height - pad)
        pts.append((x, y))
    line_d = _smooth_path(pts)
    area_d = "{} L {:.1f},{:.1f} L {:.1f},{:.1f} Z".format(line_d, pts[-1][0], height, pts[0][0], height)
    return (
        '<svg width="100%" height="{h}" viewBox="0 0 {w} {h}" preserveAspectRatio="none">'
        '<path d="{area}" fill="{c}" opacity="0.3" stroke="none"/>'
        '<path d="{line}" fill="none" stroke="{c}" stroke-width="1.5" opacity="0.6" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '</svg>'
    ).format(w=width, h=height, area=area_d, c=color, line=line_d)


def render_timeseries(values, width=600, height=110, color=ACCENT_COLOR, ref=None, unit="", min_points=4):
    vals = [v for v in values if v is not None]
    if len(vals) < min_points:
        return (
            '<div class="ts-wrap"><div class="spark-empty" style="height:{h}px;line-height:{h}px;">'
            'Collecting data&hellip; ({n}/{m} samples)</div></div>'
        ).format(h=height, n=len(vals), m=min_points)

    bounds = vals + ([ref] if ref is not None else [])
    lo, hi = min(bounds), max(bounds)
    span = (hi - lo) or 1
    pad = 6

    def y_of(v):
        return height - pad - ((v - lo) / span) * (height - 2 * pad)

    n = len(vals)
    xs = []
    pts = []
    for i, v in enumerate(vals):
        x = pad + (i / (n - 1)) * (width - 2 * pad) if n > 1 else width / 2
        xs.append(x)
        pts.append((x, y_of(v)))
    line_d = _smooth_path(pts)
    baseline = height - pad
    area_d = "{} L {:.1f},{:.1f} L {:.1f},{:.1f} Z".format(line_d, pts[-1][0], baseline, pts[0][0], baseline)

    ref_line = ""
    if ref is not None:
        ry = y_of(ref)
        ref_line = (
            '<line x1="{p}" y1="{y:.1f}" x2="{w}" y2="{y:.1f}" stroke="{c}" '
            'stroke-width="1" stroke-dasharray="4,4" opacity="0.6"/>'
        ).format(p=pad, y=ry, w=width - pad, c=DANGER_COLOR)

    grid = ""
    for frac in (0.0, 0.5, 1.0):
        gy = pad + frac * (height - 2 * pad)
        grid += (
            '<line x1="{p}" y1="{y:.1f}" x2="{w}" y2="{y:.1f}" stroke="#262a33" stroke-width="1"/>'
        ).format(p=pad, y=gy, w=width - pad)

    last_x, last_y = pts[-1]
    dot = '<circle cx="{:.1f}" cy="{:.1f}" r="3" fill="{}"/>'.format(last_x, last_y, color)

    # Invisible wide hit-targets per point so hover works even with sparse samples.
    hit_w = max((width - 2 * pad) / max(n - 1, 1), 6)
    hits = []
    for x, v in zip(xs, vals):
        hits.append(
            '<rect x="{x:.1f}" y="0" width="{hw:.1f}" height="{h}" fill="transparent" '
            'class="spark-hit" data-v="{v}" data-x="{xp:.2f}"/>'.format(
                x=x - hit_w / 2, hw=hit_w, h=height, v=round(v, 1), xp=(x / width) * 100)
        )

    svg = (
        '<svg width="100%" height="{h}" viewBox="0 0 {w} {h}" preserveAspectRatio="none" '
        'class="spark" data-unit="{unit}">'
        '{grid}{ref_line}'
        '<path d="{area_d}" fill="{color}" opacity="0.15" stroke="none"/>'
        '<path d="{line_d}" fill="none" stroke="{color}" stroke-width="1.75" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        '{dot}{hits}</svg>'
    ).format(w=width, h=height, unit=unit, grid=grid, ref_line=ref_line, area_d=area_d,
              color=color, line_d=line_d, dot=dot, hits="".join(hits))

    return (
        '<div class="ts-wrap">'
        '<div class="ts-axis"><span>{hi:.0f}</span><span>{lo:.0f}</span></div>'
        '<div class="ts-plot">{svg}<div class="crosshair"></div></div>'
        '</div>'
    ).format(hi=hi, lo=lo, svg=svg)


def compute_health(status, cfg):
    threshold = float(cfg.get("thermal_guard_threshold_celsius", 85))
    interval = clamp_interval(cfg.get("check_interval_seconds", 60))
    last_result = status.get("last_result") or ""
    cpu_max = status.get("cpu_max_celsius")
    guard_active = status.get("guard_active")

    stale = True
    last_cycle_str = status.get("last_cycle_str")
    if last_cycle_str:
        try:
            last_ts = time.mktime(time.strptime(last_cycle_str, "%Y-%m-%d %H:%M:%S"))
            stale = (time.time() - last_ts) > interval * 3
        except ValueError:
            stale = True

    fan_faults = status.get("fan_fault_ids") or []

    if stale:
        return "critical", "Control loop hasn't reported recently — check the service"
    if last_result.startswith("error"):
        return "critical", "Last cycle failed: {}".format(last_result)
    if fan_faults:
        return "critical", "Fan {} not spinning up — possible hardware failure".format(
            ", ".join("#{}".format(i) for i in fan_faults))
    if guard_active:
        return "warning", "Thermal guard is overriding your target to cool things down"
    if cpu_max is not None and cpu_max >= threshold - 10:
        return "warning", "CPU running warm, approaching the guard threshold"
    return "ok", "Everything nominal"


def check_fan_faults(fans):
    """A Redfish-reported Redundant fan reading 0% for FAN_FAULT_CONFIRM_CYCLES
    consecutive cycles is treated as a hardware fault -- iLO only marks fans
    "Redundant" when they're part of the active cooling group, so a redundant
    fan idle at 0% (unlike the non-redundant/absent bays, which are normal)
    means it should be spinning and isn't. Requires persistence across
    cycles so one noisy sample doesn't trigger a false alarm."""
    global _fan_fault_counts
    faulted = []
    seen_ids = set()
    for f in fans:
        fid = f["id"]
        seen_ids.add(fid)
        if f.get("redundant") and f.get("percent") == 0:
            _fan_fault_counts[fid] = _fan_fault_counts.get(fid, 0) + 1
        else:
            _fan_fault_counts[fid] = 0
        if _fan_fault_counts[fid] >= FAN_FAULT_CONFIRM_CYCLES:
            faulted.append(fid)
    for fid in list(_fan_fault_counts):
        if fid not in seen_ids:
            del _fan_fault_counts[fid]
    return faulted


def _parse_hhmm(text):
    hh, mm = text.split(":")
    hh, mm = int(hh), int(mm)
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        raise ValueError("out of range")
    return hh * 60 + mm


def resolve_target(cfg):
    """Normal target, unless quiet hours are enabled and we're currently
    inside the configured window -- returns (target_pct, quiet_active)."""
    base_target = int(cfg["target_fan_percentage"])
    if not cfg.get("quiet_hours_enabled"):
        return base_target, False
    try:
        start = _parse_hhmm(cfg.get("quiet_hours_start", "22:00"))
        end = _parse_hhmm(cfg.get("quiet_hours_end", "07:00"))
        quiet_target = int(cfg.get("quiet_hours_target_fan_percentage", base_target))
    except (ValueError, TypeError, KeyError):
        log.warning("Invalid quiet_hours_* config; ignoring quiet hours this cycle")
        return base_target, False
    quiet_target = max(MIN_PCT, min(MAX_PCT, quiet_target))
    now = time.localtime()
    now_min = now.tm_hour * 60 + now.tm_min
    if start <= end:
        in_window = start <= now_min < end
    else:
        in_window = now_min >= start or now_min < end
    return (quiet_target, True) if in_window else (base_target, False)


AWAY_CURVE_COOL_C = 45.0  # at/below this, Away Mode uses the minimum floor


def compute_away_target(cpu_max_c, threshold_c, min_pct, max_pct):
    """Away Mode's fan floor as a function of current CPU temp: min_pct
    when cool (<= AWAY_CURVE_COOL_C), ramping linearly up to max_pct by the
    time CPU is within 5C of the guard threshold -- so cooling responds
    proactively as load rises instead of sitting flat until the reactive
    100% guard override is the only thing left to catch it.

    max_pct=0 means fully automatic (hands entirely to iLO) regardless of
    temperature. min_pct >= max_pct means a flat floor at max_pct."""
    if max_pct <= 0:
        return 0
    if cpu_max_c is None or min_pct >= max_pct:
        return max_pct
    hot_c = threshold_c - 5.0
    if hot_c <= AWAY_CURVE_COOL_C:
        return max_pct if cpu_max_c >= AWAY_CURVE_COOL_C else min_pct
    if cpu_max_c <= AWAY_CURVE_COOL_C:
        return min_pct
    if cpu_max_c >= hot_c:
        return max_pct
    frac = (cpu_max_c - AWAY_CURVE_COOL_C) / (hot_c - AWAY_CURVE_COOL_C)
    return int(round(min_pct + frac * (max_pct - min_pct)))


THERMOSTAT_GAIN = 2.5       # percentage points of fan speed per degree C of error
THERMOSTAT_MAX_STEP = 20.0  # cap how far one cycle can move fan speed, to damp oscillation


def compute_thermostat_step(cpu_max_c, setpoint_c, prev_pct, min_pct, max_pct,
                             gain=THERMOSTAT_GAIN, max_step=THERMOSTAT_MAX_STEP):
    """One proportional-control step toward an ideal temperature: nudge the
    previous cycle's fan% by `gain` points per degree C of error (current -
    setpoint), rate-limited to `max_step` points/cycle so a single noisy
    reading can't slam the fans, then clamp to [min_pct, max_pct]. This
    converges toward whatever fan speed holds CPU near setpoint_c, adapting
    automatically as load changes -- unlike the fixed curve, it has memory
    of where it already was."""
    if prev_pct is None or not (min_pct <= prev_pct <= max_pct):
        prev_pct = max_pct  # no continuity to build on yet -- err toward more cooling
    if cpu_max_c is None:
        return int(round(max(min_pct, min(max_pct, prev_pct))))
    error = cpu_max_c - setpoint_c
    delta = max(-max_step, min(max_step, gain * error))
    new_pct = prev_pct + delta
    return int(round(max(min_pct, min(max_pct, new_pct))))


def f_to_c(fahrenheit):
    return (fahrenheit - 32.0) * 5.0 / 9.0


def _get_thermal_resilient(ilo, cfg):
    """GET thermal state, transparently re-authenticating once if the
    held session has expired (HTTP 401), instead of failing the whole cycle."""
    try:
        return ilo.get_thermal(cfg)
    except RuntimeError as e:
        if "HTTP 401" in str(e):
            log.info("iLO session expired; re-authenticating")
            ilo.login(cfg)
            return ilo.get_thermal(cfg)
        raise


def run_cycle(ilo):
    cfg = load_config()
    try:
        target, quiet_active = resolve_target(cfg)
    except (TypeError, ValueError, KeyError):
        log.error("Invalid target_fan_percentage in config; skipping cycle")
        return
    if not MIN_PCT <= target <= MAX_PCT:
        log.error("target_fan_percentage %s out of range; skipping cycle", target)
        return

    # Reuse one session across cycles instead of a fresh login/logout every
    # time — cuts per-cycle latency and iLO session churn. _get_thermal_resilient
    # transparently re-authenticates if the held session has expired.
    if ilo.token is None:
        ilo.login(cfg)

    thermal, etag = _get_thermal_resilient(ilo, cfg)
    summary = summarize_thermal(thermal)
    cpu_max = summary["cpu_max_celsius"]

    guard_enabled = bool(cfg.get("thermal_guard_enabled", True))
    threshold = float(cfg.get("thermal_guard_threshold_celsius", 85))
    hysteresis = float(cfg.get("thermal_guard_hysteresis_celsius", 5))
    confirm_delay = float(cfg.get("thermal_guard_confirm_seconds", 8))

    # Away Mode enforces automatic control instead of your normal target,
    # either a fixed curve (temp -> fan%, memoryless) or a thermostat
    # (proportional control toward an ideal temperature, with memory of the
    # previous cycle's speed) -- so cooling responds proactively rather than
    # sitting flat until the reactive 100% guard is all that's left.
    # (away_max=0 means fully automatic, hands entirely to iLO; away_min >=
    # away_max means a flat floor.) This does NOT disable thermal guard or
    # fan-fault protection -- those are safety systems, not manual controls,
    # and stay active regardless of Away Mode.
    away_mode = bool(cfg.get("manual_controls_locked"))
    if away_mode:
        try:
            away_min = max(0, min(MAX_PCT, int(cfg.get("away_min_fan_percentage", 25))))
        except (TypeError, ValueError):
            away_min = 25
        try:
            away_max = max(0, min(MAX_PCT, int(cfg.get("away_max_fan_percentage", 65))))
        except (TypeError, ValueError):
            away_max = 65
        control_mode = (cfg.get("away_control_mode") or "curve").lower()

        if away_max <= 0:
            baseline = 0
            baseline_desc = "iLO automatic control (Away Mode)"
        elif control_mode == "thermostat":
            try:
                setpoint = float(cfg.get("away_ideal_temp_celsius", 55))
            except (TypeError, ValueError):
                setpoint = 55.0
            with state_lock:
                prev_pct = shared_state.get("last_enforced_pct")
            baseline = compute_thermostat_step(cpu_max, setpoint, prev_pct, away_min, away_max)
            baseline_desc = "Away Mode thermostat {}% (CPU {}C -> {:.0f}C target)".format(
                baseline, "?" if cpu_max is None else "{:.0f}".format(cpu_max), setpoint)
        else:
            baseline = compute_away_target(cpu_max, threshold, away_min, away_max)
            if away_min >= away_max:
                baseline_desc = "Away Mode target {}%".format(baseline)
            else:
                baseline_desc = "Away Mode curve {}% (CPU {}C, {}-{}%)".format(
                    baseline, "?" if cpu_max is None else "{:.0f}".format(cpu_max), away_min, away_max)

        # Away Mode normally overrides quiet hours entirely (its own
        # curve/thermostat floor takes over). If quiet_hours_overrides_away_mode
        # is set, treat the quiet-hours target as a ceiling instead: never
        # force MORE airflow than that during the quiet window, even while
        # Away Mode is locked. It can still go quieter than that if Away
        # Mode's own strategy already wants less. Thermal guard/fan-fault
        # protection (applied further below) are unaffected either way.
        if quiet_active and bool(cfg.get("quiet_hours_overrides_away_mode")) and baseline > target:
            log.info("Quiet hours active; capping %s at %d%% (was %d%%)",
                     baseline_desc, target, baseline)
            baseline_desc = "{} capped to {}% by quiet hours".format(baseline_desc, target)
            baseline = target
    else:
        baseline = target
        baseline_desc = "configured target {}%".format(target)

    with state_lock:
        was_active = shared_state["guard_active"]
        was_faulted = set(shared_state.get("fan_fault_ids") or [])
    effective = baseline
    guard_now = was_active

    if guard_enabled and cpu_max is not None:
        if was_active:
            if cpu_max < threshold - hysteresis:
                guard_now = False
                log.info("Thermal guard released (CPU max %.0fC < %.0fC); resuming %s",
                         cpu_max, threshold - hysteresis, baseline_desc)
            else:
                effective = MAX_PCT
        elif cpu_max >= threshold:
            # A single elevated sample can be a transient turbo-boost
            # spike rather than sustained load. Confirm with one more
            # read a few seconds later before overriding to 100%, so a
            # blip that's gone by the next reading doesn't spin fans up.
            log.info("CPU max %.0fC >= %.0fC; confirming before override "
                     "(re-checking in %.0fs)", cpu_max, threshold, confirm_delay)
            time.sleep(confirm_delay)
            thermal2, etag2 = _get_thermal_resilient(ilo, cfg)
            summary2 = summarize_thermal(thermal2)
            cpu_max2 = summary2["cpu_max_celsius"]
            if cpu_max2 is not None and cpu_max2 >= threshold:
                guard_now = True
                effective = MAX_PCT
                summary, etag, cpu_max = summary2, etag2, cpu_max2
                log.warning("THERMAL GUARD CONFIRMED: CPU max %.0fC >= %.0fC; "
                            "overriding target %s%% -> %d%%",
                            cpu_max2, threshold, target, MAX_PCT)
            else:
                # Not confirmed, so no guard override -- but the confirm
                # read is still the most recent, most accurate snapshot we
                # have. Use it for display, otherwise the dashboard is left
                # showing the stale spike (and a headroom/guard mismatch)
                # for up to a full interval after it already passed.
                summary, etag, cpu_max = summary2, etag2, cpu_max2
                log.info("Thermal spike was transient (CPU max settled at %sC); "
                         "no override", cpu_max2)

    # A confirmed hardware fault always wins: force max airflow on the
    # remaining fans regardless of target/guard state.
    faulted = check_fan_faults(summary["fans"])
    if faulted:
        effective = MAX_PCT
        if set(faulted) != was_faulted:
            names = ", ".join("#{}".format(i) for i in faulted)
            log.critical("FAN FAULT: %s reporting 0%% while marked redundant "
                         "(likely failed); forcing 100%% on remaining fans", names)
            log_activity("Fan fault detected: {}".format(names))
            send_alert(cfg, "iLO Fan Control: FAN FAULT",
                       "Fan(s) {} not spinning (0% while redundant). "
                       "Forcing remaining fans to 100%.".format(names))
    elif was_faulted:
        log.info("Fan fault cleared (previously: %s)",
                 ", ".join("#{}".format(i) for i in was_faulted))
        log_activity("Fan fault cleared")
        send_alert(cfg, "iLO Fan Control: fan fault cleared",
                   "Previously faulted fan(s) are reporting normal speeds again.")

    if guard_now != was_active:
        if guard_now:
            log_activity("Thermal guard ACTIVE (CPU {:.0f}C >= {:.0f}C)".format(cpu_max, threshold))
            send_alert(cfg, "iLO Fan Control: thermal guard ACTIVE",
                       "CPU max hit {:.0f}C (threshold {:.0f}C) -- "
                       "fans forced to 100%.".format(cpu_max, threshold))
        else:
            log_activity("Thermal guard released")
            send_alert(cfg, "iLO Fan Control: thermal guard released",
                       "Temps dropped back down; resuming {}.".format(baseline_desc))

    if effective != summary["ilo_min_pct"]:
        ok = ilo.patch_minimum(cfg, etag, effective)
        if ok:
            log.info("Enforced FanPercentMinimum=%s%% (was %s%%)%s",
                     effective, summary["ilo_min_pct"],
                     " [GUARD]" if guard_now and effective != baseline else "")
            # The `summary` above was captured BEFORE the patch, so its fan/
            # sensor readings are one cycle stale relative to the change we
            # just made. Re-read so the dashboard reflects reality, not the
            # pre-change snapshot (this was showing old fan speeds after
            # every target change until fixed).
            try:
                thermal3, _ = _get_thermal_resilient(ilo, cfg)
                summary = summarize_thermal(thermal3)
            except Exception as e:
                log.warning("Post-patch refresh read failed (%s); showing pre-patch snapshot", e)
    else:
        log.info("FanPercentMinimum already %s%% (%s); fans=%s%s",
                 effective, baseline_desc, [f["percent"] for f in summary["fans"]],
                 " [GUARD ACTIVE]" if guard_now else "")

    record_state(
        summary,
        last_enforced_pct=effective,
        resolved_target_pct=baseline,
        last_result="ok",
        guard_active=guard_now,
        fan_fault_ids=faulted,
        quiet_hours_active=quiet_active,
    )


ERROR_ALERT_THRESHOLD = 3
_consecutive_errors = 0


def fan_control_loop():
    global _consecutive_errors
    ilo = IloClient()
    while not stop_event.is_set():
        interval = 30
        try:
            run_cycle(ilo)
            interval = clamp_interval(load_config().get("check_interval_seconds", 60))
            if _consecutive_errors >= ERROR_ALERT_THRESHOLD:
                cfg = load_config()
                log_activity("Recovered after {} failed cycles".format(_consecutive_errors))
                send_alert(cfg, "iLO Fan Control: recovered",
                           "Control loop is healthy again after {} consecutive "
                           "failed cycles.".format(_consecutive_errors))
            _consecutive_errors = 0
        except Exception as e:
            _consecutive_errors += 1
            log.exception("Loop error: %s", e)
            with state_lock:
                shared_state["last_result"] = "error: {}".format(e)
            if _consecutive_errors == ERROR_ALERT_THRESHOLD:
                cfg = load_config()
                log_activity("ALERT: {} consecutive cycle failures ({})".format(_consecutive_errors, e))
                send_alert(cfg, "iLO Fan Control: ERROR",
                           "{} consecutive cycle failures. Last error: {}".format(
                               _consecutive_errors, e))
        woken = force_event.wait(interval)
        force_event.clear()
    ilo.close()
    log.info("Fan control loop stopped")


app = Flask(__name__)
app.jinja_env.autoescape = True

BASE_STYLE = """
    :root {
        --bg: #0d0e12;
        --card: #16181f;
        --card-border: #262a35;
        --text: #d8dbe1;
        --text-dim: #868c99;
        --accent: #3b9eff;
        --ok: #34c759;
        --ok-bg: rgba(52,199,89,0.10);
        --warn: #ffb020;
        --warn-bg: rgba(255,176,32,0.10);
        --danger: #ff4d4f;
        --danger-bg: rgba(255,77,79,0.12);
        --muted: #454a55;
    }
    * { box-sizing: border-box; }
    body {
        font-family: 'Inter', -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background: var(--bg); color: var(--text); margin: 0; padding: 14px 14px 32px; font-size: 13px;
        font-feature-settings: 'tnum' 1, 'cv05' 1;
    }
    .topbar {
        display: flex; align-items: baseline; gap: 8px;
        max-width: 1800px; margin: 0 auto 10px;
    }
    .topbar .brand { font-size: 16px; font-weight: 700; color: #fff; }
    .topbar .host { color: var(--text-dim); font-weight: 400; font-size: 12px; }
    .ilo-icon { color: var(--text-dim); display: flex; align-items: center; }
    .ilo-icon:hover { color: var(--accent); }
    .live-dot {
        width: 7px; height: 7px; border-radius: 50%; background: var(--ok);
        box-shadow: 0 0 6px var(--ok); animation: pulse 2s ease-in-out infinite;
    }
    .live-dot.stale { background: var(--danger); box-shadow: 0 0 6px var(--danger); animation: none; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
    nav { margin-left: auto; }
    nav a { color: var(--text-dim); text-decoration: none; margin-left: 14px; font-size: 12px; }
    nav a:hover, nav a.active { color: var(--accent); }
    a { color: var(--accent); }

    .toast { max-width: 1800px; margin: 0 auto 8px; padding: 8px 14px; border-radius: 4px; font-size: 13px; }
    .toast.ok { background: var(--ok-bg); color: var(--ok); }
    .toast.error { background: var(--danger-bg); color: var(--danger); }

    .dash { max-width: 1800px; margin: 0 auto; }

    .panel, .card {
        background: var(--card); border: 1px solid var(--card-border); border-radius: 8px;
        padding: 14px 16px; transition: background-color 0.4s ease;
    }
    .panel-h, .card h3 {
        margin: 0 0 8px; font-size: 10.5px; color: var(--text-dim); text-transform: uppercase;
        letter-spacing: 0.05em; font-weight: 600;
    }

    .stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-bottom: 10px; }
    .stat { position: relative; overflow: hidden; min-height: 92px; }
    .stat.status-ok { background: var(--ok-bg); border-color: rgba(52,199,89,0.3); }
    .stat.status-warning { background: var(--warn-bg); border-color: rgba(255,176,32,0.35); }
    .stat.status-critical { background: var(--danger-bg); border-color: rgba(255,77,79,0.4); }
    .stat-spark-bg { position: absolute; left: 0; right: 0; bottom: 0; height: 42%; opacity: 0.7; }
    .stat-value {
        position: relative; font-size: 23px; font-weight: 700; margin-top: 3px;
        font-variant-numeric: tabular-nums; color: #fff; letter-spacing: -0.01em;
        text-shadow: 0 0 8px var(--card), 0 0 8px var(--card), 0 1px 0 var(--card);
    }
    .stat-value.c-ok { color: var(--ok); }
    .stat-value.c-warn { color: var(--warn); }
    .stat-value.c-danger { color: var(--danger); }
    .stat-sub {
        position: relative; font-size: 11px; color: var(--text-dim); margin-top: 3px; line-height: 1.5;
        text-shadow: 0 0 6px var(--card), 0 0 6px var(--card);
    }

    .main-grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 10px; }
    .col-3 { grid-column: span 3; }
    .col-4 { grid-column: span 4; }
    .col-5 { grid-column: span 5; }
    .col-6 { grid-column: span 6; }
    .col-12 { grid-column: span 12; }
    @media (max-width: 760px) {
        .main-grid { grid-template-columns: 1fr; }
        .main-grid [class*="col-"] { grid-column: span 1; }
    }

    .grid { max-width: 1800px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }
    .span-2 { grid-column: span 2; }

    #stat-row, #cpu-chart, #fan-chart, #fans-list, #sensors-table, #activity-log, #footer-text { transition: opacity 0.25s ease; }
    .fading { opacity: 0.45; }

    .activity-list { max-height: 190px; overflow-y: auto; font-size: 12px; }
    .activity-row { display: flex; gap: 12px; padding: 5px 0; border-bottom: 1px solid var(--card-border); }
    .activity-row:last-child { border-bottom: none; }
    .activity-t { color: var(--text-dim); flex: none; width: 150px; font-variant-numeric: tabular-nums; }
    .activity-text { color: var(--text); }

    .fanrow.fault .flabel { color: var(--danger); font-weight: 700; }
    .fanrow.fault .fbadge { background: var(--danger); color: #fff; border-color: var(--danger); }

    .ts-wrap { display: flex; gap: 6px; }
    .ts-axis {
        display: flex; flex-direction: column; justify-content: space-between;
        font-size: 10px; color: var(--text-dim); text-align: right; padding: 2px 0;
        font-variant-numeric: tabular-nums;
    }
    .ts-plot { position: relative; flex: 1; min-width: 0; }
    .crosshair {
        position: absolute; top: 0; bottom: 0; width: 1px; background: rgba(255,255,255,0.25);
        display: none; pointer-events: none;
    }
    .crosshair.active { display: block; }
    .spark { display: block; }
    .spark-tip {
        position: fixed; pointer-events: none; background: #000; color: #fff;
        padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;
        opacity: 0; transition: opacity 0.08s; z-index: 50; white-space: nowrap;
    }
    .spark-range { font-size: 11px; color: var(--text-dim); margin-top: 4px; }
    .spark-empty { color: var(--text-dim); font-size: 12px; text-align: center; }

    .fanrow { display: flex; align-items: center; gap: 10px; margin: 11px 0; font-size: 12px; }
    .fanrow .flabel { width: 28px; color: var(--text-dim); flex: none; }
    .fantrack { flex: 1; height: 12px; background: #262a35; border-radius: 6px; overflow: hidden; }
    .fanfill { display: block; height: 100%; border-radius: 6px; min-width: 3px; transition: width 0.6s cubic-bezier(.22,.61,.36,1); }
    .fanrow .fpct { width: 38px; text-align: right; flex: none; font-variant-numeric: tabular-nums; font-weight: 600; }
    .fanrow .fbadge {
        width: 16px; height: 16px; border-radius: 4px; flex: none; font-size: 9px;
        display: flex; align-items: center; justify-content: center; color: var(--text-dim);
        border: 1px solid var(--card-border);
    }

    table { border-collapse: collapse; width: 100%; font-size: 12px; }
    th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid var(--card-border); }
    th { color: var(--text-dim); font-weight: 600; font-size: 10px; text-transform: uppercase; }
    tr:nth-child(even) td { background: rgba(255,255,255,0.015); }
    td.hot { color: var(--danger); font-weight: 700; }
    td.warm { color: var(--warn); }

    input, button { padding: 9px 12px; font-size: 13px; border-radius: 6px; border: 1px solid var(--card-border); background: #0f1116; color: var(--text); }
    input[type=number] { width: 80px; }
    label { font-size: 12px; color: var(--text-dim); }
    button { background: var(--accent); cursor: pointer; border: none; color: #06121f; font-weight: 700; }
    button:hover { filter: brightness(1.1); }
    button.danger { background: var(--danger); color: #200; }
    form.inline { display: flex; align-items: end; gap: 8px; flex-wrap: wrap; margin-top: 2px; margin-bottom: 8px; }

    .footer { max-width: 1800px; margin: 12px auto 0; color: var(--text-dim); font-size: 11px; text-align: center; }
    .warn { color: var(--warn); font-weight: bold; }
    .error { color: var(--danger); }
"""

STAT_ROW_TEMPLATE = """
<div class="panel stat status-{{ health_level }}">
    <div class="panel-h">Status</div>
    <div class="stat-value">{{ status_word }}</div>
    <div class="stat-sub">{{ health_detail }}</div>
</div>
<div class="panel stat">
    <div class="stat-spark-bg">{{ target_spark|safe }}</div>
    <div class="panel-h">Target / Enforced</div>
    {% if show_ilo_auto %}
    <div class="stat-value">iLO Auto</div>
    {% else %}
    <div class="stat-value">{{ status.resolved_target_pct if status.resolved_target_pct is not none else config.target_fan_percentage }}% / {{ status.last_enforced_pct if status.last_enforced_pct is not none else '-' }}%</div>
    {% if quiet_active %}<div class="stat-sub">&#127769; quiet hours active</div>{% endif %}
    {% endif %}
    {% if away_mode_label %}<div class="stat-sub">&#128274; {{ away_mode_label }}</div>{% endif %}
</div>
<div class="panel stat">
    <div class="stat-spark-bg">{{ cpu_spark_mini|safe }}</div>
    <div class="panel-h">CPU Max</div>
    <div class="stat-value {{ cpu_class }}">{{ cpu_max_f|round|int if cpu_max_f is not none else '-' }}&deg;F</div>
</div>
<div class="panel stat">
    <div class="panel-h">Headroom to Guard</div>
    <div class="stat-value {{ cpu_class }}">{{ headroom if headroom is not none else '-' }}&deg;F</div>
    <div class="stat-sub">guard fires at {{ threshold_f|round(0, 'floor')|int }}&deg;F</div>
</div>
<div class="panel stat">
    <div class="panel-h">Inlet</div>
    <div class="stat-value">{{ inlet_f|round|int if inlet_f is not none else '-' }}&deg;F</div>
</div>
<div class="panel stat">
    <div class="panel-h">Guard</div>
    <div class="stat-value {{ guard_class }}">{{ 'ACTIVE' if status.guard_active else 'normal' }}</div>
    <div class="stat-sub">last cycle: {{ status.last_cycle_str or '-' }}</div>
</div>
"""

CPU_CHART_TEMPLATE = """{{ cpu_spark|safe }}<div class="spark-range">{{ cpu_range or 'dashed line = guard threshold' }}</div>"""

FAN_CHART_TEMPLATE = """{{ fan_spark|safe }}<div class="spark-range">{{ fan_range or 'spikes to 100% mean the guard fired' }}</div>"""

FANS_TEMPLATE = """
{% for f in status.fans %}
<div class="fanrow{{ ' fault' if f.id in fan_fault_ids else '' }}">
    <span class="flabel">#{{ f.id }}</span>
    <span class="fantrack"><span class="fanfill" style="width:{{ f.percent }}%; background:{{ danger_color if (f.percent >= 90 or f.id in fan_fault_ids) else (muted_color if f.percent == 0 else accent_color) }};"></span></span>
    <span class="fpct">{{ f.percent }}%</span>
    <span class="fbadge" title="{{ 'FAULT' if f.id in fan_fault_ids else ('Redundant' if f.redundant else 'Not redundant') }}">{{ '!' if f.id in fan_fault_ids else ('R' if f.redundant else '-') }}</span>
</div>
{% endfor %}
"""

SENSORS_TEMPLATE = """
<tr><th>Sensor</th><th>&deg;F</th></tr>
{% for t in temps_display %}
{% set delta = threshold - t.celsius %}
<tr><td{% if delta <= 5 %} class="hot"{% elif delta <= 20 %} class="warm"{% endif %}>{{ t.name }}</td><td{% if delta <= 5 %} class="hot"{% elif delta <= 20 %} class="warm"{% endif %}>{{ t.fahrenheit }}</td></tr>
{% endfor %}
"""

ACTIVITY_TEMPLATE = """
{% if activity %}
{% for a in activity %}
<div class="activity-row"><span class="activity-t">{{ a.t }}</span><span class="activity-text">{{ a.text }}</span></div>
{% endfor %}
{% else %}
<div class="spark-empty">No activity yet this run.</div>
{% endif %}
"""

FOOTER_TEMPLATE = """Last cycle {{ status.last_cycle_str }} ({{ status.last_result }}) &middot; live"""

STATUS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>iLO Fan Control</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>{{ style|safe }}</style>
</head>
<body>
<div class="topbar">
    <a href="{{ ilo_url }}" target="_blank" rel="noopener noreferrer" class="ilo-icon" title="Open iLO console ({{ config.ilo_ip }})">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
    </a>
    <span class="brand">iLO Fan Control</span>
    <span class="host">{{ hostname }}</span>
    <span class="live-dot" title="Live &mdash; updates automatically"></span>
    <nav><a href="/" class="active">Status</a><a href="/credentials">Credentials</a><a href="/settings">Settings</a></nav>
</div>

{% if request.args.get('saved') %}<div class="toast ok">Saved and applying now.</div>{% endif %}
{% if request.args.get('applied') %}<div class="toast ok">Cycle forced.</div>{% endif %}
{% if request.args.get('bad') == 'locked' %}<div class="toast error">Manual controls are locked (Away Mode) &mdash; unlock via Set Target or Settings.</div>
{% elif request.args.get('bad') %}<div class="toast error">Invalid value: must be {{ min_pct }}-{{ max_pct }}.</div>{% endif %}

<div class="dash">
<div class="stat-row" id="stat-row">{{ stat_row_html|safe }}</div>

<div class="main-grid">
    <div class="panel col-6">
        <div class="panel-h">CPU Temp Trend</div>
        <div id="cpu-chart">{{ cpu_chart_html|safe }}</div>
    </div>
    <div class="panel col-6">
        <div class="panel-h">Enforced Fan % Trend</div>
        <div id="fan-chart">{{ fan_chart_html|safe }}</div>
    </div>

    <div class="panel col-4">
        <div class="panel-h">Set Target</div>
        {% if config.manual_controls_locked %}
        <p class="stat-sub">&#128274; Away Mode is on &mdash;
            {% if show_ilo_auto %}your enforced floor is released (FanPercentMinimum=0)
            so iLO's own automatic algorithm is fully in control.
            {% elif config.away_control_mode == 'thermostat' %}a thermostat (currently
            {{ status.resolved_target_pct }}%) is holding CPU near your ideal temperature.
            {% else %}a temperature-driven curve (currently {{ status.resolved_target_pct }}%)
            is enforced automatically, scaling with CPU temp.
            {% endif %}
            Thermal guard and fan-fault protection stay active regardless.
            Adjust this on the <a href="/settings">Settings</a> page.</p>
        <form method="POST" action="/lock" class="inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="next" value="/">
            <button type="submit">Unlock</button>
        </form>
        {% else %}
        <form method="POST" action="/update" class="inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div>
                <label>New target ({{ min_pct }}-{{ max_pct }})</label><br>
                <input type="number" name="target" value="{{ config.target_fan_percentage }}"
                       min="{{ min_pct }}" max="{{ max_pct }}" required>
            </div>
            <button type="submit">Update</button>
        </form>
        <form method="POST" action="/apply" class="inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit">Apply Now</button>
        </form>
        <form method="POST" action="/lock" class="inline">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="next" value="/">
            <button type="submit" class="danger" title="Disable manual controls; the automatic loop keeps running">&#128274; Away Mode</button>
        </form>
        {% endif %}
    </div>

    <div class="panel col-3">
        <div class="panel-h">Fans</div>
        <div id="fans-list">{{ fans_html|safe }}</div>
    </div>

    <div class="panel col-5">
        <div class="panel-h">Hottest Sensors</div>
        <table id="sensors-table">{{ sensors_html|safe }}</table>
    </div>

    <div class="panel col-12">
        <div class="panel-h">Recent Activity</div>
        <div id="activity-log" class="activity-list">{{ activity_html|safe }}</div>
    </div>
</div>
</div>

<div class="footer" id="footer-text">{{ footer_html|safe }}</div>
<script>
(function () {
    var tip = document.createElement("div");
    tip.className = "spark-tip";
    document.body.appendChild(tip);
    document.addEventListener("mousemove", function (e) {
        var hit = e.target.closest ? e.target.closest(".spark-hit") : null;
        document.querySelectorAll(".crosshair.active").forEach(function (c) { c.classList.remove("active"); });
        if (!hit) { tip.style.opacity = 0; return; }
        var svg = hit.closest("svg");
        var unit = svg ? (svg.getAttribute("data-unit") || "") : "";
        var plot = hit.closest(".ts-plot");
        if (plot) {
            var cross = plot.querySelector(".crosshair");
            if (cross) { cross.style.left = hit.getAttribute("data-x") + "%"; cross.classList.add("active"); }
        }
        tip.textContent = hit.getAttribute("data-v") + unit;
        tip.style.left = (e.clientX + 12) + "px";
        tip.style.top = (e.clientY - 26) + "px";
        tip.style.opacity = 1;
    });
})();
(function () {
    var liveDot = document.querySelector(".live-dot");
    var ids = ["stat-row", "cpu-chart", "fan-chart", "fans-list", "sensors-table", "activity-log", "footer-text"];
    var keys = {
        "stat-row": "stat_row", "cpu-chart": "cpu_chart", "fan-chart": "fan_chart",
        "fans-list": "fans", "sensors-table": "sensors", "activity-log": "activity", "footer-text": "footer"
    };
    function poll() {
        fetch("/api/status").then(function (r) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return r.json();
        }).then(function (d) {
            ids.forEach(function (id) {
                var el = document.getElementById(id);
                var next = d[keys[id]];
                if (!el || next === undefined || el.innerHTML === next) return;
                el.classList.add("fading");
                setTimeout(function () {
                    el.innerHTML = next;
                    el.classList.remove("fading");
                }, 180);
            });
            if (liveDot) { liveDot.classList.remove("stale"); }
        }).catch(function () {
            if (liveDot) { liveDot.classList.add("stale"); }
        });
    }
    setInterval(poll, 4000);
    poll();
})();
</script>
</body>
</html>
"""

CREDS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Credentials - iLO Fan Control</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>{{ style|safe }}</style>
</head>
<body>
<div class="topbar">
    <a href="{{ ilo_url }}" target="_blank" rel="noopener noreferrer" class="ilo-icon" title="Open iLO console">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
    </a>
    <span class="brand">iLO Fan Control</span>
    <nav><a href="/">Status</a><a href="/credentials" class="active">Credentials</a><a href="/settings">Settings</a></nav>
</div>
{% if request.args.get('dash') == 'ok' %}<div class="toast ok">Dashboard credentials updated.</div>{% endif %}
{% if request.args.get('ilo') == 'ok' %}<div class="toast ok">iLO credentials updated (verified by test login).</div>{% endif %}
{% if request.args.get('err') %}<div class="toast error">{{ request.args.get('err') }}</div>{% endif %}

<div class="grid">
<div class="card">
    <h3>Dashboard Login</h3>
    <form method="POST" action="/credentials/dashboard">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="password" name="current_password" placeholder="Current password" required><br>
        <input type="text" name="new_username" placeholder="Username (blank = keep)" value=""><br>
        <input type="password" name="new_password" placeholder="New password (min {{ min_len }})" required><br>
        <input type="password" name="confirm_password" placeholder="Confirm new password" required><br>
        <button type="submit">Update Dashboard Login</button>
    </form>
</div>
<div class="card">
    <h3>iLO Credentials</h3>
    <p class="warn">Applied to iLO, verified by fresh login; auto-reverts on failure.</p>
    <form method="POST" action="/credentials/ilo">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="password" name="current_ilo_password" placeholder="Current iLO password" required><br>
        <input type="text" name="new_username" placeholder="iLO username (blank = keep)" value=""><br>
        <input type="password" name="new_ilo_password" placeholder="New iLO password (min {{ min_len }})" required><br>
        <input type="password" name="confirm_password" placeholder="Confirm new password" required><br>
        <button type="submit" class="danger">Update iLO Credentials</button>
    </form>
</div>
</div>
</body>
</html>
"""

SETTINGS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Settings - iLO Fan Control</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>{{ style|safe }}</style>
</head>
<body>
<div class="topbar">
    <a href="{{ ilo_url }}" target="_blank" rel="noopener noreferrer" class="ilo-icon" title="Open iLO console">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
    </a>
    <span class="brand">iLO Fan Control</span>
    <nav><a href="/">Status</a><a href="/credentials">Credentials</a><a href="/settings" class="active">Settings</a></nav>
</div>
{% if request.args.get('saved') %}<div class="toast ok">Settings saved &mdash; applying now.</div>{% endif %}
{% if request.args.get('tested') %}<div class="toast ok">Test alert sent &mdash; check your webhook target.</div>{% endif %}
{% if request.args.get('err') %}<div class="toast error">{{ request.args.get('err') }}</div>{% endif %}

<div class="grid">
<div class="card">
    <h3>Away Mode</h3>
    <p class="stat-sub">
        {% if config.manual_controls_locked %}
        &#128274; Locked. Update / Apply Now are disabled, and automatic control is enforced
        instead, clamped to {{ away_min }}-{{ away_max }}%:
        {% if away_control_mode == 'thermostat' %}
        <b>Thermostat</b> &mdash; proportional control that continuously nudges fan speed to hold
        CPU near {{ ideal_f }}&deg;F, adapting as load changes instead of following a fixed formula.
        {% else %}
        <b>Curve</b> &mdash; {{ away_min }}% when CPU is cool (&le;{{ cool_f }}&deg;F), ramping up to
        {{ away_max }}% as it approaches {{ hot_f }}&deg;F (5&deg;C below your guard threshold).
        {% endif %}
        Either way this is proactive cooling instead of a flat number, so the guard's reactive
        100% is rarely needed. Set min=max for a flat floor, or max to 0 for fully hands-off to iLO.
        {% if config.quiet_hours_enabled and config.quiet_hours_overrides_away_mode %}
        Quiet hours is set to cap this during its window (see below).
        {% elif config.quiet_hours_enabled %}
        Quiet hours is enabled but won't affect this unless you check "cap Away Mode" below.
        {% endif %}
        {% else %}
        Unlocked. Manual controls are available and your configured target (with quiet hours,
        if enabled) is being enforced as normal.
        {% endif %}
        Thermal guard and fan-fault protection stay active either way &mdash; those are safety
        systems, not manual controls, so Away Mode never turns them off.
    </p>
    <form method="POST" action="/settings/away-mode">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label>Strategy</label>
        <select name="away_control_mode">
            <option value="curve" {{ 'selected' if away_control_mode != 'thermostat' }}>Curve</option>
            <option value="thermostat" {{ 'selected' if away_control_mode == 'thermostat' }}>Thermostat</option>
        </select><br>
        <label>Min % (when cool / thermostat floor)</label>
        <input type="number" name="away_min" min="0" max="{{ max_pct }}" value="{{ away_min }}">
        <label>Max % (near guard threshold / thermostat ceiling)</label>
        <input type="number" name="away_max" min="0" max="{{ max_pct }}" value="{{ away_max }}"><br>
        <label>Ideal temperature (&deg;F, thermostat only)</label>
        <input type="number" name="away_ideal_f" min="60" max="200" value="{{ ideal_f }}">
        <button type="submit">Save Away Settings</button>
    </form>
    <form method="POST" action="/lock">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="hidden" name="next" value="/settings">
        <button type="submit" class="{{ '' if config.manual_controls_locked else 'danger' }}">
            {{ 'Unlock Manual Controls' if config.manual_controls_locked else 'Lock Manual Controls (Away Mode)' }}
        </button>
    </form>
</div>

<div class="card">
    <h3>Quiet Hours</h3>
    <p class="stat-sub">Swap in a lower fan target during a time window (e.g. overnight),
        reverting automatically outside it. Thermal guard and fan-fault overrides always
        take priority over this. By default Away Mode overrides quiet hours entirely (its
        own curve/thermostat takes over) -- check the box below to have quiet hours act as
        a noise ceiling on Away Mode too, instead of being ignored while it's locked.</p>
    <form method="POST" action="/settings/quiet-hours">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label><input type="checkbox" name="quiet_enabled" {{ 'checked' if config.quiet_hours_enabled }}> Enabled</label><br>
        <label>Start</label>
        <input type="time" name="quiet_start" value="{{ config.quiet_hours_start or '22:00' }}"><br>
        <label>End</label>
        <input type="time" name="quiet_end" value="{{ config.quiet_hours_end or '07:00' }}"><br>
        <label>Target ({{ min_pct }}-{{ max_pct }}%)</label>
        <input type="number" name="quiet_target" min="{{ min_pct }}" max="{{ max_pct }}"
               value="{{ config.quiet_hours_target_fan_percentage or config.target_fan_percentage }}"><br>
        <label><input type="checkbox" name="quiet_overrides_away"
               {{ 'checked' if config.quiet_hours_overrides_away_mode }}>
               Also cap Away Mode's fan speed during quiet hours</label><br>
        <button type="submit">Save Quiet Hours</button>
    </form>
</div>

<div class="card">
    <h3>Alert Webhook</h3>
    <p class="stat-sub">Get notified when the thermal guard fires/releases, a fan fault is
        detected/clears, or the control loop fails repeatedly (and again when it recovers).
        Works with ntfy.sh, Discord, or a generic JSON endpoint.</p>
    <form method="POST" action="/settings/alerts">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="webhook_url" placeholder="https://ntfy.sh/your-topic"
               value="{{ config.alert_webhook_url or '' }}" style="width:100%; max-width:420px;"><br>
        <select name="webhook_format">
            <option value="ntfy" {{ 'selected' if (config.alert_webhook_format or 'ntfy') == 'ntfy' }}>ntfy.sh</option>
            <option value="discord" {{ 'selected' if config.alert_webhook_format == 'discord' }}>Discord</option>
            <option value="generic" {{ 'selected' if config.alert_webhook_format == 'generic' }}>Generic JSON</option>
        </select>
        <button type="submit">Save Webhook</button>
    </form>
    <form method="POST" action="/settings/test-alert" style="margin-top:8px;">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit">Send Test Alert</button>
    </form>
</div>
</div>
</body>
</html>
"""


_auth_rate_buckets = {}
# Separate rate-limit pools per action family -- sharing one bucket across
# unrelated actions (e.g. settings saves eating into the test-alert budget)
# caused exactly the kind of surprise 429 this fixes.
_action_rate_buckets = {}       # /update, /apply
_credentials_rate_buckets = {}  # /credentials/dashboard, /credentials/ilo
_settings_rate_buckets = {}     # /settings/quiet-hours, /settings/alerts, /lock
_test_alert_rate_buckets = {}   # /settings/test-alert -- kept isolated to avoid webhook spam


def rate_ok(ip, limit=10, window=60, buckets=None):
    if buckets is None:
        buckets = _rate_buckets
    now = time.time()
    with _rate_lock:
        bucket = [t for t in buckets.get(ip, []) if now - t < window]
        if len(bucket) >= limit:
            buckets[ip] = bucket
            return False
        bucket.append(now)
        buckets[ip] = bucket
        return True


def is_ip_locked(ip, buckets, limit, window):
    """Check-only: is this IP currently over the limit, without recording
    an attempt. Use for auth gates where only *failures* should count."""
    now = time.time()
    with _rate_lock:
        bucket = [t for t in buckets.get(ip, []) if now - t < window]
        buckets[ip] = bucket
        return len(bucket) >= limit


def record_attempt(ip, buckets):
    with _rate_lock:
        buckets.setdefault(ip, []).append(time.time())


CSRF_COOKIE = "csrf_token"


def get_csrf_token():
    return request.cookies.get(CSRF_COOKIE) or secrets.token_hex(32)


def with_csrf_cookie(resp, token):
    resp.set_cookie(CSRF_COOKIE, token, samesite="Strict",
                    secure=request.is_secure, httponly=False, max_age=86400)
    return resp


def requires_csrf(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        form_token = request.form.get("csrf_token", "")
        if not cookie_token or not hmac.compare_digest(form_token, cookie_token):
            abort(403, description="Invalid or missing CSRF token; reload the page and try again")
        return f(*args, **kwargs)
    return wrapper


def check_auth(username, password):
    cfg = load_config()
    stored_hash = cfg.get("dashboard_password_hash")
    salt = cfg.get("dashboard_salt")
    if not stored_hash or not salt:
        return False
    candidate = hash_password(password, salt)
    return (hmac.compare_digest(username, cfg.get("dashboard_user", "admin"))
            and hmac.compare_digest(candidate, stored_hash))


def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "?"
        # Only failed attempts count against this limiter -- legitimate
        # traffic (live polling, multiple tabs, normal clicking) never
        # touches it, however much of it there is.
        if is_ip_locked(ip, _auth_rate_buckets, limit=15, window=60):
            abort(429, description="Too many failed login attempts; try again shortly")
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            record_attempt(ip, _auth_rate_buckets)
            log.warning("Failed dashboard login attempt from %s (user=%s)",
                        ip, auth.username if auth else "-")
            return Response("Authentication required.", 401,
                            {"WWW-Authenticate": 'Basic realm="ilo-fan-control"'})
        return f(*args, **kwargs)
    return wrapper


def build_dashboard_context(cfg, status, hist, activity=None):
    # All classification/guard math below stays in Celsius -- it's compared
    # against thermal_guard_threshold_celsius, the actual config/hardware
    # source of truth. Fahrenheit is derived purely for display.
    threshold = float(cfg.get("thermal_guard_threshold_celsius", 85))
    cpu_max = status.get("cpu_max_celsius")
    headroom_c = (threshold - cpu_max) if cpu_max is not None else None
    health_level, health_detail = compute_health(status, cfg)
    status_word = {"ok": "OK", "warning": "WARN", "critical": "CRIT"}[health_level]

    cpu_color = threshold_color(cpu_max, threshold - 20, threshold - 5)
    cpu_class = COLOR_CLASS.get(cpu_color, "")
    guard_class = "c-danger" if status.get("guard_active") else "c-ok"
    fan_fault_ids = set(status.get("fan_fault_ids") or [])
    # Quiet hours only actually influences enforcement when Away Mode isn't
    # locked, unless quiet_hours_overrides_away_mode is set (making it a
    # ceiling on Away Mode's own floor too) -- suppress the badge otherwise
    # so it doesn't imply something that isn't happening.
    quiet_active = bool(status.get("quiet_hours_active")) and (
        not bool(cfg.get("manual_controls_locked")) or bool(cfg.get("quiet_hours_overrides_away_mode")))

    threshold_f = c_to_f(threshold)
    cpu_max_f = c_to_f(cpu_max) if cpu_max is not None else None
    inlet_f = c_to_f(status["inlet_celsius"]) if status.get("inlet_celsius") is not None else None
    headroom = round(c_delta_to_f(headroom_c), 1) if headroom_c is not None else None
    temps_display = [dict(t, fahrenheit=round(c_to_f(t["celsius"]))) for t in status.get("temps", [])]

    cpu_vals = [h.get("cpu") for h in hist if h.get("cpu") is not None]
    fan_vals = [h.get("enforced") for h in hist if h.get("enforced") is not None]
    cpu_vals_f = [c_to_f(v) for v in cpu_vals]
    cpu_spark = render_timeseries(cpu_vals_f, color=(cpu_color or ACCENT_COLOR), ref=threshold_f, unit="°F")
    fan_spark = render_timeseries(fan_vals, color=ACCENT_COLOR, unit="%")
    cpu_spark_mini = render_stat_spark(cpu_vals_f, color=(cpu_color or ACCENT_COLOR))
    target_spark = render_stat_spark(fan_vals, color=ACCENT_COLOR)
    cpu_range = ("{:.0f}–{:.0f}°F over last {} cycles".format(min(cpu_vals_f), max(cpu_vals_f), len(cpu_vals_f))
                 if len(cpu_vals_f) >= 4 else None)
    fan_range = ("{:.0f}–{:.0f}% over last {} cycles".format(min(fan_vals), max(fan_vals), len(fan_vals))
                 if len(fan_vals) >= 4 else None)

    away_overridden = bool(status.get("guard_active") or fan_fault_ids)
    resolved = status.get("resolved_target_pct")
    show_ilo_auto = bool(cfg.get("manual_controls_locked")) and resolved == 0 and not away_overridden
    away_mode_label = None
    if cfg.get("manual_controls_locked"):
        if away_overridden:
            away_mode_label = "away mode — safety override active"
        elif resolved == 0:
            away_mode_label = "away mode — floor released, iLO's own algorithm in control"
        else:
            away_mode_label = "away mode — target {}%".format(resolved if resolved is not None else "?")

    return dict(
        config=cfg, status=status, threshold=threshold, threshold_f=threshold_f, headroom=headroom,
        cpu_max_f=cpu_max_f, inlet_f=inlet_f, temps_display=temps_display,
        fan_fault_ids=fan_fault_ids, quiet_active=quiet_active,
        show_ilo_auto=show_ilo_auto, away_mode_label=away_mode_label,
        health_level=health_level, health_detail=health_detail, status_word=status_word,
        cpu_class=cpu_class, guard_class=guard_class,
        cpu_spark=cpu_spark, fan_spark=fan_spark, cpu_spark_mini=cpu_spark_mini, target_spark=target_spark,
        cpu_range=cpu_range, fan_range=fan_range, activity=activity or [],
        accent_color=ACCENT_COLOR, danger_color=DANGER_COLOR, muted_color="#454a55",
    )


def render_dashboard_fragments(ctx):
    return {
        "stat_row": render_template_string(STAT_ROW_TEMPLATE, **ctx),
        "cpu_chart": render_template_string(CPU_CHART_TEMPLATE, **ctx),
        "fan_chart": render_template_string(FAN_CHART_TEMPLATE, **ctx),
        "fans": render_template_string(FANS_TEMPLATE, **ctx),
        "sensors": render_template_string(SENSORS_TEMPLATE, **ctx),
        "activity": render_template_string(ACTIVITY_TEMPLATE, **ctx),
        "footer": render_template_string(FOOTER_TEMPLATE, **ctx),
    }


@app.route("/")
@requires_auth
def index():
    cfg = load_config()
    with state_lock:
        status = dict(shared_state)
        hist = list(history)
        activity = list(activity_log)

    ctx = build_dashboard_context(cfg, status, hist, activity)
    frags = render_dashboard_fragments(ctx)
    ilo_url = "https://{}/".format(cfg.get("ilo_ip", ""))

    token = get_csrf_token()
    resp = make_response(render_template_string(
        STATUS_TEMPLATE, config=cfg, status=status, style=BASE_STYLE, hostname=HOSTNAME, ilo_url=ilo_url,
        min_pct=MIN_PCT, max_pct=MAX_PCT, csrf_token=token,
        health_level=ctx["health_level"], show_ilo_auto=ctx["show_ilo_auto"],
        stat_row_html=frags["stat_row"], cpu_chart_html=frags["cpu_chart"], fan_chart_html=frags["fan_chart"],
        fans_html=frags["fans"], sensors_html=frags["sensors"], activity_html=frags["activity"],
        footer_html=frags["footer"],
    ))
    return with_csrf_cookie(resp, token)


@app.route("/api/status")
@requires_auth
def api_status():
    cfg = load_config()
    with state_lock:
        status = dict(shared_state)
        hist = list(history)
        activity = list(activity_log)
    ctx = build_dashboard_context(cfg, status, hist, activity)
    return render_dashboard_fragments(ctx)


@app.route("/update", methods=["POST"])
@requires_auth
@requires_csrf
def update():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=20, buckets=_action_rate_buckets):
        abort(429, description="Too many requests")
    if load_config().get("manual_controls_locked"):
        log.warning("Update rejected: manual controls locked (Away Mode), from %s", ip)
        return redirect("/?bad=locked")
    raw = request.form.get("target", "")
    try:
        new_target = int(raw)
    except ValueError:
        abort(400, description="target must be an integer")
    if not MIN_PCT <= new_target <= MAX_PCT:
        abort(400, description="target out of range")
    with config_lock:
        cfg = load_config()
        cfg["target_fan_percentage"] = new_target
        save_config(cfg)
    log.info("Dashboard update: target=%s%% by %s; forcing cycle", new_target, ip)
    log_activity("Target changed to {}% by {}".format(new_target, ip))
    force_event.set()
    return redirect("/?saved=1")


@app.route("/apply", methods=["POST"])
@requires_auth
@requires_csrf
def apply_now():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=20, buckets=_action_rate_buckets):
        abort(429, description="Too many requests")
    if load_config().get("manual_controls_locked"):
        log.warning("Apply Now rejected: manual controls locked (Away Mode), from %s", ip)
        return redirect("/?bad=locked")
    log.info("Manual cycle forced via web by %s", ip)
    log_activity("Cycle forced by {}".format(ip))
    force_event.set()
    return redirect("/?applied=1")


@app.route("/credentials", methods=["GET"])
@requires_auth
def credentials_page():
    cfg = load_config()
    ilo_url = "https://{}/".format(cfg.get("ilo_ip", ""))
    token = get_csrf_token()
    resp = make_response(render_template_string(
        CREDS_TEMPLATE, style=BASE_STYLE, min_len=MIN_SECRET_LEN, csrf_token=token, ilo_url=ilo_url,
    ))
    return with_csrf_cookie(resp, token)


@app.route("/credentials/dashboard", methods=["POST"])
@requires_auth
@requires_csrf
def credentials_dashboard():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=5, buckets=_credentials_rate_buckets):
        abort(429, description="Too many requests")
    auth = request.authorization
    current_pw = request.form.get("current_password", "")
    new_user = request.form.get("new_username", "").strip()
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not check_auth(auth.username, current_pw):
        log.warning("Dashboard credential change rejected (bad current password) from %s", ip)
        return redirect("/credentials?err=Current%20password%20incorrect")
    if len(new_pw) < MIN_SECRET_LEN:
        return redirect("/credentials?err=New%20password%20too%20short")
    if new_pw != confirm:
        return redirect("/credentials?err=Passwords%20do%20not%20match")

    with config_lock:
        cfg = load_config()
        username = new_user or cfg.get("dashboard_user", "admin")
        salt_hex = secrets.token_hex(16)
        cfg["dashboard_user"] = username
        cfg["dashboard_salt"] = salt_hex
        cfg["dashboard_password_hash"] = hash_password(new_pw, salt_hex)
        save_config(cfg)
    log.info("Dashboard credentials changed by %s (user=%s)", ip, username)
    log_activity("Dashboard login credentials changed by {}".format(ip))
    return redirect("/credentials?dash=ok")


@app.route("/credentials/ilo", methods=["POST"])
@requires_auth
@requires_csrf
def credentials_ilo():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=5, buckets=_credentials_rate_buckets):
        abort(429, description="Too many requests")
    current_ilo_pw = request.form.get("current_ilo_password", "")
    new_user = request.form.get("new_username", "").strip()
    new_pw = request.form.get("new_ilo_password", "")
    confirm = request.form.get("confirm_password", "")

    with config_lock:
        cfg = load_config()
    if not hmac.compare_digest(current_ilo_pw, cfg.get("ilo_password", "")):
        log.warning("iLO credential change rejected (bad current password) from %s", ip)
        return redirect("/credentials?err=Current%20iLO%20password%20incorrect")
    if len(new_pw) < MIN_SECRET_LEN:
        return redirect("/credentials?err=New%20password%20too%20short")
    if new_pw != confirm:
        return redirect("/credentials?err=Passwords%20do%20not%20match")

    username = new_user or cfg.get("ilo_user")
    ok, detail = set_ilo_account_credentials(
        cfg["ilo_ip"], cfg["ilo_user"], cfg["ilo_password"],
        cfg.get("ilo_user"), username, new_pw,
    )
    if not ok:
        log.warning("iLO credential change failed: %s", detail)
        return redirect(
            "/credentials?err={}".format(requests.utils.quote(detail))
        )

    with config_lock:
        cfg = load_config()
        cfg["ilo_user"] = username
        cfg["ilo_password"] = new_pw
        save_config(cfg)
    log.info("iLO credentials rotated via web by %s (user=%s); verified by test login", ip, username)
    log_activity("iLO credentials rotated by {}".format(ip))
    force_event.set()
    return redirect("/credentials?ilo=ok")


@app.route("/settings", methods=["GET"])
@requires_auth
def settings_page():
    cfg = load_config()
    ilo_url = "https://{}/".format(cfg.get("ilo_ip", ""))
    threshold = float(cfg.get("thermal_guard_threshold_celsius", 85))
    away_min = cfg.get("away_min_fan_percentage", 25)
    away_max = cfg.get("away_max_fan_percentage", 65)
    away_control_mode = (cfg.get("away_control_mode") or "curve").lower()
    ideal_f = round(c_to_f(float(cfg.get("away_ideal_temp_celsius", 55))))
    token = get_csrf_token()
    resp = make_response(render_template_string(
        SETTINGS_TEMPLATE, style=BASE_STYLE, csrf_token=token, ilo_url=ilo_url,
        config=cfg, min_pct=MIN_PCT, max_pct=MAX_PCT,
        away_min=away_min, away_max=away_max, away_control_mode=away_control_mode, ideal_f=ideal_f,
        cool_f=round(c_to_f(AWAY_CURVE_COOL_C)), hot_f=round(c_to_f(threshold - 5)),
    ))
    return with_csrf_cookie(resp, token)


@app.route("/settings/away-mode", methods=["POST"])
@requires_auth
@requires_csrf
def settings_away_mode():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=15, buckets=_settings_rate_buckets):
        abort(429, description="Too many requests")
    try:
        away_min = int(request.form.get("away_min", ""))
        away_max = int(request.form.get("away_max", ""))
        if not (0 <= away_min <= MAX_PCT and 0 <= away_max <= MAX_PCT):
            raise ValueError
    except ValueError:
        return redirect("/settings?err={}".format(
            requests.utils.quote("Away min/max must both be 0-{}".format(MAX_PCT))))

    control_mode = request.form.get("away_control_mode", "curve").strip().lower()
    if control_mode not in ("curve", "thermostat"):
        control_mode = "curve"

    try:
        ideal_f = float(request.form.get("away_ideal_f", ""))
        if not 60 <= ideal_f <= 200:
            raise ValueError
    except ValueError:
        return redirect("/settings?err={}".format(
            requests.utils.quote("Ideal temperature must be 60-200F")))

    with config_lock:
        cfg = load_config()
        cfg["away_min_fan_percentage"] = away_min
        cfg["away_max_fan_percentage"] = away_max
        cfg["away_control_mode"] = control_mode
        cfg["away_ideal_temp_celsius"] = round(f_to_c(ideal_f), 1)
        save_config(cfg)
    log_activity("Away settings: {} mode, {}-{}%, ideal {:.0f}F, by {}".format(
        control_mode, away_min, away_max, ideal_f, ip))
    force_event.set()
    return redirect("/settings?saved=1")


@app.route("/settings/quiet-hours", methods=["POST"])
@requires_auth
@requires_csrf
def settings_quiet_hours():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=15, buckets=_settings_rate_buckets):
        abort(429, description="Too many requests")

    enabled = request.form.get("quiet_enabled") == "on"
    overrides_away = request.form.get("quiet_overrides_away") == "on"
    start = request.form.get("quiet_start", "").strip()
    end = request.form.get("quiet_end", "").strip()

    errors = []
    try:
        _parse_hhmm(start)
    except ValueError:
        errors.append("Start time must be HH:MM")
    try:
        _parse_hhmm(end)
    except ValueError:
        errors.append("End time must be HH:MM")
    try:
        target = int(request.form.get("quiet_target", ""))
        if not MIN_PCT <= target <= MAX_PCT:
            raise ValueError
    except ValueError:
        errors.append("Target must be {}-{}".format(MIN_PCT, MAX_PCT))
        target = None

    if errors:
        return redirect("/settings?err={}".format(requests.utils.quote("; ".join(errors))))

    with config_lock:
        cfg = load_config()
        cfg["quiet_hours_enabled"] = enabled
        cfg["quiet_hours_start"] = start
        cfg["quiet_hours_end"] = end
        cfg["quiet_hours_target_fan_percentage"] = target
        cfg["quiet_hours_overrides_away_mode"] = overrides_away
        save_config(cfg)
    log_activity("Quiet hours {} ({}-{}, target {}%, {} Away Mode) by {}".format(
        "enabled" if enabled else "updated (disabled)", start, end, target,
        "capping" if overrides_away else "not capping", ip))
    force_event.set()
    return redirect("/settings?saved=1")


@app.route("/settings/alerts", methods=["POST"])
@requires_auth
@requires_csrf
def settings_alerts():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=15, buckets=_settings_rate_buckets):
        abort(429, description="Too many requests")

    url = request.form.get("webhook_url", "").strip()
    fmt = request.form.get("webhook_format", "ntfy").strip().lower()

    if url and not url.startswith(("http://", "https://")):
        return redirect("/settings?err={}".format(
            requests.utils.quote("Webhook URL must start with http:// or https://")))
    if fmt not in ("ntfy", "discord", "generic"):
        fmt = "ntfy"

    with config_lock:
        cfg = load_config()
        cfg["alert_webhook_url"] = url
        cfg["alert_webhook_format"] = fmt
        save_config(cfg)
    log_activity("Alert webhook {} by {}".format("configured" if url else "cleared", ip))
    return redirect("/settings?saved=1")


@app.route("/settings/test-alert", methods=["POST"])
@requires_auth
@requires_csrf
def settings_test_alert():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=5, buckets=_test_alert_rate_buckets):
        abort(429, description="Too many requests")
    cfg = load_config()
    if not cfg.get("alert_webhook_url"):
        return redirect("/settings?err={}".format(
            requests.utils.quote("Save a webhook URL first")))
    send_alert(cfg, "iLO Fan Control: test alert",
               "This is a test notification, triggered from Settings by {}.".format(ip))
    log_activity("Test alert sent by {}".format(ip))
    return redirect("/settings?tested=1")


@app.route("/lock", methods=["POST"])
@requires_auth
@requires_csrf
def toggle_lock():
    ip = request.remote_addr or "?"
    if not rate_ok(ip, limit=15, buckets=_settings_rate_buckets):
        abort(429, description="Too many requests")
    with config_lock:
        cfg = load_config()
        new_state = not bool(cfg.get("manual_controls_locked"))
        cfg["manual_controls_locked"] = new_state
        save_config(cfg)
    log_activity("Away Mode {} by {}".format("ENABLED (manual controls locked)" if new_state
                                              else "disabled (manual controls unlocked)", ip))
    dest = request.form.get("next") or "/"
    if not dest.startswith("/") or dest.startswith("//"):
        dest = "/"
    return redirect(dest)


def ensure_dashboard_credentials(cfg):
    if cfg.get("dashboard_password_hash") and cfg.get("dashboard_salt"):
        return
    log.warning("No dashboard credentials configured; generating a random password (see journal).")
    password = secrets.token_urlsafe(12)
    salt_hex = secrets.token_hex(16)
    with config_lock:
        cfg["dashboard_user"] = cfg.get("dashboard_user", "admin")
        cfg["dashboard_salt"] = salt_hex
        cfg["dashboard_password_hash"] = hash_password(password, salt_hex)
        save_config(cfg)
    log.warning("Generated dashboard credentials -> user: %s password: %s",
                cfg["dashboard_user"], password)


def ensure_tls_context(cfg):
    if not cfg.get("dashboard_tls"):
        return None
    cert = cfg.get("dashboard_cert") or os.path.join(TLS_DIR, "cert.pem")
    key = cfg.get("dashboard_key") or os.path.join(TLS_DIR, "key.pem")
    if shutil.which("openssl") is None:
        log.error("TLS enabled but openssl not found; falling back to HTTP")
        return None
    if not (os.path.exists(cert) and os.path.exists(key)):
        os.makedirs(TLS_DIR, exist_ok=True)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "825",
             "-subj", "/CN=ilo-fan-control"],
            check=True, capture_output=True,
        )
        os.chmod(key, 0o600)
    log.info("TLS enabled: %s", cert)
    return (cert, key)


def serve_dashboard(host, port, tls_ctx):
    """Serve the Flask app with cheroot (a real WSGI server) instead of
    Werkzeug's development server. Falls back to the dev server if cheroot
    isn't installed, so a missing optional dependency never blocks startup."""
    try:
        from cheroot.wsgi import Server as WSGIServer
        from cheroot.ssl.builtin import BuiltinSSLAdapter
    except ImportError:
        log.warning("cheroot not installed; falling back to Flask's development "
                    "server (fine for light use; `apt install python3-cheroot` for production)")
        app.run(host=host, port=port, threaded=True, ssl_context=tls_ctx)
        return

    server = WSGIServer((host, port), app, numthreads=8)
    if tls_ctx:
        cert, key = tls_ctx
        server.ssl_adapter = BuiltinSSLAdapter(cert, key, None)
    log.info("Serving via cheroot (production WSGI server)")
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


def cmd_set_password(argv):
    logging.basicConfig(stream=sys.stdout, format="%(message)s")
    cfg = load_config()
    password = argv[0] if argv else secrets.token_urlsafe(12)
    salt_hex = secrets.token_hex(16)
    with config_lock:
        cfg["dashboard_user"] = cfg.get("dashboard_user", "admin")
        cfg["dashboard_salt"] = salt_hex
        cfg["dashboard_password_hash"] = hash_password(password, salt_hex)
        save_config(cfg)
    print("Dashboard user: {}".format(cfg["dashboard_user"]))
    print("Dashboard password: {}".format(password))
    print("(stored only as a PBKDF2 hash)")
    return 0


def cmd_set_auto():
    logging.basicConfig(stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s",
                        level=logging.INFO)
    cfg = load_config()
    ilo = IloClient()
    ok = False
    try:
        ilo.login(cfg)
        _, etag = ilo.get_thermal(cfg)
        ok = ilo.patch_minimum(cfg, etag, 0)
    finally:
        ilo.close()
    log.info("Automatic fan control restored" if ok
             else "Failed to restore automatic fan control")
    return 0 if ok else 1


def cmd_check():
    logging.basicConfig(stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s",
                        level=logging.INFO)
    cfg = load_config()
    ilo = IloClient()
    try:
        ilo.login(cfg)
        thermal, _ = ilo.get_thermal(cfg)
        summary = summarize_thermal(thermal)
        log.info("Enforced minimum: %s%% | Inlet: %sC | CPU max: %sC",
                 summary["ilo_min_pct"], summary["inlet_celsius"],
                 summary["cpu_max_celsius"])
        log.info("Fans: %s", [f["percent"] for f in summary["fans"]])
        log.info("Top sensors: %s",
                 [(t["name"], t["celsius"]) for t in summary["temps"][:5]])
        return 0
    finally:
        ilo.close()


def handle_signal(signum, frame):
    if signum == getattr(signal, "SIGUSR1", None):
        log.info("SIGUSR1 received; forcing cycle")
        force_event.set()
    else:
        log.info("Received signal %s; shutting down", signum)
        stop_event.set()
        force_event.set()


def main():
    logging.basicConfig(stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s",
                        level=logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == "set-password":
        return cmd_set_password(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "set-auto":
        return cmd_set_auto()
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        return cmd_check()

    cfg = load_config()
    ensure_dashboard_credentials(cfg)

    restored = load_history()
    if restored:
        history.clear()
        history.extend(restored)
        log.info("Restored %d history samples from previous run", len(restored))

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, handle_signal)

    tls_ctx = None
    try:
        tls_ctx = ensure_tls_context(cfg)
    except Exception as e:
        log.error("TLS setup failed (%s); falling back to HTTP", e)

    host = cfg.get("dashboard_host", "0.0.0.0")
    port = int(cfg.get("dashboard_port", 5000))
    scheme = "https" if tls_ctx else "http"
    ui = threading.Thread(
        target=lambda: serve_dashboard(host, port, tls_ctx),
        daemon=True,
    )
    ui.start()
    log.info("Dashboard listening on %s://%s:%s (basic auth enabled)",
             scheme, host, port)
    log.info("Startup config: target=%s%% interval=%ss guard=%s(threshold %.0fC) tls=%s",
             cfg.get("target_fan_percentage"),
             clamp_interval(cfg.get("check_interval_seconds", 60)),
             bool(cfg.get("thermal_guard_enabled", True)),
             float(cfg.get("thermal_guard_threshold_celsius", 85)),
             bool(tls_ctx))

    fan_control_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
