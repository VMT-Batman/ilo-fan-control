# iLO Fan Control

A small self-hosted service that enforces a minimum fan speed on HPE
ProLiant servers via iLO's Redfish API, with a live web dashboard, a
temperature-driven "Away Mode" for when you're not watching it, quiet
hours, thermal-guard and fan-fault safety protection, and optional
webhook alerts.

Built because iLO's own stock fan curve can be too conservative (quiet
enough to run hotter than you'd like) on some servers. This lets you set
a floor, watch it live, and forget about it.

**Screenshot-free by design** -- once it's running, open the dashboard
in your browser and you'll see everything: live fan speeds, hottest
sensors, temperature trends, and current status at a glance.

## Compatibility

Developed and tested against an **HPE ProLiant DL360 Gen10 running iLO 5
(firmware v3.20)**. The core mechanism is an HPE-specific Redfish OEM
property:

```
PATCH https://<ilo-ip>/redfish/v1/Chassis/{chassis_id}/Thermal/
Body: {"Oem": {"Hpe": {"FanPercentMinimum": <0, or 10-100>}}}
```

This *should* work on other Gen9/Gen10 HPE servers with iLO 4/5, but
Redfish implementations vary by generation and firmware version. **Before
relying on it**, verify your hardware actually supports this property:

```bash
python3 fan_control.py check
```

If that logs a clean thermal summary (fans, sensors, enforced minimum),
you're good. If it errors on the PATCH step, your firmware may expose a
different property name or chassis path -- check your iLO's Redfish
schema at `https://<ilo-ip>/redfish/v1/Chassis/1/Thermal/` (log in via
the iLO web UI first, then it may prompt for the session token) or in
HPE's Redfish documentation for your generation.

## Requirements

- A Linux host that can reach your iLO's network interface (a Proxmox
  host, a Raspberry Pi, a VM -- anything that stays powered on)
- Python 3.9+
- `flask`, `requests`, and (recommended) `cheroot` for production-grade
  serving instead of Flask's development server
- `openssl` CLI, if you want the dashboard's self-signed HTTPS (optional
  but recommended -- it's on by default in the example config)
- An iLO account with rights to read Thermal data and PATCH the Chassis
  resource (an existing admin account is simplest)

## Quick start

```bash
git clone <this-repo-url>
cd ilo-fan-control
sudo ./install.sh
```

The installer:
1. Installs Python dependencies (via `apt` if available, `pip3` otherwise)
2. Copies `fan_control.py` to `/srv/ilo-fan-control/`
3. Asks for your iLO IP/username/password and starting fan target, and
   writes `/srv/ilo-fan-control/config.json` (mode 600) from those answers
4. Installs and starts the systemd service

That's it -- the dashboard comes up on `https://<this-machine>:5000` with
a random password (see below to find or replace it).

## Manual install

If you'd rather not run a script, or you're not on a systemd/apt system:

1. Copy `fan_control.py` somewhere permanent, e.g. `/srv/ilo-fan-control/`.
2. Copy `config.example.json` to `config.json` next to it, and fill in
   at least `ilo_ip`, `ilo_user`, `ilo_password`. Everything else has a
   sensible default (see the [configuration reference](#configuration-reference)).
   `chmod 600 config.json` -- it holds your iLO password in plaintext.
3. Install the Python dependencies: `flask`, `requests`, and optionally
   `cheroot` (falls back to Flask's dev server with a warning if missing).
4. Run it directly to test: `python3 fan_control.py`
5. Once it works, install `ilo-fan-control.service` into
   `/etc/systemd/system/` (edit the `ExecStart` path if you didn't use
   `/srv/ilo-fan-control/`), then:
   ```bash
   systemctl daemon-reload
   systemctl enable --now ilo-fan-control
   ```

## First login

On first start, if no dashboard password is configured yet, one is
generated randomly and printed to the log:

```bash
journalctl -u ilo-fan-control | grep "Generated dashboard"
```

To set your own instead:

```bash
python3 /srv/ilo-fan-control/fan_control.py set-password
# or with a specific password:
python3 /srv/ilo-fan-control/fan_control.py set-password 'your-password-here'
```

Then open `https://<host>:5000` (or `http://` if you disabled
`dashboard_tls`). The self-signed certificate will trigger a browser
warning the first time -- that's expected for a LAN service like this;
click through it (Advanced -> Proceed).

## The dashboard

- **Status** -- live health at a glance: current target vs. what's
  actually enforced, CPU temp with headroom to the guard threshold, fan
  speeds per-slot, hottest sensors, thermal-guard/fan-fault state, and a
  recent-activity log. Updates automatically every few seconds without
  reloading the page.
- **Credentials** -- change the dashboard login, or rotate the iLO
  account's own password (applied via Redfish, verified with a fresh
  login, and automatically reverted if verification fails -- you can't
  accidentally lock yourself out of iLO from here).
- **Settings** -- Away Mode (see below), Quiet Hours, and webhook alerts,
  all editable from the browser; nothing requires hand-editing
  `config.json` after initial setup.

### Away Mode

A lock you can flip when you're not around to watch it, so manual
controls (the Update/Apply buttons) are disabled and a fully automatic
strategy takes over instead:

- **Curve** (default): a quiet floor when the CPU is cool, ramping up
  toward a stronger floor as it approaches the thermal-guard threshold --
  proactive, so the guard's reactive 100% override is rarely needed.
- **Thermostat**: real proportional control toward an ideal temperature
  you pick. Each cycle it nudges fan speed based on how far off target
  the CPU is, with memory of the previous cycle's speed -- it converges
  and adapts as load changes, rather than following a fixed formula.
- Set the min and max the same for a flat floor, or max to 0 to fully
  release control back to iLO's own algorithm.

Thermal guard and fan-fault protection are never disabled by Away Mode --
those are safety systems, not manual controls.

### Quiet Hours

An optional lower target during a configured time window (e.g. overnight),
reverting automatically outside it. Independent of Away Mode -- useful
even if you never lock manual controls at all.

### Alerts

Point `alert_webhook_url` (Settings page or config.json) at an
[ntfy.sh](https://ntfy.sh) topic, a Discord webhook, or a generic JSON
endpoint, and get notified when: the thermal guard fires or releases, a
fan fault is detected or clears, or the control loop fails repeatedly (and
again when it recovers). There's a "Send Test Alert" button on the
Settings page so you can verify it works without waiting for a real event.

## CLI reference

```
fan_control.py                 run the service (what systemd does)
fan_control.py set-password    set/generate the dashboard password
fan_control.py set-auto        apply 0% once (restore iLO's own automatic
                                fan control) and exit -- useful for
                                temporarily backing out without editing config
fan_control.py check           one-shot: log in, print thermal state, exit
```

## Configuration reference

Everything except the two iLO credentials can also be changed live from
the Settings/Credentials pages -- this table is for `config.json` /
first-time setup.

| Key | Default | Meaning |
|---|---|---|
| `ilo_ip` | *(required)* | iLO management IP or hostname |
| `ilo_user` / `ilo_password` | *(required)* | iLO account credentials |
| `chassis_id` | `1` | Redfish chassis index (rarely anything but 1) |
| `target_fan_percentage` | *(required)* | Minimum fan % to enforce (10-100) while unlocked |
| `check_interval_seconds` | `60` | How often the control loop runs (clamped 15-3600) |
| `request_timeout_seconds` | `15` | Per-request timeout talking to iLO |
| `thermal_guard_enabled` | `true` | CPU-temp safety override |
| `thermal_guard_threshold_celsius` | `85` | Temp that triggers a forced 100% |
| `thermal_guard_hysteresis_celsius` | `5` | Margin below threshold before releasing the guard |
| `thermal_guard_confirm_seconds` | `8` | Delay before confirming a spike, to ignore transient noise |
| `dashboard_host` / `dashboard_port` | `0.0.0.0` / `5000` | Web UI bind address |
| `dashboard_tls` | `false` (example config ships `true`) | Serve HTTPS with a self-signed cert (auto-generated) |
| `dashboard_user` | `admin` | Dashboard login username |
| `manual_controls_locked` | `false` | Away Mode on/off |
| `away_control_mode` | `curve` | `curve` or `thermostat` |
| `away_min_fan_percentage` / `away_max_fan_percentage` | `25` / `65` | Away Mode's floor/ceiling (either strategy); max=0 means fully automatic |
| `away_ideal_temp_celsius` | `55` | Thermostat mode's setpoint |
| `quiet_hours_enabled` | `false` | Enable the overnight schedule |
| `quiet_hours_start` / `quiet_hours_end` | `22:00` / `07:00` | 24h local time window |
| `quiet_hours_target_fan_percentage` | *(falls back to `target_fan_percentage`)* | Target during the window |
| `alert_webhook_url` | *(unset = disabled)* | ntfy/Discord/generic endpoint |
| `alert_webhook_format` | `ntfy` | `ntfy`, `discord`, or `generic` |

Fields marked `dashboard_password_hash` / `dashboard_salt` are managed
automatically (PBKDF2-hashed) -- never put a plaintext dashboard password
in the config file.

## Security notes

- `config.json` holds your iLO password in plaintext (required for the
  Redfish API) -- keep it `chmod 600`, owned by whichever user runs the
  service (root, by default, matching the shipped systemd unit).
- Enable `dashboard_tls` (on by default in the example config) unless
  the host running this is already on a trusted, isolated management
  network -- otherwise Basic Auth credentials cross the network in the
  clear.
- Dashboard login attempts are rate-limited per IP; repeated failures
  lock out that IP for a minute rather than allowing unlimited guesses.
- The iLO credential-rotation flow requires your *current* iLO password
  and verifies the new one with a live login before committing, reverting
  automatically if that verification fails.

## Troubleshooting

- **"development server" warning in the logs**: install `python3-cheroot`
  (or `pip3 install cheroot`) and restart the service -- it's used
  automatically if present, no config change needed.
- **PATCH fails with `PropertyNotWritableOrUnknown`**: your iLO firmware
  doesn't expose `FanPercentMinimum` at that path. Check
  `https://<ilo-ip>/redfish/v1/Chassis/<id>/Thermal/` for the actual OEM
  properties your generation supports, and adjust `chassis_id` if you
  have more than one chassis.
- **Self-signed certificate warning in your browser**: expected. The
  cert is generated locally on first run (`tls/cert.pem`, `tls/key.pem`)
  and never leaves the machine.
- **Fans not dropping after lowering the target**: the display refreshes
  within one control-loop cycle (`check_interval_seconds`, default 60s)
  or immediately if you click "Apply Now".
