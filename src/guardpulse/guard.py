"""The rule engine: every change to protection goes through ``Guard``.

Permission model ("one-way ratchet"):

* Anything that makes protection *stricter* is free - adding a blocked site or
  app, adding a schedule, switching a protection on.
* Anything that *loosens* it needs the accountability partner - whitelisting a
  site, deleting a block, disabling or deleting a schedule, switching a
  protection off, changing the partner, PIN or alert settings.

The partner unlocks with their PIN (on the device) or a 6-digit TOTP code from
their authenticator app (remotely). An unlock lasts ``unlock_minutes`` and is
held in memory only, so restarting the app locks it again.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from . import db, safety, security
from .domains import most_specific, normalize_domain, normalize_package

DEFAULT_SETTINGS: dict[str, object] = {
    "family_dns": True,
    "browser_overlay": True,
    "feed_youtube_shorts": True,
    "feed_instagram_reels": True,
    "feed_facebook_reels": True,
    "feed_snapchat_spotlight": True,
    "uninstall_protection": False,
    "settings_guard": False,
    # search "dorking": searches naming blocked sites, Google Translate proxies of
    # blocked sites, search caches / web archives / reader proxies
    "dork_guard": True,
    "unlock_minutes": 5,
    # partner alerts go to https://ntfy.sh/<topic>; the topic is generated once a
    # partner exists and is the only "secret" (long + random = unguessable)
    "ntfy_server": "https://ntfy.sh",
    "ntfy_topic": "",
}
NTFY_TOPIC_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")


def new_alert_topic() -> str:
    return "guardpulse-" + secrets.token_hex(12)
PROTECTIVE_FLAGS = {
    "family_dns",
    "browser_overlay",
    "feed_youtube_shorts",
    "feed_instagram_reels",
    "feed_facebook_reels",
    "feed_snapchat_spotlight",
    "uninstall_protection",
    "settings_guard",
    "dork_guard",
}
UNLOCK_MINUTES_RANGE = (1, 30)

# Cloudflare 1.1.1.1 for Families - "malware + adult content" resolvers.
FAMILY_DNS_V4 = ("1.1.1.3", "1.0.0.3")
FAMILY_DNS_V6 = ("2606:4700:4700::1113", "2606:4700:4700::1003")
FAMILY_DOH = "https://family.cloudflare-dns.com/dns-query"


class GuardError(Exception):
    """A user-facing error: the message is shown as-is."""


class Locked(GuardError):
    def __init__(self, action: str):
        super().__init__(f"Your accountability partner's PIN is needed to {action}.")
        self.action = action


@dataclass(frozen=True)
class Rule:
    id: int
    kind: str
    value: str
    created_at: float


@dataclass(frozen=True)
class BlockedApp:
    id: int
    package: str
    label: str


@dataclass(frozen=True)
class Schedule:
    id: int
    name: str
    days: int
    start_min: int
    end_min: int
    packages: tuple[str, ...]
    enabled: bool

    def active_at(self, moment: datetime) -> bool:
        """Is the lock window open at ``moment``? Windows may run past midnight."""
        if not self.enabled:
            return False
        minute = moment.hour * 60 + moment.minute
        today = moment.weekday()
        if self.start_min <= self.end_min:
            return bool(self.days >> today & 1) and self.start_min <= minute < self.end_min
        # overnight: the evening part belongs to today, the morning part to yesterday
        if minute >= self.start_min:
            return bool(self.days >> today & 1)
        yesterday = (today - 1) % 7
        return bool(self.days >> yesterday & 1) and minute < self.end_min


_A_MONDAY = datetime(2024, 1, 1)  # any Monday; only weekday + time matter


def is_stricter_or_equal(old: Schedule, new: Schedule) -> bool:
    """True if ``new`` locks at least every app ``old`` did, at every minute of the
    week ``old`` was locking (ignoring pause state). Checked minute by minute, so
    overnight windows and day changes can't fool it."""
    if not set(old.packages) <= set(new.packages):
        return False
    probe_old = Schedule(old.id, old.name, old.days, old.start_min, old.end_min, old.packages, True)
    probe_new = Schedule(new.id, new.name, new.days, new.start_min, new.end_min, new.packages, True)
    for minute in range(7 * 24 * 60):
        moment = _A_MONDAY + timedelta(minutes=minute)
        if probe_old.active_at(moment) and not probe_new.active_at(moment):
            return False
    return True


@dataclass(frozen=True)
class Partner:
    name: str
    contact: str
    failed_attempts: int
    locked_until: float


class Guard:
    def __init__(
        self,
        folder: Path | None = None,
        key_provider: security.KeyProvider | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.folder = folder or db.data_dir()
        # an update must never start on an empty database (see safety.py)
        self.recovered = safety.recover_if_missing(self.folder)
        self.conn = db.connect(self.folder / "guardpulse.db")
        self.keys = key_provider or security.FileKeyProvider(self.folder / "seal.key")
        self.clock = clock
        self._unlocked_until = 0.0
        self._unlocked_by = "none"
        # check the seal before seeding, so new default keys in an update
        # aren't mistaken for an outside edit
        self.tampered = self._check_seal()
        self._seed_settings()
        if self.recovered:
            self._audit("data.recovered", self.recovered)

    # --- app version / backups ---------------------------------------------

    def note_app_version(self, version: str) -> str | None:
        """Record the running version; returns the previous one after an update."""
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'app_version'").fetchone()
        previous = row["value"] if row else None
        if previous == version:
            return None
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('app_version', ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (version,),
        )
        if previous is not None:
            self._audit("app.updated", f"{previous} -> {version}")
        return previous

    def snapshot(self, label: str) -> Path:
        """Private safety copy of all data, e.g. right before installing an update."""
        path = safety.snapshot(self.folder, self.conn, label)
        self._audit("data.snapshot", label)
        return path

    # --- sync (Phase 6) ------------------------------------------------------

    @property
    def device_id(self) -> str:
        """Random id for this install, used to label synced activity."""
        value = self.meta("device_id")
        if not value:
            value = secrets.token_hex(6)
            self.set_meta("device_id", value)
        return value

    def _touch_partner(self) -> None:
        """Stamp partner changes so two phones' edits can be ordered when merging."""
        self.set_meta("partner_changed_at", repr(self.clock()))

    def apply_synced(self, state: dict) -> None:
        """Make protected state match a merged sync snapshot.

        No ratchet check here: every loosening in ``state`` was approved with the
        partner PIN on the phone that made it, and the snapshot is end-to-end
        encrypted + authenticated with a key only paired phones hold.
        """
        partner = state.get("partner")
        with self._tx():
            self.conn.execute("DELETE FROM rules")
            self.conn.executemany(
                "INSERT INTO rules (kind, value, created_at) VALUES (?, ?, ?)",
                [(kind, value, self.clock()) for kind, value in state.get("rules", [])],
            )
            self.conn.execute("DELETE FROM apps")
            self.conn.executemany(
                "INSERT INTO apps (package, label, created_at) VALUES (?, ?, ?)",
                [(pkg, label, self.clock()) for pkg, label in state.get("apps", [])],
            )
            self.conn.execute("DELETE FROM schedules")
            self.conn.executemany(
                "INSERT INTO schedules (name, days, start_min, end_min, packages, enabled, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (s["name"], s["days"], s["start_min"], s["end_min"], json.dumps(s["packages"]),
                     int(s["enabled"]), self.clock())
                    for s in state.get("schedules", [])
                ],
            )
            for key, value in state.get("settings", {}).items():
                if key in DEFAULT_SETTINGS:
                    self._write_setting(key, value)
            if partner:
                self.conn.execute(
                    "INSERT INTO partner (id, name, contact, pin_hash, totp_secret, totp_last_counter, created_at)"
                    " VALUES (1, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (id) DO UPDATE SET name = excluded.name, contact = excluded.contact,"
                    " pin_hash = excluded.pin_hash, totp_secret = excluded.totp_secret,"
                    " totp_last_counter = MAX(partner.totp_last_counter, excluded.totp_last_counter)",
                    (partner["name"], partner["contact"], partner["pin_hash"], partner["totp_secret"],
                     int(partner.get("totp_last_counter", 0)), self.clock()),
                )
                self.set_meta("partner_changed_at", repr(float(partner.get("changed_at", 0))))
                if partner.get("pin_verify"):  # re-sign the offline PIN hash with THIS phone's key
                    payload = partner["pin_verify"].encode()
                    (self.folder / "pin.verify").write_bytes(payload)
                    (self.folder / "pin.verify.sig").write_text(security.seal(self.keys.get_key(), payload))
            self._audit("sync.applied", f"{len(state.get('rules', []))} rules, {len(state.get('apps', []))} apps")

    def import_activity(self, entries: list[dict]) -> int:
        """Add other phones' activity (by unique key); returns how many were new."""
        own = self.device_id  # read first: creating it is a write that mustn't be counted
        before = self.conn.total_changes
        self.conn.executemany(
            "INSERT OR IGNORE INTO remote_activity (key, device, at, action, detail, authorised_by)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (e["key"], e["device"], float(e["at"]), e["action"], e.get("detail", ""), e.get("by", "none"))
                for e in entries
                if e.get("device") != own
            ],
        )
        return self.conn.total_changes - before

    def meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        """Unsealed bookkeeping (update checks etc.) - never rules or settings."""
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # --- partner / unlock --------------------------------------------------

    @property
    def is_setup(self) -> bool:
        return self.conn.execute("SELECT 1 FROM partner").fetchone() is not None

    def partner(self) -> Partner | None:
        row = self.conn.execute(
            "SELECT name, contact, failed_attempts, locked_until FROM partner"
        ).fetchone()
        return Partner(**dict(row)) if row else None

    def setup_partner(self, name: str, contact: str, pin: str) -> str:
        """First-run: register the partner. Returns the TOTP secret to show as a QR code."""
        if self.is_setup:
            raise GuardError("An accountability partner is already set up.")
        name = (name or "").strip()
        if not name:
            raise GuardError("Enter your partner's name.")
        pin = security.validate_pin(pin)
        secret = security.new_totp_secret()
        with self._tx():
            self.conn.execute(
                "INSERT INTO partner (id, name, contact, pin_hash, totp_secret, created_at)"
                " VALUES (1, ?, ?, ?, ?, ?)",
                (name, (contact or "").strip(), security.hash_pin(pin), secret, self.clock()),
            )
            self._write_native_auth(pin)
            if not self.setting("ntfy_topic"):
                self._write_setting("ntfy_topic", new_alert_topic())
            self._touch_partner()
            self._audit("partner.setup", name, "setup")
        return secret

    def _write_native_auth(self, pin: str) -> None:
        """Write the HMAC-sealed PBKDF2 PIN hash the Kotlin settings-guard verifies offline."""
        payload = security.pbkdf2_hash(pin).encode()
        (self.folder / "pin.verify").write_bytes(payload)
        (self.folder / "pin.verify.sig").write_text(security.seal(self.keys.get_key(), payload))

    def totp_uri(self) -> str:
        self._require("view the authenticator QR code")
        row = self.conn.execute("SELECT name, totp_secret FROM partner").fetchone()
        return security.totp_uri(row["totp_secret"], row["name"])

    @property
    def unlocked(self) -> bool:
        return not self.is_setup or self.clock() < self._unlocked_until

    @property
    def unlock_remaining(self) -> int:
        return max(0, int(self._unlocked_until - self.clock()))

    def lockout_remaining(self) -> int:
        partner = self.partner()
        return max(0, int(partner.locked_until - self.clock())) if partner else 0

    def unlock(self, secret: str) -> str:
        """Unlock with the partner PIN or a TOTP code. Returns ``"pin"`` or ``"totp"``."""
        row = self.conn.execute("SELECT * FROM partner").fetchone()
        if row is None:
            return "setup"
        now = self.clock()
        if now < row["locked_until"]:
            raise GuardError(
                f"Too many wrong attempts. Try again in {int(row['locked_until'] - now)} s."
            )
        method = None
        counter = None
        if security.verify_pin(secret, row["pin_hash"]):
            method = "pin"
        else:
            counter = security.verify_totp(
                row["totp_secret"], secret, row["totp_last_counter"], at=now
            )
            if counter is not None:
                method = "totp"
        with self._tx():
            if method is None:
                failed = row["failed_attempts"] + 1
                wait = security.lockout_seconds(failed)
                self.conn.execute(
                    "UPDATE partner SET failed_attempts = ?, locked_until = ?",
                    (failed, now + wait if wait else 0),
                )
                self._audit("unlock.failed", f"attempt {failed}")
                if failed >= 3:
                    self._queue("unlock_failed", {"attempts": failed})
            else:
                self.conn.execute(
                    "UPDATE partner SET failed_attempts = 0, locked_until = 0,"
                    " totp_last_counter = COALESCE(?, totp_last_counter)",
                    (counter,),
                )
                self._audit("unlock", "", method)
                self._queue("unlocked", {"method": method})
        if method is None:
            raise GuardError("That PIN or code is incorrect.")
        self._unlocked_until = now + int(self.setting("unlock_minutes")) * 60
        self._unlocked_by = method
        return method

    def lock(self) -> None:
        self._unlocked_until = 0.0
        self._unlocked_by = "none"

    def change_pin(self, new_pin: str) -> None:
        self._require("change the PIN")
        new_pin = security.validate_pin(new_pin)
        with self._tx():
            self.conn.execute("UPDATE partner SET pin_hash = ?", (security.hash_pin(new_pin),))
            self._write_native_auth(new_pin)
            self._touch_partner()
            self._audit("partner.pin_changed", "", self._unlocked_by)
            self._queue("pin_changed", {})

    def reset_totp(self) -> str:
        self._require("reset the authenticator")
        secret = security.new_totp_secret()
        with self._tx():
            self.conn.execute(
                "UPDATE partner SET totp_secret = ?, totp_last_counter = 0", (secret,)
            )
            self._touch_partner()
            self._audit("partner.totp_reset", "", self._unlocked_by)
        return secret

    def update_partner(self, name: str, contact: str) -> None:
        self._require("change the partner details")
        name = (name or "").strip()
        if not name:
            raise GuardError("Enter your partner's name.")
        with self._tx():
            self.conn.execute(
                "UPDATE partner SET name = ?, contact = ?", (name, (contact or "").strip())
            )
            self._touch_partner()
            self._audit("partner.updated", name, self._unlocked_by)

    # --- websites ----------------------------------------------------------

    def rules(self, kind: str) -> list[Rule]:
        rows = self.conn.execute(
            "SELECT id, kind, value, created_at FROM rules WHERE kind = ? ORDER BY value",
            (kind,),
        ).fetchall()
        return [Rule(**dict(r)) for r in rows]

    def add_block(self, raw: str) -> Rule:
        return self._add_rule("block", normalize_domain(raw))

    def add_allow(self, raw: str) -> Rule:
        host = normalize_domain(raw)
        self._require(f"whitelist {host}")
        return self._add_rule("allow", host)

    def remove_rule(self, rule_id: int) -> None:
        row = self.conn.execute("SELECT kind, value FROM rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            return
        self._require(f"remove {row['value']}")
        with self._tx():
            self.conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            self._audit(f"{row['kind']}.removed", row["value"], self._unlocked_by)
            self._queue("rule_removed", {"kind": row["kind"], "value": row["value"]})

    def decide(self, host_or_url: str) -> str:
        """``"block"``, ``"allow"`` or ``"default"`` (fall through to Family DNS)."""
        host = normalize_domain(host_or_url)
        block = most_specific(host, [r.value for r in self.rules("block")])
        allow = most_specific(host, [r.value for r in self.rules("allow")])
        if block is None and allow is None:
            return "default"
        if allow is not None and (block is None or len(allow) >= len(block)):
            return "allow"
        return "block"

    # --- apps --------------------------------------------------------------

    def blocked_apps(self) -> list[BlockedApp]:
        rows = self.conn.execute("SELECT id, package, label FROM apps ORDER BY label").fetchall()
        return [BlockedApp(**dict(r)) for r in rows]

    def add_app(self, package: str, label: str = "") -> BlockedApp:
        package = normalize_package(package)
        label = (label or "").strip() or package
        with self._tx():
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO apps (package, label, created_at) VALUES (?, ?, ?)",
                (package, label, self.clock()),
            )
            if cur.rowcount:
                self._audit("app.blocked", package)
        row = self.conn.execute("SELECT id, package, label FROM apps WHERE package = ?", (package,))
        return BlockedApp(**dict(row.fetchone()))

    def remove_app(self, app_id: int) -> None:
        row = self.conn.execute("SELECT package FROM apps WHERE id = ?", (app_id,)).fetchone()
        if row is None:
            return
        self._require(f"unblock {row['package']}")
        with self._tx():
            self.conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))
            self._audit("app.unblocked", row["package"], self._unlocked_by)
            self._queue("app_unblocked", {"package": row["package"]})

    def is_app_blocked(self, package: str, moment: datetime | None = None) -> bool:
        if self.conn.execute("SELECT 1 FROM apps WHERE package = ?", (package,)).fetchone():
            return True
        moment = moment or datetime.fromtimestamp(self.clock())
        return any(package in s.packages and s.active_at(moment) for s in self.schedules())

    # --- schedules ---------------------------------------------------------

    def schedules(self) -> list[Schedule]:
        rows = self.conn.execute("SELECT * FROM schedules ORDER BY start_min, name").fetchall()
        return [
            Schedule(
                id=r["id"],
                name=r["name"],
                days=r["days"],
                start_min=r["start_min"],
                end_min=r["end_min"],
                packages=tuple(json.loads(r["packages"])),
                enabled=bool(r["enabled"]),
            )
            for r in rows
        ]

    @staticmethod
    def _clean_schedule(name, days, start_min, end_min, packages) -> tuple[str, list[str]]:
        name = (name or "").strip() or "App lock"
        if not 1 <= days <= 127:
            raise GuardError("Pick at least one day.")
        if start_min == end_min:
            raise GuardError("Start and end time can't be the same.")
        clean = sorted({normalize_package(p) for p in packages})
        if not clean:
            raise GuardError("Pick at least one app to lock.")
        return name, clean

    def update_schedule(
        self, schedule_id: int, name: str, days: int, start_min: int, end_min: int, packages: list[str]
    ) -> Schedule:
        """Edit a schedule. Free when the edit only makes it stricter (same or more
        apps, locked at every minute it was locked before); otherwise needs the partner."""
        old = next((s for s in self.schedules() if s.id == schedule_id), None)
        if old is None:
            raise GuardError("That schedule no longer exists.")
        name, clean = self._clean_schedule(name, days, start_min, end_min, packages)
        new = Schedule(old.id, name, days, start_min, end_min, tuple(clean), old.enabled)
        looser = not is_stricter_or_equal(old, new)
        if looser:
            self._require(f"loosen the '{old.name}' schedule")
        with self._tx():
            self.conn.execute(
                "UPDATE schedules SET name = ?, days = ?, start_min = ?, end_min = ?, packages = ?"
                " WHERE id = ?",
                (name, days, start_min, end_min, json.dumps(clean), schedule_id),
            )
            self._audit("schedule.edited", name, self._unlocked_by if looser else "none")
            if looser:
                self._queue("schedule_loosened", {"name": name})
        return next(s for s in self.schedules() if s.id == schedule_id)

    def add_schedule(
        self, name: str, days: int, start_min: int, end_min: int, packages: list[str]
    ) -> Schedule:
        name, clean = self._clean_schedule(name, days, start_min, end_min, packages)
        with self._tx():
            cur = self.conn.execute(
                "INSERT INTO schedules (name, days, start_min, end_min, packages, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (name, days, start_min, end_min, json.dumps(clean), self.clock()),
            )
            self._audit("schedule.added", name)
        return next(s for s in self.schedules() if s.id == cur.lastrowid)

    def set_schedule_enabled(self, schedule_id: int, enabled: bool) -> None:
        row = self.conn.execute("SELECT name FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        if row is None:
            return
        if not enabled:
            self._require(f"pause the '{row['name']}' schedule")
        with self._tx():
            self.conn.execute(
                "UPDATE schedules SET enabled = ? WHERE id = ?", (int(enabled), schedule_id)
            )
            self._audit(
                "schedule.enabled" if enabled else "schedule.paused",
                row["name"],
                "none" if enabled else self._unlocked_by,
            )

    def remove_schedule(self, schedule_id: int) -> None:
        row = self.conn.execute("SELECT name FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        if row is None:
            return
        self._require(f"delete the '{row['name']}' schedule")
        with self._tx():
            self.conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
            self._audit("schedule.removed", row["name"], self._unlocked_by)
            self._queue("schedule_removed", {"name": row["name"]})

    # --- settings ----------------------------------------------------------

    def setting(self, key: str):
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else DEFAULT_SETTINGS[key]

    def settings(self) -> dict[str, object]:
        return {key: self.setting(key) for key in DEFAULT_SETTINGS}

    def set_setting(self, key: str, value) -> None:
        if key not in DEFAULT_SETTINGS:
            raise GuardError(f"Unknown setting {key}.")
        current = self.setting(key)
        if key in PROTECTIVE_FLAGS:
            value = bool(value)
            if current and not value:
                self._require("switch that protection off")
        elif key == "unlock_minutes":
            value = int(value)
            low, high = UNLOCK_MINUTES_RANGE
            if not low <= value <= high:
                raise GuardError(f"Unlock time must be {low}-{high} minutes.")
            if value > current:
                self._require("lengthen the unlock time")
        elif key == "ntfy_server":
            value = (value or "").strip().rstrip("/")
            if not value.startswith("https://"):
                raise GuardError("The ntfy server must be an https:// address.")
            self._require("change where alerts are sent")
        elif key == "ntfy_topic":
            value = (value or "").strip()
            if not NTFY_TOPIC_RE.fullmatch(value):
                raise GuardError("A topic is 8-64 letters, digits, - or _.")
            self._require("change where alerts are sent")
        if value == current:
            return
        with self._tx():
            self._write_setting(key, value)
            self._audit("setting.changed", f"{key}={value}", self._unlocked_by)
            if key in PROTECTIVE_FLAGS and not value:
                self._queue("protection_disabled", {"setting": key})

    def _write_setting(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )

    # --- partner alerts (ntfy) ---------------------------------------------

    def ensure_alert_topic(self) -> str:
        """Give the partner an unguessable ntfy topic once a partner exists.

        Creating it is free (it only adds protection); changing it later needs
        the partner. Returns the topic ("" while no partner is set up).
        """
        topic = self.setting("ntfy_topic")
        if topic or not self.is_setup:
            return topic
        topic = new_alert_topic()
        with self._tx():
            self._write_setting("ntfy_topic", topic)
            self._audit("alerts.topic_created", "")
        return topic

    def alert_subscribe_url(self) -> str:
        """https link the partner opens / scans to subscribe (needs the partner)."""
        self._require("see the partner alert link")
        return f"{self.setting('ntfy_server')}/{self.ensure_alert_topic()}"

    def new_alert_topic_now(self) -> str:
        """Replace the topic (e.g. if it leaked). Needs the partner."""
        self._require("change where alerts are sent")
        topic = new_alert_topic()
        with self._tx():
            self._write_setting("ntfy_topic", topic)
            self._audit("alerts.topic_changed", "", self._unlocked_by)
        return topic

    def queue_test_alert(self) -> None:
        self._queue("test", {})
        self._audit("alerts.test")

    def mark_alert(self, alert_id: int, sent: bool) -> None:
        """Delivery bookkeeping for the outbox (not sealed: it's not protection state)."""
        if sent:
            self.conn.execute("UPDATE outbox SET sent_at = ? WHERE id = ?", (self.clock(), alert_id))
        else:
            self.conn.execute("UPDATE outbox SET attempts = attempts + 1 WHERE id = ?", (alert_id,))

    # --- tamper detection --------------------------------------------------

    def acknowledge_tamper(self) -> None:
        self._require("clear the tamper warning")
        with self._tx():
            self.conn.execute("DELETE FROM meta WHERE key = 'tampered'")
            self._audit("tamper.acknowledged", "", self._unlocked_by)
        self.tampered = False

    def authorise_filter_off(self) -> None:
        """Gate + record switching the DNS filter off from inside the app."""
        self._authorise_off("filter.disabled", "dns_filter", "turn the DNS filter off")

    def authorise_overlay_off(self) -> None:
        """Gate + record switching the security overlay off from inside the app."""
        self._authorise_off("overlay.disabled", "security_overlay", "turn the security overlay off")

    def authorise_uninstall_off(self) -> None:
        """Gate + record switching uninstall protection off from inside the app."""
        self._authorise_off("uninstall.disabled", "uninstall_protection", "turn uninstall protection off")

    def _authorise_off(self, action: str, setting: str, reason: str) -> None:
        self._require(reason)
        with self._tx():
            self._audit(action, "", self._unlocked_by)
            self._queue("protection_disabled", {"setting": setting})

    def record_native(self, event: str, detail: str) -> None:
        """Log an event from the Android layer; tamper events also raise the warning."""
        from .native import TAMPER_EVENTS

        if event in TAMPER_EVENTS:
            # the Android layer already alerted the partner when it happened
            # (so it arrives even if this app is never reopened) - don't repeat it
            self.report_tamper(detail or event, alert=False)
        else:
            self._audit(f"native.{event}", detail)

    def report_tamper(self, what: str, alert: bool = True) -> None:
        """Flag tampering. ``alert=False`` when the partner was already told natively."""
        with self._tx():
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES ('tampered', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (what,),
            )
            self._audit("tamper.detected", what)
            if alert:
                self._queue("tamper", {"what": what})
        self.tampered = True

    # --- export / history --------------------------------------------------

    def policy(self) -> dict:
        """The snapshot the native enforcement layer reads (Phase 2+)."""
        return {
            "version": 1,
            "generated_at": self.clock(),
            "block": [r.value for r in self.rules("block")],
            "allow": [r.value for r in self.rules("allow")],
            "apps": [a.package for a in self.blocked_apps()],
            "schedules": [
                {
                    "days": s.days,
                    "start_min": s.start_min,
                    "end_min": s.end_min,
                    "packages": list(s.packages),
                }
                for s in self.schedules()
                if s.enabled
            ],
            "settings": self.settings(),
            "dns": {"v4": list(FAMILY_DNS_V4), "v6": list(FAMILY_DNS_V6), "doh": FAMILY_DOH},
        }

    def write_policy(self) -> Path:
        payload = json.dumps(self.policy(), sort_keys=True, separators=(",", ":")).encode()
        path = self.folder / "policy.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(payload)
        tmp.replace(path)
        (self.folder / "policy.sig").write_text(security.seal(self.keys.get_key(), payload))
        return path

    def note(self, action: str, detail: str = "") -> None:
        """Record a UI event (not a rule change) in the activity log."""
        self._audit(action, detail)

    def history(self, limit: int = 100) -> list[sqlite3.Row]:
        """This phone's activity plus what synced in from the account's other phones."""
        return self.conn.execute(
            "SELECT at, action, detail, authorised_by, '' AS device, id AS seq FROM audit"
            " UNION ALL"
            " SELECT at, action, detail, authorised_by, device, 0 AS seq FROM remote_activity"
            " ORDER BY at DESC, seq DESC LIMIT ?",  # seq: newest local entry first on equal times
            (limit,),
        ).fetchall()

    def pending_alerts(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT id, at, event, payload FROM outbox WHERE sent_at IS NULL ORDER BY id"
        ).fetchall()

    def stats(self) -> dict[str, int]:
        q = self.conn.execute
        return {
            "blocked_sites": q("SELECT COUNT(*) FROM rules WHERE kind = 'block'").fetchone()[0],
            "allowed_sites": q("SELECT COUNT(*) FROM rules WHERE kind = 'allow'").fetchone()[0],
            "blocked_apps": q("SELECT COUNT(*) FROM apps").fetchone()[0],
            "schedules": q("SELECT COUNT(*) FROM schedules WHERE enabled = 1").fetchone()[0],
        }

    # --- internals ---------------------------------------------------------

    def _require(self, action: str) -> None:
        if not self.unlocked:
            raise Locked(action)

    def _add_rule(self, kind: str, host: str) -> Rule:
        with self._tx():
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO rules (kind, value, created_at) VALUES (?, ?, ?)",
                (kind, host, self.clock()),
            )
            if cur.rowcount:
                self._audit(f"{kind}.added", host, "none" if kind == "block" else self._unlocked_by)
                if kind == "allow":
                    self._queue("whitelisted", {"value": host})
        row = self.conn.execute(
            "SELECT id, kind, value, created_at FROM rules WHERE kind = ? AND value = ?", (kind, host)
        ).fetchone()
        return Rule(**dict(row))

    def _seed_settings(self) -> None:
        present = {r[0] for r in self.conn.execute("SELECT key FROM settings")}
        missing = [(k, json.dumps(v)) for k, v in DEFAULT_SETTINGS.items() if k not in present]
        if missing:
            with self._tx():
                self.conn.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", missing)

    def _audit(self, action: str, detail: str = "", authorised_by: str = "none") -> None:
        self.conn.execute(
            "INSERT INTO audit (at, action, detail, authorised_by) VALUES (?, ?, ?, ?)",
            (self.clock(), action, detail, authorised_by),
        )

    def _queue(self, event: str, payload: dict) -> None:
        self.conn.execute(
            "INSERT INTO outbox (at, event, payload) VALUES (?, ?, ?)",
            (self.clock(), event, json.dumps(payload)),
        )

    def _seal_payload(self) -> bytes:
        q = self.conn.execute
        snapshot = {
            "rules": [tuple(r) for r in q("SELECT kind, value FROM rules ORDER BY kind, value")],
            "apps": [tuple(r) for r in q("SELECT package FROM apps ORDER BY package")],
            "schedules": [
                tuple(r)
                for r in q(
                    "SELECT name, days, start_min, end_min, packages, enabled"
                    " FROM schedules ORDER BY id"
                )
            ],
            "settings": [tuple(r) for r in q("SELECT key, value FROM settings ORDER BY key")],
            "partner": [tuple(r) for r in q("SELECT pin_hash, totp_secret FROM partner")],
        }
        return json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()

    def _reseal(self) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('seal', ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            (security.seal(self.keys.get_key(), self._seal_payload()),),
        )

    def _check_seal(self) -> bool:
        """True if protected tables were edited outside the app."""
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'seal'").fetchone()
        if row is None:
            self._reseal()  # brand-new database
        elif not security.seal_ok(self.keys.get_key(), self._seal_payload(), row["value"]):
            self.report_tamper("database edited outside GuardPulse")
        flagged = self.conn.execute("SELECT 1 FROM meta WHERE key = 'tampered'").fetchone()
        return flagged is not None

    def _tx(self):
        return _Transaction(self)


class _Transaction:
    """BEGIN IMMEDIATE ... reseal ... COMMIT, rolled back on any error."""

    def __init__(self, guard: Guard):
        self.guard = guard

    def __enter__(self):
        self.guard.conn.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        conn = self.guard.conn
        if exc_type is None:
            self.guard._reseal()
            conn.execute("COMMIT")
            try:
                self.guard.write_policy()
            except OSError:
                pass  # the policy file is a cache; the DB is the source of truth
        else:
            conn.execute("ROLLBACK")
        return False
