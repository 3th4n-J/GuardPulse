"""Snapshots of protected state, and the fail-safe three-way merge.

A snapshot is plain JSON (before encryption):

    {"v": 1, "device": "...", "at": ts, "rev": n, "lineage": [[rev, digest], ...],
     "rules": [[kind, value], ...], "apps": [[package, label], ...],
     "schedules": [{name, days, start_min, end_min, packages, enabled}, ...],
     "settings": {...}, "partner": {...} | null, "activity": [...]}

Merging compares each side with the last snapshot both phones agreed on
("base"). Changes from either side are combined; a removal only syncs if it
happened on the other phone (where it already needed the partner PIN). When
the same setting changed on both phones, the STRICTER value wins.

``rev`` and ``lineage`` sit INSIDE the encryption: every upload lists the
(rev, digest) of the copies it was built on. A phone only lets the cloud copy
remove or loosen anything when that copy was built on top of what this phone
last agreed on. An older copy put back in the cloud, or a split history, is
combined fail-safe instead (nothing removed, no whitelist added).
"""

from __future__ import annotations

import hashlib
import json

from ..guard import DEFAULT_SETTINGS, PROTECTIVE_FLAGS, Schedule, is_stricter_or_equal

VERSION = 1
ACTIVITY_TAIL = 200
LOOSENING_KINDS = ("allow", "app_allow")  # rule kinds whose ADDITION loosens protection
LINEAGE_KEEP = 50  # how many earlier copies an upload remembers being built on
# settings that travel between phones (all of them today; kept explicit)
SYNCED_SETTINGS = tuple(DEFAULT_SETTINGS)
# partner fields that identify "the same partner/PIN" (counters and lockouts don't)
_PARTNER_IDENTITY = ("name", "contact", "pin_hash", "totp_secret", "pin_verify")

EMPTY = {"rules": [], "apps": [], "schedules": [], "settings": {}, "partner": None}


def export(guard) -> dict:
    """This phone's protected state as a snapshot."""
    q = guard.conn.execute
    partner = None
    row = q("SELECT name, contact, pin_hash, totp_secret, totp_last_counter FROM partner").fetchone()
    if row is not None:
        pin_verify = guard.folder / "pin.verify"
        partner = {
            "name": row["name"],
            "contact": row["contact"],
            "pin_hash": row["pin_hash"],
            "totp_secret": row["totp_secret"],
            "totp_last_counter": row["totp_last_counter"],
            "pin_verify": pin_verify.read_text().strip() if pin_verify.exists() else "",
            "changed_at": float(guard.meta("partner_changed_at") or 0),
        }
    device = guard.device_id
    activity = [
        {"key": f"{device}:{r['id']}", "device": device, "at": r["at"], "action": r["action"],
         "detail": r["detail"], "by": r["authorised_by"]}
        for r in q("SELECT id, at, action, detail, authorised_by FROM audit ORDER BY id DESC LIMIT ?",
                   (ACTIVITY_TAIL,))
    ]
    return {
        "v": VERSION,
        "device": device,
        "at": guard.clock(),
        "rules": sorted([r["kind"], r["value"]] for r in q("SELECT kind, value FROM rules")),
        "apps": sorted([r["package"], r["label"]] for r in q("SELECT package, label FROM apps")),
        "schedules": sorted(
            (
                {"name": r["name"], "days": r["days"], "start_min": r["start_min"],
                 "end_min": r["end_min"], "packages": json.loads(r["packages"]),
                 "enabled": bool(r["enabled"])}
                for r in q("SELECT * FROM schedules")
            ),
            key=_schedule_key,
        ),
        "settings": {k: guard.setting(k) for k in SYNCED_SETTINGS},
        "partner": partner,
        "activity": activity,
    }


def protected(state: dict) -> dict:
    """The parts that decide protection (what gets merged and applied)."""
    return {k: state.get(k, EMPTY[k]) for k in EMPTY}


def is_blank(state: dict) -> bool:
    """A phone with nothing set up yet (fresh install about to be paired)."""
    s = protected(state)
    return not (s["rules"] or s["apps"] or s["schedules"] or s["partner"])


def digest(snap: dict) -> str:
    """Fingerprint of a snapshot's protected part (what lineage entries point at)."""
    body = json.dumps(protected(snap), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()[:32]


def descends_from(remote: dict, rev: int, fingerprint: str) -> bool:
    """Was ``remote`` built on top of the copy this phone last agreed on?"""
    return [rev, fingerprint] in remote.get("lineage", [])


def join_lineage(*lineages: list) -> list:
    """Every (rev, digest) from the given lineages, oldest first, newest LINEAGE_KEEP kept."""
    seen = {tuple(entry) for lineage in lineages for entry in lineage}
    return [list(entry) for entry in sorted(seen)][-LINEAGE_KEEP:]


# --- what a sync would loosen -------------------------------------------------------


def loosened(before: dict, after: dict) -> list[str]:
    """What going from ``before`` to ``after`` makes LESS strict, in plain words."""
    b, a = protected(before), protected(after)
    out = []
    b_rules, a_rules = {tuple(r) for r in b["rules"]}, {tuple(r) for r in a["rules"]}
    out += [f"{value} unblocked" for kind, value in sorted(b_rules - a_rules) if kind == "block"]
    out += [f"keyword '{value}' removed" for kind, value in sorted(b_rules - a_rules) if kind == "keyword"]
    out += [f"{value} whitelisted" for kind, value in sorted(a_rules - b_rules) if kind == "allow"]
    out += [f"{value} always allowed" for kind, value in sorted(a_rules - b_rules) if kind == "app_allow"]
    kept_apps = {package for package, _ in a["apps"]}
    out += [f"{label} unblocked" for package, label in b["apps"] if package not in kept_apps]
    for old in b["schedules"]:
        if old not in a["schedules"] and not any(
            _covers(old, new) for new in a["schedules"] if new["name"] == old["name"]
        ):
            out.append(f"'{old['name']}' schedule loosened or deleted")
    bs, as_ = b["settings"], a["settings"]
    out += [f"{key} switched off" for key in sorted(PROTECTIVE_FLAGS) if bs.get(key) is True and as_.get(key) is False]
    if "unlock_minutes" in bs and "unlock_minutes" in as_ and int(as_["unlock_minutes"]) > int(bs["unlock_minutes"]):
        out.append(f"unlock time lengthened to {as_['unlock_minutes']} minutes")
    if any(bs.get(key) and key in as_ and bs[key] != as_[key] for key in ("ntfy_server", "ntfy_topic")):
        out.append("alerts now go somewhere else")
    if b["partner"] and a["partner"] and _identity(b["partner"]) != _identity(a["partner"]):
        out.append("partner PIN or details changed")
    return out


def _covers(old: dict, new: dict) -> bool:
    if old["enabled"] and not new["enabled"]:
        return False
    return is_stricter_or_equal(_as_schedule(old), _as_schedule(new))


def _as_schedule(s: dict) -> Schedule:
    return Schedule(0, s["name"], s["days"], s["start_min"], s["end_min"], tuple(s["packages"]), True)


# --- merge ------------------------------------------------------------------------


def merge(base: dict | None, local: dict, remote: dict) -> dict:
    """Three-way merge. With no trusted ``base`` it's fail-safe: a union that removes
    nothing and only takes whitelist / always-allow entries this phone already has."""
    b, l_, r = protected(base or EMPTY), protected(local), protected(remote)
    if base is None:
        r = dict(r, rules=[rule for rule in r["rules"] if rule[0] not in LOOSENING_KINDS])
    return {
        "rules": _merge_items(b["rules"], l_["rules"], r["rules"], key=tuple),
        "apps": _merge_apps(b["apps"], l_["apps"], r["apps"]),
        "schedules": sorted(
            _merge_items(b["schedules"], l_["schedules"], r["schedules"], key=_schedule_key),
            key=_schedule_key,
        ),
        "settings": _merge_settings(b["settings"], l_["settings"], r["settings"]),
        "partner": _merge_partner(b["partner"], l_["partner"], r["partner"]),
    }


def _merge_items(base: list, local: list, remote: list, key) -> list:
    """Keep local; drop what the other phone removed; add what it added."""
    bk = {_freeze(key(i)) for i in base}
    rk = {_freeze(key(i)): i for i in remote}
    out = {_freeze(key(i)): i for i in local}
    for k in bk - set(rk):  # removed on the other phone
        out.pop(k, None)
    for k, item in rk.items():  # added on the other phone
        if k not in bk:
            out.setdefault(k, item)
    return sorted(out.values(), key=lambda i: json.dumps(i, sort_keys=True))


def _merge_apps(base: list, local: list, remote: list) -> list:
    packages = _merge_items([[p] for p, _ in base], [[p] for p, _ in local], [[p] for p, _ in remote], key=tuple)
    labels = dict(remote) | dict(local)
    return sorted([p, labels.get(p, p)] for (p,) in packages)


def _merge_settings(base: dict, local: dict, remote: dict) -> dict:
    out = {}
    for key in set(local) | set(remote):
        b = base.get(key)
        lv = local.get(key, remote.get(key))  # a key only one side knows about counts as unchanged
        rv = remote.get(key, local.get(key))
        if lv == rv:
            out[key] = lv
        elif lv == b:  # only the other phone changed it
            out[key] = rv
        elif rv == b:  # only this phone changed it
            out[key] = lv
        else:  # both changed it: the stricter value wins
            out[key] = _stricter(key, lv, rv)
    return out


def _stricter(key: str, a, b):
    if key in PROTECTIVE_FLAGS:
        return bool(a) or bool(b)
    if key == "unlock_minutes":
        return min(int(a), int(b))
    return a  # where alerts go etc.: keep this phone's choice


def _merge_partner(base, local, remote):
    if local is None or remote is None:
        return local or remote
    li, ri = _identity(local), _identity(remote)
    counter = max(int(local.get("totp_last_counter", 0)), int(remote.get("totp_last_counter", 0)))
    if li == ri:
        pick = local
    elif base is not None and li == _identity(base):
        pick = remote
    elif base is not None and ri == _identity(base):
        pick = local
    else:  # both changed: the most recent change wins
        pick = remote if float(remote.get("changed_at", 0)) > float(local.get("changed_at", 0)) else local
    return dict(pick, totp_last_counter=counter)


def _identity(partner: dict) -> tuple:
    return tuple(partner.get(f, "") for f in _PARTNER_IDENTITY)


def _schedule_key(s: dict) -> tuple:
    return (s["name"], s["days"], s["start_min"], s["end_min"], tuple(sorted(s["packages"])), bool(s["enabled"]))


def _freeze(value):
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value
