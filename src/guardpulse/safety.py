"""Keeping GuardPulse data alive across updates.

An in-place Android update (same package, same signing key, higher
versionCode) never touches app-private data. Data is lost only when:

1. the update can't install in place (different signing key) and the user
   uninstalls to get it on - the updater refuses such APKs;
2. a new build looks for its data somewhere else (what happened to Selah
   when Flet moved FLET_APP_STORAGE_DATA) - ``recover_if_missing`` finds the
   old copy;
3. the database file is damaged - ``snapshot`` keeps recent copies.

Snapshots live in app-private storage (``<data>/backups``): they hold the
partner PIN hash and TOTP secret, so they must never go to shared storage.
"""

from __future__ import annotations

import shutil
import sqlite3
import time
from pathlib import Path

DB_NAME = "guardpulse.db"
KEY_NAME = "seal.key"
BACKUP_DIR = "backups"
KEEP_SNAPSHOTS = 3


def snapshot(folder: Path, conn: sqlite3.Connection, label: str, keep: int = KEEP_SNAPSHOTS) -> Path:
    """Consistent copy of the live DB (+ seal key) into ``<folder>/backups``."""
    target_dir = folder / BACKUP_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_label = "".join(c if c.isalnum() or c in ".-" else "_" for c in label)
    target = target_dir / f"guardpulse-{stamp}-{safe_label}.db"
    dest = sqlite3.connect(target)
    try:
        conn.backup(dest)  # online backup: safe while the app is using the DB
    finally:
        dest.close()
    key = folder / KEY_NAME
    if key.exists():
        shutil.copy2(key, target.with_suffix(".key"))
    _prune(target_dir, keep)
    return target


def snapshots(folder: Path) -> list[Path]:
    """Newest first."""
    target_dir = folder / BACKUP_DIR
    if not target_dir.exists():
        return []
    return sorted(target_dir.glob("guardpulse-*.db"), key=lambda p: p.name, reverse=True)


def _prune(target_dir: Path, keep: int) -> None:
    for old in sorted(target_dir.glob("guardpulse-*.db"), key=lambda p: p.name, reverse=True)[keep:]:
        old.unlink(missing_ok=True)
        old.with_suffix(".key").unlink(missing_ok=True)


def legacy_locations(folder: Path) -> list[Path]:
    """Where an older build might have kept its data, relative to today's folder.

    Flet 1.0 uses ``<app>/files/data``; older templates used ``<app>/app_flutter``
    or ``<app>/files``. Checking the neighbours covers a future move as well.
    """
    candidates = [
        folder.parent / "app_flutter",
        folder.parent,
        folder.parent.parent / "app_flutter",
        folder.parent.parent / "files",
        folder.parent.parent / "files" / "data",
    ]
    seen: list[Path] = []
    for c in candidates:
        try:
            resolved = c.resolve()
        except OSError:
            continue
        if resolved != folder.resolve() and resolved not in seen:
            seen.append(resolved)
    return seen


def _valid_db(path: Path) -> bool:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            ok = conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            has_rules = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rules'"
            ).fetchone()
            return ok and has_rules is not None
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def recover_if_missing(folder: Path) -> str | None:
    """If today's folder has no database, bring one back. Never overwrites.

    Order: an older build's folder first (newest data), then the newest
    valid snapshot. Returns a description of what was restored, or None.
    """
    db = folder / DB_NAME
    if db.exists():
        return None
    folder.mkdir(parents=True, exist_ok=True)
    for old in legacy_locations(folder):
        src = old / DB_NAME
        if src.is_file() and _valid_db(src):
            _restore(src, old / KEY_NAME, folder)
            return f"moved data from {old}"
    for snap in snapshots(folder):
        if _valid_db(snap):
            _restore(snap, snap.with_suffix(".key"), folder)
            return f"restored snapshot {snap.name}"
    return None


def _restore(db_src: Path, key_src: Path, folder: Path) -> None:
    # copy (not move) so the original stays put until the user is happy
    shutil.copy2(db_src, folder / DB_NAME)
    for suffix in ("-wal", "-shm"):
        side = db_src.with_name(db_src.name + suffix)
        if side.exists():
            shutil.copy2(side, folder / (DB_NAME + suffix))
    if key_src.is_file() and not (folder / KEY_NAME).exists():
        shutil.copy2(key_src, folder / KEY_NAME)
