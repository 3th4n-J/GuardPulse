"""Sync orchestration: sign-in, pairing, and the pull-merge-push loop.

Each operation is written once as a generator that ``yield``s its network
calls. ``_run`` executes those calls inline (tests, scripts); ``_run_async``
executes them in a worker thread so the app never freezes, while every
database touch stays on the app's event loop (one SQLite connection, one
thread).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

from .. import security
from ..guard import Guard, GuardError
from . import crypto, state
from .firebase import Config, Conflict, Firebase, FirebaseError, Session

BASE_FILE = "sync_base.json"
ACTIVITY_KEEP = 300


@dataclass(frozen=True)
class Status:
    configured: bool  # firebase.json filled in
    signed_in: bool
    email: str
    paired: bool  # this phone holds the sync key
    last_sync: float
    last_error: str


class SyncError(GuardError):
    """A user-facing sync problem (message shown as-is)."""


def _run(gen):
    """Drive a step generator, doing its network calls inline."""
    result, error = None, None
    while True:
        try:
            fn, args = gen.throw(error) if error else gen.send(result)
        except StopIteration as stop:
            return stop.value
        result, error = None, None
        try:
            result = fn(*args)
        except Exception as exc:  # noqa: BLE001 - re-raised inside the generator
            error = exc


async def _run_async(gen):
    """Same, but network calls run in a worker thread."""
    result, error = None, None
    while True:
        try:
            fn, args = gen.throw(error) if error else gen.send(result)
        except StopIteration as stop:
            return stop.value
        result, error = None, None
        try:
            result = await asyncio.to_thread(fn, *args)
        except Exception as exc:  # noqa: BLE001
            error = exc


class SyncManager:
    def __init__(self, guard: Guard, config: Config | None = None, firebase: Firebase | None = None):
        self.guard = guard
        self.folder: Path = guard.folder
        self.config = config or Config.load()
        self.firebase = firebase or Firebase(self.config)
        self.last_error = ""

    # --- status ----------------------------------------------------------------

    @property
    def session(self) -> Session | None:
        return Session.load(self.folder)

    @property
    def key(self) -> bytes | None:
        return crypto.load_key(self.folder)

    def status(self) -> Status:
        s = self.session
        return Status(
            configured=self.config.ready,
            signed_in=s is not None,
            email=s.email if s else "",
            paired=self.key is not None,
            last_sync=float(self.guard.meta("sync_at") or 0),
            last_error=self.last_error,
        )

    # --- public API (blocking + async twins) ---------------------------------------

    def sign_in(self, google_id_token: str) -> str:
        return _run(self._sign_in(google_id_token))

    async def sign_in_async(self, google_id_token: str) -> str:
        return await _run_async(self._sign_in(google_id_token))

    def pair(self, code: str) -> None:
        return _run(self._pair(code))

    async def pair_async(self, code: str) -> None:
        return await _run_async(self._pair(code))

    def sync_now(self) -> bool:
        return _run(self._sync())

    async def sync_now_async(self) -> bool:
        return await _run_async(self._sync())

    def pairing_code(self) -> str:
        """For the QR on an already-synced phone. Needs the partner: it unlocks everything."""
        self.guard._require("add another phone")
        s, key = self.session, self.key
        if s is None or key is None:
            raise SyncError("Turn on sync on this phone first.")
        self.guard.note("sync.pair_code_shown")
        return crypto.pair_code(s.uid, key)

    def sign_out(self) -> None:
        """Stop syncing on this phone. Needs the partner (sync carries the partner + PIN)."""
        self.guard._require("turn sync off")
        Session.forget(self.folder)
        crypto.forget_key(self.folder)
        (self.folder / BASE_FILE).unlink(missing_ok=True)
        self.guard.note("sync.signed_out")

    # --- steps (generators that yield network calls) -------------------------------

    def _sign_in(self, google_id_token: str):
        """Returns "synced" (first phone, or already paired) or "needs_pair"."""
        if not self.config.ready:
            raise SyncError("Sync isn't set up in this build yet (firebase.json is empty).")
        try:
            session = yield self.firebase.sign_in_with_google, (google_id_token,)
        except FirebaseError as exc:
            raise SyncError(str(exc)) from exc
        session.save(self.folder)
        self.guard.note("sync.signed_in", session.email)
        blob, _, _ = yield from self._get(session)
        if blob is None:  # first phone on this account: make the key, upload
            if self.key is None:
                crypto.save_key(self.folder, crypto.new_key())
            yield from self._sync()
            return "synced"
        if self.key is not None:
            try:
                crypto.open_(self.key, session.uid, blob)
                yield from self._sync()
                return "synced"
            except crypto.SyncCryptoError:
                crypto.forget_key(self.folder)  # key from another account / old pairing
        return "needs_pair"

    def _pair(self, code: str):
        """New phone: accept the key from the other phone's QR, then sync."""
        s = self.session
        if s is None:
            raise SyncError("Sign in with Google first.")
        try:
            uid, key = crypto.parse_pair_code(code)
        except crypto.SyncCryptoError as exc:
            raise SyncError(str(exc)) from exc
        if uid != s.uid:
            raise SyncError(
                "That code is from a different Google account. Sign in with the same account on both phones."
            )
        blob, _, _ = yield from self._get(s)
        if blob is not None:
            try:
                crypto.open_(key, uid, blob)
            except crypto.SyncCryptoError as exc:
                raise SyncError("That code doesn't match the synced data - show a fresh code.") from exc
        crypto.save_key(self.folder, key)
        self.guard.note("sync.paired")
        yield from self._sync()

    def _sync(self):
        """Pull, merge, apply, push. Returns True if this phone's rules changed."""
        session, key = self.session, self.key
        if session is None or key is None or not self.config.ready:
            return False
        try:
            for _attempt in range(3):
                session = yield from self._fresh(session)
                blob, rev, update_time = yield self.firebase.get_state, (session,)
                local = state.export(self.guard)
                remote = crypto.open_(key, session.uid, blob) if blob else None
                changed = False
                if remote is not None:
                    self.guard.import_activity(remote.get("activity", []))
                    base = self._load_base()
                    if base is None and state.is_blank(local):
                        merged = state.protected(remote)  # brand-new phone: take the account's state
                    else:
                        merged = state.merge(base, local, remote)
                    if merged != state.protected(local):
                        self.guard.apply_synced(merged)
                        changed = True
                    local = state.export(self.guard)
                upload = dict(local)
                upload["activity"] = _merge_activity(remote, local)
                needs_push = remote is None or state.protected(upload) != state.protected(remote) or (
                    {a["key"] for a in upload["activity"]} != {a["key"] for a in remote.get("activity", [])}
                )
                if needs_push:
                    try:
                        yield self.firebase.put_state, (
                            session, crypto.seal(key, session.uid, upload), rev + 1, update_time,
                        )
                    except Conflict:
                        continue  # someone else synced in between: pull again
                self._save_base(state.protected(local))
                self.guard.set_meta("sync_at", repr(self.guard.clock()))
                self.last_error = ""
                return changed
            raise SyncError("Couldn't sync - another phone kept changing things. Try again shortly.")
        except (FirebaseError, crypto.SyncCryptoError) as exc:
            self.last_error = str(exc)
            raise SyncError(str(exc)) from exc

    def _fresh(self, session: Session):
        fresh = yield self.firebase.fresh, (session,)
        if fresh is not session:
            fresh.save(self.folder)
        return fresh

    def _get(self, session: Session):
        try:
            session = yield from self._fresh(session)
            result = yield self.firebase.get_state, (session,)
            return result
        except FirebaseError as exc:
            raise SyncError(str(exc)) from exc

    # --- the agreed base -------------------------------------------------------------

    def _load_base(self) -> dict | None:
        """Last state both phones agreed on - sealed so it can't be edited to steer a merge."""
        try:
            raw = json.loads((self.folder / BASE_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        body = json.dumps(raw.get("state"), sort_keys=True).encode()
        if not security.seal_ok(self.guard.keys.get_key(), body, raw.get("seal", "")):
            return None  # tampered: fall back to the fail-safe union merge
        return raw["state"]

    def _save_base(self, snap: dict) -> None:
        body = json.dumps(snap, sort_keys=True).encode()
        (self.folder / BASE_FILE).write_text(
            json.dumps({"state": snap, "seal": security.seal(self.guard.keys.get_key(), body)}),
            encoding="utf-8",
        )


def _merge_activity(remote: dict | None, local: dict) -> list[dict]:
    """Every phone's recent activity, newest first, so the cloud keeps all of it."""
    seen: dict[str, dict] = {}
    for entry in (remote or {}).get("activity", []) + local.get("activity", []):
        seen.setdefault(entry["key"], entry)
    return sorted(seen.values(), key=lambda e: e["at"], reverse=True)[:ACTIVITY_KEEP]
