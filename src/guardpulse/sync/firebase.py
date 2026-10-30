"""Firebase Auth + Firestore over plain HTTPS (Spark/free plan, no SDK).

- Sign-in: a Google ID token (from Android's "Sign in with Google") is
  exchanged at Identity Toolkit for a Firebase session; refreshed via the
  Secure Token API.
- Data: one Firestore document per account,
  ``users/{uid}/guardpulse/state`` = {blob, rev}. ``blob`` is the AES-GCM
  encrypted snapshot; Firestore never sees anything readable. Writes carry an
  ``updateTime`` precondition so two phones can't silently overwrite each other.

The project's Firestore rules must restrict ``users/{uid}`` to that uid
(see firebase/firestore.rules).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

CONFIG_FILE = Path(__file__).resolve().parents[1] / "firebase.json"
SESSION_FILE = "sync_session.json"


class FirebaseError(Exception):
    pass


class Conflict(FirebaseError):
    """The cloud copy changed since we read it - pull and merge again."""


@dataclass(frozen=True)
class Config:
    api_key: str = ""
    project_id: str = ""
    web_client_id: str = ""  # OAuth "Web client" id - Android sign-in needs it as serverClientId

    @property
    def ready(self) -> bool:
        return bool(self.api_key and self.project_id and self.web_client_id)

    @staticmethod
    def load(path: Path = CONFIG_FILE) -> "Config":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return Config()
        return Config(
            api_key=str(data.get("api_key", "")).strip(),
            project_id=str(data.get("project_id", "")).strip(),
            web_client_id=str(data.get("web_client_id", "")).strip(),
        )


@dataclass
class Session:
    uid: str
    email: str
    id_token: str
    refresh_token: str
    expires_at: float

    def save(self, folder: Path) -> None:
        (folder / SESSION_FILE).write_text(json.dumps(asdict(self)), encoding="utf-8")

    @staticmethod
    def load(folder: Path) -> "Session | None":
        try:
            return Session(**json.loads((folder / SESSION_FILE).read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def forget(folder: Path) -> None:
        (folder / SESSION_FILE).unlink(missing_ok=True)


# (method, url, json_body | None, headers) -> (status, parsed json)
Http = Callable[[str, str, dict | None, dict], tuple[int, dict]]


def _http(method: str, url: str, body: dict | None, headers: dict) -> tuple[int, dict]:
    data = None
    if body is not None:
        if headers.get("Content-Type") == "application/x-www-form-urlencoded":
            data = urllib.parse.urlencode(body).encode()
        else:
            data = json.dumps(body).encode()
            headers = {"Content-Type": "application/json", **headers}
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except ValueError:
            return exc.code, {"error": {"message": raw.decode(errors="replace")[:200]}}


class Firebase:
    def __init__(self, config: Config, http: Http = _http, clock: Callable[[], float] = time.time):
        self.config = config
        self.http = http
        self.clock = clock

    # --- auth ------------------------------------------------------------------

    def sign_in_with_google(self, google_id_token: str) -> Session:
        status, data = self.http(
            "POST",
            f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key={self.config.api_key}",
            {
                "postBody": urllib.parse.urlencode({"id_token": google_id_token, "providerId": "google.com"}),
                "requestUri": "http://localhost",
                "returnSecureToken": True,
                "returnIdpCredential": True,
            },
            {},
        )
        if status != 200:
            raise FirebaseError(_message(data, "Google sign-in was refused by Firebase."))
        return Session(
            uid=data["localId"],
            email=data.get("email", ""),
            id_token=data["idToken"],
            refresh_token=data["refreshToken"],
            expires_at=self.clock() + int(data.get("expiresIn", 3600)),
        )

    def fresh(self, session: Session) -> Session:
        """Refresh the ID token if it expires within 5 minutes."""
        if session.expires_at - self.clock() > 300:
            return session
        status, data = self.http(
            "POST",
            f"https://securetoken.googleapis.com/v1/token?key={self.config.api_key}",
            {"grant_type": "refresh_token", "refresh_token": session.refresh_token},
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        if status != 200:
            raise FirebaseError(_message(data, "Your sign-in expired - sign in again."))
        return Session(
            uid=data.get("user_id", session.uid),
            email=session.email,
            id_token=data["id_token"],
            refresh_token=data.get("refresh_token", session.refresh_token),
            expires_at=self.clock() + int(data.get("expires_in", 3600)),
        )

    # --- data ------------------------------------------------------------------

    def _doc_url(self, session: Session) -> str:
        return (
            f"https://firestore.googleapis.com/v1/projects/{self.config.project_id}"
            f"/databases/(default)/documents/users/{session.uid}/guardpulse/state"
        )

    def get_state(self, session: Session) -> tuple[str | None, int, str | None]:
        """(blob, rev, updateTime); blob is None when nothing has been synced yet."""
        status, data = self.http("GET", self._doc_url(session), None, _auth(session))
        if status == 404:
            return None, 0, None
        if status != 200:
            raise FirebaseError(_message(data, "Couldn't read your synced data."))
        fields = data.get("fields", {})
        return (
            fields.get("blob", {}).get("stringValue"),
            int(fields.get("rev", {}).get("integerValue", 0)),
            data.get("updateTime"),
        )

    def put_state(self, session: Session, blob: str, rev: int, update_time: str | None) -> str:
        """Write only if the document is still what we read (or still absent)."""
        precondition = (
            f"currentDocument.updateTime={urllib.parse.quote(update_time)}"
            if update_time
            else "currentDocument.exists=false"
        )
        status, data = self.http(
            "PATCH",
            f"{self._doc_url(session)}?{precondition}",
            {"fields": {"blob": {"stringValue": blob}, "rev": {"integerValue": str(rev)}}},
            _auth(session),
        )
        precondition_failed = status in (400, 409, 412) and "FAILED_PRECONDITION" in json.dumps(data)
        if precondition_failed or status == 409:
            raise Conflict("Another phone synced at the same moment.")
        if status != 200:
            raise FirebaseError(_message(data, "Couldn't save your synced data."))
        return data.get("updateTime", "")


def _auth(session: Session) -> dict:
    return {"Authorization": f"Bearer {session.id_token}"}


def _message(data: dict, fallback: str) -> str:
    err = data.get("error")
    if isinstance(err, dict) and err.get("message"):
        return f"{fallback} ({err['message']})"
    return fallback
