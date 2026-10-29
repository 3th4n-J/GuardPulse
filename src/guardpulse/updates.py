"""Update check against GitHub Releases (3th4n-J/GuardPulse).

Only the *check* happens here (plain HTTPS, no token). Downloading and
installing happen in Kotlin (native.py) so the APK's signing certificate can
be compared with the installed app before Android is asked to install it.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

REPO = "3th4n-J/GuardPulse"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
CHECK_EVERY_SECONDS = 24 * 3600


@dataclass(frozen=True)
class Release:
    tag: str
    name: str
    notes: str
    page_url: str
    apk_url: str | None
    apk_name: str | None
    apk_size: int

    @property
    def version(self) -> str:
        return ".".join(str(n) for n in parse_version(self.tag)) or self.tag


def parse_version(tag: str | None) -> tuple[int, ...]:
    """'v0.4.0' -> (0, 4, 0); pre-release suffixes are ignored."""
    match = re.match(r"\s*v?(\d+(?:\.\d+)*)", tag or "")
    return tuple(int(x) for x in match.group(1).split(".")) if match else ()


def is_newer(tag: str, current: str) -> bool:
    latest, cur = parse_version(tag), parse_version(current)
    if not latest:
        return False
    width = max(len(latest), len(cur))
    return latest + (0,) * (width - len(latest)) > cur + (0,) * (width - len(cur))


def parse_release(data: dict) -> Release | None:
    """Pick the APK asset, preferring 'GuardPulse-<version>.apk'."""
    if not data or data.get("draft") or data.get("prerelease"):
        return None
    apks = [a for a in data.get("assets", []) if (a.get("name") or "").lower().endswith(".apk")]
    apks.sort(key=lambda a: not (a.get("name") or "").startswith("GuardPulse-"))
    apk = apks[0] if apks else None
    return Release(
        tag=data.get("tag_name", ""),
        name=data.get("name") or data.get("tag_name", ""),
        notes=(data.get("body") or "").strip(),
        page_url=data.get("html_url") or RELEASES_PAGE,
        apk_url=apk.get("browser_download_url") if apk else None,
        apk_name=apk.get("name") if apk else None,
        apk_size=int(apk.get("size") or 0) if apk else 0,
    )


def fetch_latest(timeout: float = 8) -> Release | None:
    request = urllib.request.Request(
        API_LATEST,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "GuardPulse-UpdateCheck"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return parse_release(json.loads(response.read().decode("utf-8")))


async def latest_release() -> tuple[Release | None, bool]:
    """``(release, reached)``. ``(None, True)`` = GitHub answered but nothing is published yet;
    ``(None, False)`` = offline or GitHub unreachable."""
    try:
        return await asyncio.to_thread(fetch_latest), True
    except urllib.error.HTTPError as exc:
        return None, exc.code == 404  # /releases/latest is 404 until the first release
    except Exception:  # noqa: BLE001 - a failed check must never bother the user
        return None, False
