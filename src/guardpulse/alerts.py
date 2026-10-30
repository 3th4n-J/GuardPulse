"""Partner alerts over ntfy (https://ntfy.sh).

The app's outbox (guard.outbox) holds events like "unlocked" or "whitelisted".
``deliver_pending`` posts each one to ``<ntfy_server>/<ntfy_topic>``; the
partner subscribes to that topic in the free ntfy app and gets a push.
Rows stay queued until ntfy accepts them, so nothing is lost while offline.

Tamper events raised by the Android layer (VPN switched off, overlay
disabled, ...) are sent by Kotlin itself (Alerts.kt) at the moment they
happen, so they don't wait for this app to be opened.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass
from typing import Callable

SETTING_LABELS = {
    "family_dns": "Cloudflare Family DNS",
    "browser_overlay": "the browser overlay",
    "feed_youtube_shorts": "YouTube Shorts blocking",
    "feed_instagram_reels": "Instagram Reels blocking",
    "feed_facebook_reels": "Facebook Reels blocking",
    "feed_snapchat_spotlight": "Snapchat Spotlight blocking",
    "settings_guard": "the Settings guard",
    "dns_filter": "the DNS filter",
    "security_overlay": "the security overlay",
    "uninstall_protection": "uninstall protection",
}


@dataclass(frozen=True)
class Alert:
    title: str
    message: str
    tags: str  # ntfy emoji shortcodes, comma separated
    priority: int  # 1 (min) .. 5 (max)


def describe(event: str, payload: dict) -> Alert:
    """Plain-language alert for an outbox event."""
    p = payload or {}
    if event == "unlocked":
        how = "authenticator code" if p.get("method") == "totp" else "PIN"
        return Alert("GuardPulse unlocked", f"Settings were unlocked with the partner {how}.", "unlock", 3)
    if event == "unlock_failed":
        n = p.get("attempts", "several")
        return Alert("Wrong PIN entered", f"{n} wrong PIN / code attempts in a row.", "warning", 4)
    if event == "whitelisted":
        return Alert("Site whitelisted", f"{p.get('value', 'A site')} was added to the allowed list.", "white_check_mark", 3)
    if event == "rule_removed":
        kind = "whitelist" if p.get("kind") == "allow" else "blocklist"
        return Alert("Rule removed", f"{p.get('value', 'A site')} was removed from the {kind}.", "wastebasket", 3)
    if event == "app_unblocked":
        return Alert("App unblocked", f"{p.get('package', 'An app')} is no longer blocked.", "unlock", 3)
    if event == "schedule_removed":
        return Alert("Schedule deleted", f"The '{p.get('name', '')}' app-lock schedule was deleted.", "wastebasket", 3)
    if event == "pin_changed":
        return Alert("Partner PIN changed", "The partner PIN was changed.", "key", 3)
    if event == "protection_disabled":
        what = SETTING_LABELS.get(p.get("setting", ""), p.get("setting", "a protection"))
        return Alert("Protection switched off", f"{what[:1].upper()}{what[1:]} was switched off.", "rotating_light", 4)
    if event == "tamper":
        return Alert("Tampering detected", p.get("what") or "GuardPulse's data was changed outside the app.", "rotating_light", 5)
    if event == "test":
        return Alert("GuardPulse test alert", "Alerts are working - you'll get a message like this when something changes.", "bell", 3)
    return Alert("GuardPulse", event.replace("_", " "), "bell", 3)


def post(server: str, topic: str, alert: Alert, timeout: float = 10) -> None:
    """POST one alert to ntfy. Raises on failure (caller retries later)."""
    request = urllib.request.Request(
        f"{server.rstrip('/')}/{topic}",
        data=alert.message.encode("utf-8"),
        method="POST",
        headers={
            # ntfy header values must be latin-1; titles here are plain ASCII
            "Title": alert.title,
            "Tags": alert.tags,
            "Priority": str(alert.priority),
            "User-Agent": "GuardPulse",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status >= 300:
            raise OSError(f"ntfy answered {response.status}")


def _alert_for(row) -> Alert:
    try:
        payload = json.loads(row["payload"] or "{}")
    except json.JSONDecodeError:
        payload = {}
    return describe(row["event"], payload)


def deliver_pending(guard, send: Callable[[str, str, Alert], None] = post) -> tuple[int, int]:
    """Send every queued alert. Returns ``(sent, failed)``."""
    server, topic = guard.setting("ntfy_server"), guard.setting("ntfy_topic")
    if not topic:
        return 0, 0
    sent = failed = 0
    for row in guard.pending_alerts():
        try:
            send(server, topic, _alert_for(row))
        except Exception:  # noqa: BLE001 - offline, DNS, ntfy down: retry next round
            guard.mark_alert(row["id"], sent=False)
            failed += 1
            break  # likely offline - don't hammer the rest this round
        guard.mark_alert(row["id"], sent=True)
        sent += 1
    return sent, failed


async def deliver_pending_async(guard, send: Callable[[str, str, Alert], None] = post) -> tuple[int, int]:
    """Same as ``deliver_pending`` but the HTTP call runs in a worker thread,
    while every database touch stays on the app's event loop."""
    server, topic = guard.setting("ntfy_server"), guard.setting("ntfy_topic")
    if not topic:
        return 0, 0
    sent = failed = 0
    for row in guard.pending_alerts():
        try:
            await asyncio.to_thread(send, server, topic, _alert_for(row))
        except Exception:  # noqa: BLE001
            guard.mark_alert(row["id"], sent=False)
            failed += 1
            break
        guard.mark_alert(row["id"], sent=True)
        sent += 1
    return sent, failed
