"""Bridge to the Android enforcement layer (extensions/flet_guardpulse_native).

On Android the GuardNative service talks to the Kotlin DNS-filter VPN. On
desktop/web, or a build without the extension, every component reports
"not available" so the app still runs for development.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import flet as ft

try:  # Android builds bundle the extension; desktop dev may not have it
    from flet_guardpulse_native import GuardNative
except ImportError:  # pragma: no cover - depends on the environment
    GuardNative = None

# native events that mean protection was weakened outside the app
TAMPER_EVENTS = {"vpn_revoked", "policy_signature_invalid"}
FAMILY_PRIVATE_DNS = "family.cloudflare-dns.com"


@dataclass(frozen=True)
class Component:
    key: str
    title: str
    detail: str
    phase: int
    available: bool = False
    active: bool = False


class NativeBridge:
    def __init__(self, page: ft.Page | None = None, folder: Path | None = None):
        self.folder = folder
        self.service = None
        self.state: dict[str, Any] = {}
        if page is not None and GuardNative is not None and page.platform == ft.PagePlatform.ANDROID:
            self.service = GuardNative()
            page.services.append(self.service)

    @property
    def available(self) -> bool:
        return self.service is not None

    @property
    def filter_running(self) -> bool:
        return bool(self.state.get("vpn_running"))

    def status(self) -> list[Component]:
        return [
            Component(
                "vpn",
                "DNS filter",
                self._vpn_detail(),
                2,
                available=self.available,
                active=self.filter_running,
            ),
            Component("accessibility", "Security overlay", "Covers blocked sites, apps and short-video feeds", 3),
            Component("device_admin", "Uninstall protection", "Needs the partner PIN to remove GuardPulse", 4),
        ]

    def _vpn_detail(self) -> str:
        if not self.available:
            return "Blocks sites and routes DNS via Cloudflare Family (Android only)"
        if not self.filter_running:
            return "Off - tap Turn on to start filtering"
        blocked = self.state.get("blocked", 0)
        always_on = " · Always-on" if self.state.get("always_on") else ""
        return f"Filtering every app · {blocked} lookups blocked{always_on}"

    def private_dns_warning(self) -> str | None:
        """Private DNS set to another provider bypasses the filter."""
        mode = self.state.get("private_dns_mode")
        host = (self.state.get("private_dns_host") or "").lower()
        if mode == "hostname" and host and host != FAMILY_PRIVATE_DNS:
            return (
                f"Private DNS is set to {host}, which skips the filter. In Android Settings > "
                f"Network > Private DNS, choose Off, Automatic or {FAMILY_PRIVATE_DNS}."
            )
        return None

    @property
    def needs_always_on(self) -> bool:
        return self.filter_running and not self.state.get("always_on")

    # --- calls into Kotlin --------------------------------------------------

    async def refresh(self) -> None:
        if not self.service:
            return
        try:
            self.state = await self.service.status()
        except Exception:  # noqa: BLE001 - a status failure must never break the UI
            self.state = {}

    async def enable_filter(self) -> bool:
        """VPN consent (first time only), then start. False if the user declined."""
        if not self.service or self.folder is None:
            return False
        if not await self.service.prepare_vpn():
            return False
        started = await self.service.start_vpn(str(self.folder))
        await self.refresh()
        return started

    async def disable_filter(self) -> None:
        if self.service:
            await self.service.stop_vpn()
            await self.refresh()

    async def reload_policy(self) -> None:
        if self.service and self.filter_running:
            await self.service.reload_policy()

    async def open_vpn_settings(self) -> None:
        if self.service:
            await self.service.open_vpn_settings()

    # --- events from Kotlin -------------------------------------------------

    def drain_events(self) -> list[dict]:
        """Read and clear native_events.jsonl (written by the Kotlin side)."""
        if self.folder is None:
            return []
        path = self.folder / "native_events.jsonl"
        if not path.exists():
            return []
        claimed = path.with_suffix(".reading")
        try:
            os.replace(path, claimed)  # atomic: new events go to a fresh file
            lines = claimed.read_text(encoding="utf-8").splitlines()
            claimed.unlink()
        except OSError:
            return []
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
