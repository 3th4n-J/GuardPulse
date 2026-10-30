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
TAMPER_EVENTS = {
    "vpn_revoked",
    "policy_signature_invalid",
    "accessibility_disabled",
    "device_admin_removed",
}
# GuardPulse release key (CN=Ethan Johnston, OU=GuardPulse); see build-release.ps1
RELEASE_SIGNER_SHA256 = "6aba3b6c14d4f19c9373ec672320ce6724499a94e34a7ad489d1b3f08b0e6db8"
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
        self.installed_apps: list[dict[str, str]] = []
        self.app_info: dict[str, Any] = {}
        self.icons: dict[str, str] = {}  # package -> base64 PNG, from this phone only
        self._no_icon: set[str] = set()
        self._configured = False
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
            Component(
                "accessibility",
                "Security overlay",
                self._overlay_detail(),
                3,
                available=self.available,
                active=self.overlay_running,
            ),
            Component(
                "device_admin",
                "Uninstall protection",
                self._admin_detail(),
                4,
                available=self.available,
                active=self.admin_active,
            ),
        ]

    @property
    def admin_active(self) -> bool:
        return bool(self.state.get("device_admin_active"))

    def _admin_detail(self) -> str:
        if not self.available:
            return "Needs the partner PIN to remove GuardPulse (Android only)"
        if not self.admin_active:
            return "Off - turn on to block uninstalling GuardPulse"
        return "On - uninstalling and its Settings pages need the partner PIN"

    def admin_off_warning(self) -> str | None:
        """Uninstall protection was on but device admin is no longer active."""
        if self.state.get("device_admin_wanted") and not self.state.get("device_admin_active"):
            return (
                "Uninstall protection was switched off. Your partner has been alerted. "
                "Turn it back on to keep GuardPulse from being removed."
            )
        return None

    def _vpn_detail(self) -> str:
        if not self.available:
            return "Blocks sites and routes DNS via Cloudflare Family (Android only)"
        if not self.filter_running:
            return "Off - tap Turn on to start filtering"
        blocked = self.state.get("blocked", 0)
        always_on = " · Always-on" if self.state.get("always_on") else ""
        return f"Filtering every app · {blocked} lookups blocked{always_on}"

    @property
    def overlay_running(self) -> bool:
        return bool(self.state.get("overlay_enabled"))

    def _overlay_detail(self) -> str:
        if not self.available:
            return "Covers blocked sites, apps and short-video feeds (Android only)"
        if not self.overlay_running:
            return "Off - tap Turn on, then switch GuardPulse on in Accessibility"
        s = self.state
        return (
            f"Watching every app · {s.get('overlay_blocked_apps', 0)} apps, "
            f"{s.get('overlay_blocked_sites', 0)} sites, {s.get('overlay_blocked_feeds', 0)} feeds stopped"
        )

    def overlay_off_warning(self) -> str | None:
        """The overlay was on but Android no longer has it enabled."""
        if self.state.get("overlay_wanted") and not self.state.get("overlay_enabled"):
            return (
                "The security overlay is switched off in Android's Accessibility settings. "
                "Your partner has been alerted. Turn it back on to keep blocked apps covered."
            )
        return None

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

    def lockdown_warning(self) -> str | None:
        """Android's "Block connections without VPN" breaks a DNS-only VPN.

        GuardPulse's tunnel carries DNS lookups only; everything else uses the
        normal network. Lockdown blocks all traffic that doesn't go *through* the
        VPN, so lookups work but nothing can connect - the whole phone goes offline.
        """
        if self.filter_running and self.state.get("lockdown"):
            return (
                "This setting stops ALL internet while GuardPulse's filter is on (it only "
                "filters lookups; the rest of your traffic uses the normal network). In "
                "Android's VPN settings tap the gear next to GuardPulse and switch it off. "
                "Keep 'Always-on VPN' on."
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
            if not self._configured and self.folder is not None:
                # the overlay may run without the VPN ever starting, so it
                # needs to learn where policy.json lives independently
                await self.service.configure(str(self.folder))
                self._configured = True
            if not self.app_info:
                self.app_info = await self.service.app_info()
            self.state = await self.service.status()
        except Exception:  # noqa: BLE001 - a status failure must never break the UI
            self.state = {}

    @property
    def official_build(self) -> bool | None:
        """Signed with the GuardPulse release key? None when unknown (desktop)."""
        signers = self.app_info.get("signer_sha256")
        if not signers:
            return None
        return RELEASE_SIGNER_SHA256 in signers

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
        if self.service and (self.filter_running or self.overlay_running):
            await self.service.reload_policy()

    async def open_vpn_settings(self) -> None:
        if self.service:
            await self.service.open_vpn_settings()

    async def open_accessibility_settings(self) -> None:
        if self.service:
            await self.service.open_accessibility_settings()

    async def open_app_info(self) -> None:
        if self.service:
            await self.service.open_app_info()

    async def disable_overlay(self) -> None:
        if self.service:
            await self.service.stop_overlay()
            await self.refresh()

    async def enable_uninstall_protection(self) -> bool:
        if not self.service:
            return False
        await self.service.request_device_admin()
        await self.refresh()
        return self.admin_active

    async def disable_uninstall_protection(self) -> None:
        if self.service:
            await self.service.remove_device_admin()
            await self.refresh()

    async def load_installed_apps(self) -> list[dict[str, str]]:
        if self.service and not self.installed_apps:
            try:
                self.installed_apps = await self.service.list_apps()
            except Exception:  # noqa: BLE001 - picker falls back to manual entry
                self.installed_apps = []
            for app in self.installed_apps:
                if app.get("icon"):
                    self.icons.setdefault(app["package"], app["icon"])
        return self.installed_apps

    async def load_icons(self, packages: list[str]) -> bool:
        """Fetch icons for packages we don't have yet. True if any new ones arrived."""
        missing = [p for p in packages if p not in self.icons and p not in self._no_icon]
        if not self.service or not missing:
            return False
        try:
            found = await self.service.app_icons(missing)
        except Exception:  # noqa: BLE001 - letter badges are a fine fallback
            return False
        self.icons.update(found)
        self._no_icon.update(p for p in missing if p not in found)
        return bool(found)

    # --- self-update ----------------------------------------------------------

    async def update_app(self, apk_url: str, progress) -> str:
        """Download -> verify (same key, newer) -> install. Returns "started",
        "needs_permission" or a human-readable refusal/failure reason."""
        if not self.service:
            return "Updating from inside the app works on Android only."
        try:
            progress("Downloading update…")
            await self.service.update_download(apk_url)
            progress("Checking it's a genuine GuardPulse update…")
            check = await self.service.update_verify()
            if not check.get("ok"):
                return check.get("reason") or "The update failed its safety check."
            progress("Handing it to Android…")
            return await self.service.update_install()
        except Exception as exc:  # noqa: BLE001 - shown to the user
            return f"Update failed: {exc}"

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
