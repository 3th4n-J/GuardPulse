"""GuardNative service: Python handle on the Kotlin enforcement layer.

Every method forwards to the ``guardpulse/shield`` MethodChannel implemented in
``android/src/main/kotlin/za/co/guardpulse/shield``.

    shield = GuardNative()
    page.services.append(shield)
    if await shield.prepare_vpn():          # shows Android's VPN consent once
        await shield.start_vpn(folder)      # folder holding policy.json/.sig + seal.key
"""

from __future__ import annotations

from typing import Any

import flet as ft

__all__ = ["GuardNative"]


@ft.control("GuardNative")
class GuardNative(ft.Service):
    """Android-only. Check ``page.platform`` before adding it to ``page.services``."""

    async def status(self) -> dict[str, Any]:
        """VPN + Private DNS state, e.g. ``{"vpn_running": True, "blocked": 12, ...}``."""
        result = await self._invoke_method("status", {})
        return dict(result or {})

    async def prepare_vpn(self) -> bool:
        """Ask for VPN consent (system dialog). True once the user has allowed it."""
        return bool(await self._invoke_method("prepare_vpn", {}, timeout=120))

    async def start_vpn(self, folder: str) -> bool:
        return bool(await self._invoke_method("start_vpn", {"folder": folder}))

    async def stop_vpn(self) -> bool:
        return bool(await self._invoke_method("stop_vpn", {}))

    async def reload_policy(self) -> bool:
        return bool(await self._invoke_method("reload_policy", {}))

    async def open_vpn_settings(self) -> bool:
        """Open Android's VPN screen so the user can turn on Always-on VPN."""
        return bool(await self._invoke_method("open_vpn_settings", {}))

    async def configure(self, folder: str) -> bool:
        """Tell the native services where policy.json lives (call once at start-up)."""
        return bool(await self._invoke_method("configure", {"folder": folder}))

    async def open_accessibility_settings(self) -> bool:
        return bool(await self._invoke_method("open_accessibility_settings", {}))

    async def open_app_info(self) -> bool:
        """App info screen - where Android 13+ hides "Allow restricted settings"."""
        return bool(await self._invoke_method("open_app_info", {}))

    async def stop_overlay(self) -> bool:
        return bool(await self._invoke_method("stop_overlay", {}))

    async def list_apps(self) -> list[dict[str, str]]:
        """Launchable apps as ``[{"package", "label", "icon"}]`` (icon = base64 PNG), sorted by label."""
        result = await self._invoke_method("list_apps", {}, timeout=60)
        return [dict(a) for a in (result or [])]

    async def app_icons(self, packages: list[str]) -> dict[str, str]:
        """``{package: base64 PNG}`` for the ones installed on this phone."""
        result = await self._invoke_method("app_icons", {"packages": list(packages)}, timeout=30)
        return dict(result or {})

    async def app_info(self) -> dict[str, Any]:
        """Installed ``version_name``, ``signer_sha256`` list, ``can_install_updates``."""
        return dict(await self._invoke_method("app_info", {}) or {})

    async def update_download(self, url: str) -> int:
        """Download a release APK into the app cache; returns its size in bytes."""
        result = await self._invoke_method("update_download", {"url": url}, timeout=600)
        return int((result or {}).get("bytes", 0))

    async def update_verify(self) -> dict[str, Any]:
        """Same package, same signing key, newer version? ``{"ok": bool, "reason": str|None, ...}``"""
        return dict(await self._invoke_method("update_verify", {}, timeout=60) or {})

    async def update_install(self) -> str:
        """``"started"``, ``"needs_permission"`` (settings opened) or a refusal reason."""
        return str(await self._invoke_method("update_install", {}, timeout=120))

    async def flush_alerts(self, server: str, topic: str) -> int:
        """Retry the native tamper-alert queue; returns how many are still waiting."""
        return int(await self._invoke_method("flush_alerts", {"server": server, "topic": topic}, timeout=60) or 0)

    async def device_admin_active(self) -> bool:
        return bool(await self._invoke_method("device_admin_active", {}))

    async def request_device_admin(self) -> bool:
        """Open Android's "activate device admin" screen for uninstall protection."""
        return bool(await self._invoke_method("request_device_admin", {}))

    async def remove_device_admin(self) -> bool:
        """Deactivate device admin. The app must verify the partner PIN before calling."""
        return bool(await self._invoke_method("remove_device_admin", {}))
