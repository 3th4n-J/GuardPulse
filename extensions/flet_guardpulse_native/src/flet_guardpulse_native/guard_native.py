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
