"""Bridge to the Android enforcement layer.

Phases 2-4 add a Flet extension (Kotlin) that owns the VPN, Accessibility and
Device Admin services. Until then every call reports "not available", so the
app runs unchanged on desktop/web for development.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    key: str
    title: str
    detail: str
    phase: int
    available: bool = False
    active: bool = False


COMPONENTS = (
    Component("vpn", "DNS filter", "Blocks sites and routes DNS via Cloudflare Family", 2),
    Component("accessibility", "Security overlay", "Covers blocked sites, apps and short-video feeds", 3),
    Component("device_admin", "Uninstall protection", "Needs the partner PIN to remove GuardPulse", 4),
)


class NativeBridge:
    def status(self) -> list[Component]:
        return list(COMPONENTS)

    def request(self, key: str) -> bool:
        """Ask Android for the permission behind ``key``. False until the extension lands."""
        return False

    def reload_policy(self) -> None:
        """Tell the running services to re-read policy.json."""
