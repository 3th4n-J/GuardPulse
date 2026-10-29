"""First-run flow: welcome -> partner PIN -> authenticator QR."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import flet as ft
import segno

from .. import security
from ..guard import GuardError
from . import theme

if TYPE_CHECKING:
    from .app import App


def qr_png(data: str) -> bytes:
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="png", scale=8, border=2, dark="#06122B", light="#FFFFFF")
    return buf.getvalue()


class Onboarding:
    def __init__(self, app: App):
        self.app = app
        self.page = app.page

    def show(self) -> None:
        self._screen(
            [
                ft.Container(theme.brand_mark(120, glow=True), padding=ft.Padding.only(top=24, bottom=8)),
                ft.Text(
                    "Stay protected.\nStay accountable.",
                    size=28,
                    weight=ft.FontWeight.W_800,
                    text_align=ft.TextAlign.CENTER,
                    color=theme.TEXT,
                ),
                ft.Text(
                    "GuardPulse blocks harmful sites and apps, filters adult content with "
                    "Cloudflare Family DNS, and puts your accountability partner in charge "
                    "of anything that would loosen protection. Free, forever.",
                    text_align=ft.TextAlign.CENTER,
                    color=theme.MUTED,
                ),
                self._feature(ft.Icons.BLOCK, "Block anything, any time", "Adding blocks never needs a PIN."),
                self._feature(
                    ft.Icons.HANDSHAKE_OUTLINED,
                    "Partner holds the key",
                    "Whitelists, deletions and switching protection off need their PIN.",
                ),
                self._feature(
                    ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED,
                    "Tamper alerts",
                    "Your partner hears about unlocks and protection being switched off.",
                ),
                ft.FilledButton(
                    "Set up my partner",
                    icon=ft.Icons.ARROW_FORWARD,
                    on_click=lambda _: self.partner_form(),
                    width=320,
                    height=48,
                ),
                ft.TextButton("Skip for now", on_click=lambda _: self._skip()),
            ]
        )

    def partner_form(self) -> None:
        name = ft.TextField(label="Partner's name", prefix_icon=ft.Icons.PERSON_OUTLINE)
        contact = ft.TextField(
            label="Email or phone (for alerts)",
            prefix_icon=ft.Icons.ALTERNATE_EMAIL,
            keyboard_type=ft.KeyboardType.EMAIL,
        )
        pin = ft.TextField(
            label="Partner PIN",
            password=True,
            can_reveal_password=True,
            keyboard_type=ft.KeyboardType.NUMBER,
            max_length=security.PIN_MAX_LENGTH,
            prefix_icon=ft.Icons.KEY,
            helper=f"{security.PIN_MIN_LENGTH}-{security.PIN_MAX_LENGTH} digits. Your partner types this - don't watch!",
        )
        confirm = ft.TextField(
            label="Confirm PIN",
            password=True,
            keyboard_type=ft.KeyboardType.NUMBER,
            max_length=security.PIN_MAX_LENGTH,
            prefix_icon=ft.Icons.KEY,
        )

        def save(_=None):
            for f in (name, pin, confirm):
                f.error = None
            if (pin.value or "") != (confirm.value or ""):
                confirm.error = "PINs don't match."
                self.page.update()
                return
            try:
                secret = self.app.guard.setup_partner(name.value, contact.value, pin.value)
            except security.WeakPin as exc:
                pin.error = str(exc)
                self.page.update()
                return
            except GuardError as exc:
                name.error = str(exc)
                self.page.update()
                return
            self.authenticator(secret, name.value.strip())

        confirm.on_submit = save
        self._screen(
            [
                ft.Icon(ft.Icons.HANDSHAKE_OUTLINED, size=56, color=theme.CYAN),
                ft.Text("Your accountability partner", size=24, weight=ft.FontWeight.W_800, color=theme.TEXT),
                ft.Text(
                    "Pick someone you trust. Hand them the phone now so they can choose a PIN "
                    "only they know.",
                    text_align=ft.TextAlign.CENTER,
                    color=theme.MUTED,
                ),
                theme.card(ft.Column([name, contact, pin, confirm], spacing=12), width=380),
                ft.FilledButton("Save partner", icon=ft.Icons.CHECK, on_click=save, width=320, height=48),
                ft.TextButton("Back", on_click=lambda _: self.show()),
            ]
        )

    def authenticator(self, secret: str, partner_name: str) -> None:
        uri = security.totp_uri(secret, partner_name)
        self._screen(
            [
                ft.Icon(ft.Icons.QR_CODE_2, size=56, color=theme.CYAN),
                ft.Text("Remote unlock codes", size=24, weight=ft.FontWeight.W_800, color=theme.TEXT),
                ft.Text(
                    f"{partner_name}: scan this with Google Authenticator, Microsoft "
                    "Authenticator or any TOTP app. When you're apart, they can read you the "
                    "6-digit code instead of the PIN. Each code works once.",
                    text_align=ft.TextAlign.CENTER,
                    color=theme.MUTED,
                ),
                ft.Container(
                    ft.Image(src=qr_png(uri), width=240, height=240),
                    bgcolor="#FFFFFF",
                    padding=12,
                    border_radius=20,
                ),
                theme.card(
                    ft.Column(
                        [
                            ft.Text("Can't scan? Enter this key manually:", size=12, color=theme.MUTED),
                            ft.Text(
                                " ".join(secret[i : i + 4] for i in range(0, len(secret), 4)),
                                selectable=True,
                                font_family="monospace",
                                weight=ft.FontWeight.W_600,
                                color=theme.TEXT,
                            ),
                        ],
                        spacing=4,
                    ),
                    width=380,
                ),
                ft.FilledButton(
                    "Done - start protecting",
                    icon=ft.Icons.SHIELD,
                    on_click=lambda _: self._finish(),
                    width=320,
                    height=48,
                ),
            ]
        )

    # --- helpers -----------------------------------------------------------

    def _skip(self) -> None:
        self.app.guard.note("onboarding.skipped")
        self._finish()

    def _finish(self) -> None:
        self.app.show_main()

    def _feature(self, icon: ft.IconData, title: str, text: str) -> ft.Control:
        return theme.card(
            ft.Row(
                [
                    ft.Container(
                        ft.Icon(icon, color=theme.CYAN),
                        padding=10,
                        border_radius=12,
                        bgcolor=ft.Colors.with_opacity(0.12, theme.CYAN),
                    ),
                    ft.Column(
                        [
                            ft.Text(title, weight=ft.FontWeight.W_700, color=theme.TEXT),
                            ft.Text(text, size=12, color=theme.MUTED),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                ]
            ),
            padding=12,
            width=380,
        )

    def _screen(self, controls: list[ft.Control]) -> None:
        page = self.page
        page.navigation_bar = None
        page.controls.clear()
        page.add(
            ft.SafeArea(
                ft.Container(
                    ft.Column(
                        controls,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=16,
                        scroll=ft.ScrollMode.AUTO,
                    ),
                    padding=24,
                    alignment=ft.Alignment.TOP_CENTER,
                ),
                expand=True,
            )
        )
        page.update()
