"""App shell: navigation, the partner-PIN gate, toasts and the unlock timer."""

from __future__ import annotations

import asyncio
from typing import Callable

import flet as ft

from ..guard import Guard, GuardError, Locked
from ..native import NativeBridge
from . import theme, views
from .onboarding import Onboarding

TABS = (
    ("Home", ft.Icons.SHIELD_OUTLINED, ft.Icons.SHIELD, views.home),
    ("Sites", ft.Icons.LANGUAGE_OUTLINED, ft.Icons.LANGUAGE, views.sites),
    ("Apps", ft.Icons.APPS_OUTLINED, ft.Icons.APPS, views.apps),
    ("Schedule", ft.Icons.SCHEDULE_OUTLINED, ft.Icons.SCHEDULE, views.schedule),
    ("Settings", ft.Icons.TUNE_OUTLINED, ft.Icons.TUNE, views.settings),
)


class App:
    def __init__(self, page: ft.Page, guard: Guard | None = None):
        self.page = page
        self.guard = guard or Guard()
        self.native = NativeBridge()
        self.tab = 0
        self.body = ft.Container(expand=True)
        self.lock_chip = ft.Container()
        self._dialogs: list[ft.DialogControl] = []

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        page = self.page
        page.title = "GuardPulse"
        theme.apply(page)
        if not self.guard.is_setup and not self.guard.history(1):
            Onboarding(self).show()
        else:
            self.show_main()
        page.run_task(self._tick)

    def show_main(self) -> None:
        page = self.page
        page.controls.clear()
        page.navigation_bar = ft.NavigationBar(
            selected_index=self.tab,
            bgcolor=theme.SURFACE,
            indicator_color=ft.Colors.with_opacity(0.22, theme.CYAN),
            destinations=[
                ft.NavigationBarDestination(icon=icon, selected_icon=sel, label=label)
                for label, icon, sel, _ in TABS
            ],
            on_change=self._on_tab,
        )
        page.add(ft.SafeArea(self.body, expand=True))
        self.render()

    def render(self) -> None:
        self._refresh_lock_chip()
        builder = TABS[self.tab][3]
        self.body.content = ft.Column(
            [self._header(), *builder(self)],
            scroll=ft.ScrollMode.AUTO,
            spacing=12,
            expand=True,
        )
        self.body.padding = ft.Padding.symmetric(horizontal=16, vertical=12)
        self.page.update()

    def _on_tab(self, e: ft.Event) -> None:
        self.tab = e.control.selected_index
        self.render()

    # --- guarded actions ---------------------------------------------------

    def act(self, fn: Callable[[], object], success: str | None = None) -> None:
        """Run ``fn``; if the partner is needed, ask for the PIN and retry once."""
        try:
            fn()
        except Locked as exc:
            self.ask_pin(exc.action, then=lambda: self.act(fn, success))
            self.render()
            return
        except (GuardError, ValueError) as exc:
            self.toast(str(exc), error=True)
            self.render()
            return
        if success:
            self.toast(success)
        self.render()

    def ask_pin(self, reason: str, then: Callable[[], None] | None = None) -> None:
        field = ft.TextField(
            label="Partner PIN or authenticator code",
            password=True,
            can_reveal_password=True,
            keyboard_type=ft.KeyboardType.NUMBER,
            max_length=12,
            autofocus=True,
            prefix_icon=ft.Icons.KEY,
        )

        async def submit(_=None):
            try:
                method = self.guard.unlock(field.value or "")
            except GuardError as exc:
                field.error = str(exc)
                field.value = ""
                field.update()
                await field.focus()
                return
            self.close_dialog()
            minutes = self.guard.setting("unlock_minutes")
            self.toast(
                f"Unlocked by {'PIN' if method == 'pin' else 'authenticator code'} for {minutes} min"
            )
            if then:
                then()
            else:
                self.render()

        field.on_submit = submit
        lockout = self.guard.lockout_remaining()
        self.open_dialog(
            ft.AlertDialog(
                modal=True,
                icon=ft.Icon(ft.Icons.LOCK, color=theme.CYAN, size=32),
                title=ft.Text("Partner approval needed", text_align=ft.TextAlign.CENTER),
                content=ft.Column(
                    [
                        ft.Text(
                            f"Hand the phone to your accountability partner to {reason}.",
                            color=theme.MUTED,
                        ),
                        ft.Text(
                            "Away from them? They can read you the 6-digit code from their "
                            "authenticator app.",
                            size=12,
                            color=theme.MUTED,
                        ),
                        field,
                        ft.Text(
                            f"Locked out for {lockout} s after wrong attempts.",
                            color=theme.AMBER,
                            size=12,
                            visible=lockout > 0,
                        ),
                    ],
                    tight=True,
                    spacing=10,
                    width=360,
                ),
                actions=[
                    ft.TextButton("Cancel", on_click=lambda _: self.close_dialog()),
                    ft.FilledButton("Unlock", icon=ft.Icons.LOCK_OPEN, on_click=submit),
                ],
            )
        )

    def open_dialog(self, dialog: ft.DialogControl) -> None:
        self._dialogs.append(dialog)
        self.page.show_dialog(dialog)

    def close_dialog(self) -> None:
        """Close our newest dialog. ``page.pop_dialog`` would close a toast on top of it."""
        while self._dialogs:
            dialog = self._dialogs.pop()
            if dialog.open:
                dialog.open = False
                dialog.update()
                return

    def lock_now(self) -> None:
        self.guard.lock()
        self.toast("Locked")
        self.render()

    def toast(self, message: str, error: bool = False) -> None:
        self.page.show_dialog(
            ft.SnackBar(
                content=ft.Row(
                    [
                        ft.Icon(
                            ft.Icons.ERROR_OUTLINE if error else ft.Icons.CHECK_CIRCLE_OUTLINE,
                            color=theme.DANGER if error else theme.PULSE,
                        ),
                        ft.Text(message, color=theme.TEXT, expand=True),
                    ]
                ),
                bgcolor=theme.SURFACE_HI,
                behavior=ft.SnackBarBehavior.FLOATING,
                duration=ft.Duration(seconds=4 if error else 2),
            )
        )

    # --- header + unlock timer ---------------------------------------------

    def _header(self) -> ft.Control:
        return ft.Row(
            [
                theme.brand_mark(40),
                ft.Column(
                    [
                        ft.Text("GuardPulse", size=20, weight=ft.FontWeight.W_800, color=theme.TEXT),
                        ft.Text(TABS[self.tab][0], size=12, color=theme.MUTED),
                    ],
                    spacing=0,
                    expand=True,
                ),
                self.lock_chip,
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

    def _refresh_lock_chip(self) -> None:
        g = self.guard
        if not g.is_setup:
            chip = theme.pill("No partner", theme.AMBER, ft.Icons.PERSON_OFF_OUTLINED)
            self.lock_chip.on_click = None
        elif g.unlocked:
            left = g.unlock_remaining
            chip = theme.pill(f"Unlocked {left // 60}:{left % 60:02d}", theme.AMBER, ft.Icons.LOCK_OPEN)
            self.lock_chip.on_click = lambda _: self.lock_now()
            self.lock_chip.tooltip = "Tap to lock now"
        else:
            chip = theme.pill("Locked", theme.PULSE, ft.Icons.LOCK)
            self.lock_chip.on_click = lambda _: self.ask_pin("unlock settings")
            self.lock_chip.tooltip = "Partner unlock"
        self.lock_chip.content = chip

    async def _tick(self) -> None:
        was_unlocked = self.guard.is_setup and self.guard.unlocked
        while True:
            await asyncio.sleep(1)
            if not self.guard.is_setup:
                continue
            unlocked = self.guard.unlocked
            try:
                if unlocked:
                    self._refresh_lock_chip()
                    self.lock_chip.update()
                elif was_unlocked:
                    self.render()  # timer ran out: re-lock the screens
            except RuntimeError:
                pass  # chip not on screen yet (onboarding)
            was_unlocked = unlocked


def main(page: ft.Page) -> None:
    App(page).start()
