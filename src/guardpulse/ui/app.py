"""App shell: navigation, the partner-PIN gate, toasts and the unlock timer."""

from __future__ import annotations

import asyncio
import time
from typing import Callable

import flet as ft

from .. import __version__, updates
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
        self.native = NativeBridge(page, self.guard.folder)
        self.tab = 0
        self.body = ft.Container(expand=True)
        self.lock_chip = ft.Container()
        self._dialogs: list[ft.DialogControl] = []
        self.update: updates.Release | None = None  # newer release, once found

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        page = self.page
        page.title = "GuardPulse"
        theme.apply(page)
        previous = self.guard.note_app_version(__version__)
        if not self.guard.is_setup and not self.guard.history(1):
            Onboarding(self).show()
        else:
            self.show_main()
            if previous:
                self.toast(f"Updated to {__version__} - all your rules and settings came along")
            if self.guard.recovered:
                self.toast("Your data was found and restored after the update")
        page.run_task(self._tick)
        page.run_task(self.check_for_updates, False)

    # --- updates ---------------------------------------------------------------

    async def check_for_updates(self, manual: bool = True) -> None:
        """Daily silent check; ``manual`` (About button) always checks and reports."""
        last = float(self.guard.meta("update_checked_at") or 0)
        if not manual and time.time() - last < updates.CHECK_EVERY_SECONDS:
            return
        if manual:
            self.toast("Checking for updates…")  # GitHub can take a few seconds
        release, reached = await updates.latest_release()
        if not reached:
            if manual:
                self.toast("Couldn't reach GitHub - check your connection", error=True)
            return
        self.guard.set_meta("update_checked_at", str(time.time()))
        if release is not None and updates.is_newer(release.tag, __version__):
            self.update = release
            if manual:
                self.show_update(release)
            elif self.page.navigation_bar is not None:
                self.render()
        elif manual:
            self.toast(f"You're on the latest version ({__version__})")

    def show_update(self, release: updates.Release) -> None:
        status = ft.Text("", size=12, color=theme.AMBER, visible=False)
        busy = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)

        def progress(message: str) -> None:
            status.value, status.visible, busy.visible = message, True, True
            status.color = theme.MUTED
            status.update()
            busy.update()

        async def run_update():
            update_btn.disabled = True
            update_btn.update()
            # private safety copy first - an in-place update keeps data anyway,
            # this covers a damaged file or a future storage move
            self.guard.snapshot(f"before-{release.version}")
            result = await self.native.update_app(release.apk_url, progress)
            busy.visible = False
            if result == "started":
                status.value, status.color = "Confirm the install on Android's screen. GuardPulse restarts on the new version.", theme.PULSE
            elif result == "needs_permission":
                status.value, status.color = (
                    "Allow \"Install unknown apps\" for GuardPulse on the screen that just opened, "
                    "then come back and tap Update again.",
                    theme.AMBER,
                )
            else:
                status.value, status.color = result, theme.DANGER
            status.visible = True
            update_btn.disabled = False
            status.update()
            busy.update()
            update_btn.update()

        update_btn = ft.FilledButton(
            "Update now",
            icon=ft.Icons.SYSTEM_UPDATE,
            on_click=lambda _: self.page.run_task(run_update),
            visible=self.native.available and bool(release.apk_url),
        )
        self.open_dialog(
            ft.AlertDialog(
                icon=ft.Icon(ft.Icons.NEW_RELEASES_OUTLINED, color=theme.CYAN, size=32),
                title=ft.Text(f"GuardPulse {release.version}", text_align=ft.TextAlign.CENTER),
                content=ft.Column(
                    [
                        ft.Text(f"You have {__version__}.", size=12, color=theme.MUTED),
                        ft.Container(
                            ft.Markdown(release.notes or "_No release notes._", selectable=True),
                            height=200 if len(release.notes) > 300 else None,
                        ),
                        theme.card(
                            ft.Row(
                                [
                                    ft.Icon(ft.Icons.VERIFIED_USER_OUTLINED, color=theme.PULSE),
                                    ft.Text(
                                        "Your data stays put. GuardPulse checks the download is signed with "
                                        "its own key so Android updates in place, and keeps a private safety "
                                        "copy first.",
                                        size=12,
                                        color=theme.MUTED,
                                        expand=True,
                                    ),
                                ]
                            ),
                            padding=10,
                        ),
                        ft.Row([busy, status], spacing=8),
                    ],
                    tight=True,
                    spacing=10,
                    width=360,
                    scroll=ft.ScrollMode.AUTO,
                ),
                actions=[
                    ft.TextButton("Later", on_click=lambda _: self.close_dialog()),
                    ft.TextButton("Release page", url=release.page_url),
                    update_btn,
                ],
            )
        )

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
        if self.native.available:
            self.page.run_task(self.native.reload_policy)
        self.render()

    # --- DNS filter (Android) ------------------------------------------------

    def enable_filter(self) -> None:
        async def run():
            if await self.native.enable_filter():
                self.guard.note("filter.enabled")
                self.toast("DNS filter is on")
            else:
                self.toast("Android's VPN permission is needed to filter sites.", error=True)
            self.render()

        self.page.run_task(run)

    def disable_filter(self) -> None:
        def gate():
            self.guard.authorise_filter_off()
            self.page.run_task(self._stop_filter)

        self.act(gate)

    async def _stop_filter(self) -> None:
        await self.native.disable_filter()
        self.toast("DNS filter is off")
        self.render()

    def open_vpn_settings(self) -> None:
        self.page.run_task(self.native.open_vpn_settings)

    # --- security overlay (Android) ------------------------------------------

    def enable_overlay(self) -> None:
        """Android won't let apps switch accessibility on themselves - walk the user through it."""

        def step(n: str, text: str) -> ft.Control:
            return ft.Row(
                [
                    ft.Container(
                        ft.Text(n, weight=ft.FontWeight.W_800, color=theme.NAVY),
                        width=26,
                        height=26,
                        border_radius=13,
                        bgcolor=theme.CYAN,
                        alignment=ft.Alignment.CENTER,
                    ),
                    ft.Text(text, size=13, color=theme.TEXT, expand=True),
                ],
                vertical_alignment=ft.CrossAxisAlignment.START,
            )

        self.open_dialog(
            ft.AlertDialog(
                icon=ft.Icon(ft.Icons.LAYERS_OUTLINED, color=theme.CYAN, size=32),
                title=ft.Text("Turn on the security overlay", text_align=ft.TextAlign.CENTER),
                content=ft.Column(
                    [
                        step("1", "Tap Accessibility below, open Installed apps (or Downloaded apps) "
                                  "and switch GuardPulse security overlay on."),
                        step("2", "If Android says it's a restricted setting: tap App info, open the "
                                  "⋮ menu, choose Allow restricted settings, then try step 1 again."),
                        step("3", "Come back here - the overlay card turns green once it's running."),
                        ft.Text(
                            "GuardPulse only reads which app is open and your browser's address bar. "
                            "Nothing leaves this phone.",
                            size=11,
                            color=theme.MUTED,
                        ),
                    ],
                    tight=True,
                    spacing=12,
                    width=360,
                ),
                actions=[
                    ft.TextButton("App info", on_click=lambda _: self.page.run_task(self.native.open_app_info)),
                    ft.FilledButton(
                        "Accessibility",
                        icon=ft.Icons.OPEN_IN_NEW,
                        on_click=lambda _: self._open_accessibility(),
                    ),
                ],
            )
        )

    def _open_accessibility(self) -> None:
        self.close_dialog()
        self.guard.note("overlay.setup_opened")
        self.page.run_task(self.native.open_accessibility_settings)

    def disable_overlay(self) -> None:
        def gate():
            self.guard.authorise_overlay_off()
            self.page.run_task(self._stop_overlay)

        self.act(gate)

    async def _stop_overlay(self) -> None:
        await self.native.disable_overlay()
        self.toast("Security overlay is off")
        self.render()

    # --- uninstall protection (Android device admin) -------------------------

    def enable_uninstall(self) -> None:
        async def run():
            await self.native.enable_uninstall_protection()
            self.guard.note("uninstall.enabled")
            if not self.native.admin_active:
                self.toast("Activate GuardPulse on the screen that opened, then come back.")
            self.render()

        self.page.run_task(run)

    def disable_uninstall(self) -> None:
        def gate():
            self.guard.authorise_uninstall_off()
            self.page.run_task(self._stop_uninstall)

        self.act(gate)

    async def _stop_uninstall(self) -> None:
        await self.native.disable_uninstall_protection()
        self.toast("Uninstall protection is off")
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
        # toasts raised from background tasks (update check) aren't auto-flushed
        self.page.update()

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
        seconds = 0
        await self._poll_native(initial=True)
        while True:
            await asyncio.sleep(1)
            seconds += 1
            if seconds % 5 == 0:
                await self._poll_native()
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

    async def _poll_native(self, initial: bool = False) -> None:
        """Pick up tamper events and status changes from the Kotlin side."""
        if not self.native.available:
            return
        events = self.native.drain_events()
        for event in events:
            self.guard.record_native(event.get("event", "unknown"), event.get("detail", ""))
        keys = (
            "vpn_running",
            "vpn_prepared",
            "always_on",
            "private_dns_mode",
            "private_dns_host",
            "overlay_enabled",
            "overlay_wanted",
            "device_admin_active",
            "device_admin_wanted",
        )
        before = {k: self.native.state.get(k) for k in keys}
        await self.native.refresh()
        # counters change constantly; only re-render (which resets scroll) on real state changes
        changed = bool(events) or {k: self.native.state.get(k) for k in keys} != before
        if (initial or changed) and self.page.navigation_bar is not None and self.tab in (0, 4):
            try:
                self.render()
            except RuntimeError:
                pass


def main(page: ft.Page) -> None:
    App(page).start()
