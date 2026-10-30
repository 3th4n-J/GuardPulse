"""The five tab screens. Each builder returns a list of controls for ``App.render``."""

from __future__ import annotations

import base64
import datetime as dt
from typing import TYPE_CHECKING

import flet as ft

from .. import __version__
from ..guard import FAMILY_DNS_V4, UNLOCK_MINUTES_RANGE, GuardError, Locked
from . import theme
from .onboarding import qr_png

if TYPE_CHECKING:
    from .app import App

DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

POPULAR_APPS = (
    ("TikTok", "com.zhiliaoapp.musically"),
    ("Instagram", "com.instagram.android"),
    ("Snapchat", "com.snapchat.android"),
    ("Reddit", "com.reddit.frontpage"),
    ("X", "com.twitter.android"),
    ("Telegram", "org.telegram.messenger"),
    ("Facebook", "com.facebook.katana"),
    ("Discord", "com.discord"),
    ("Tumblr", "com.tumblr"),
)

FEEDS = (
    ("feed_youtube_shorts", "YouTube Shorts", ft.Icons.SMART_DISPLAY_OUTLINED),
    ("feed_instagram_reels", "Instagram Reels", ft.Icons.MOVIE_FILTER_OUTLINED),
    ("feed_facebook_reels", "Facebook Reels", ft.Icons.VIDEO_LIBRARY_OUTLINED),
    ("feed_snapchat_spotlight", "Snapchat Spotlight", ft.Icons.FLASH_ON_OUTLINED),
)

ACTION_LABELS = {
    "partner.setup": ("Partner set up", ft.Icons.HANDSHAKE_OUTLINED),
    "unlock": ("Unlocked", ft.Icons.LOCK_OPEN),
    "unlock.failed": ("Wrong PIN / code", ft.Icons.GPP_BAD_OUTLINED),
    "block.added": ("Site blocked", ft.Icons.BLOCK),
    "block.removed": ("Block removed", ft.Icons.REMOVE_CIRCLE_OUTLINE),
    "allow.added": ("Site whitelisted", ft.Icons.CHECK_CIRCLE_OUTLINE),
    "allow.removed": ("Whitelist removed", ft.Icons.REMOVE_CIRCLE_OUTLINE),
    "app.blocked": ("App blocked", ft.Icons.APP_BLOCKING_OUTLINED),
    "app.unblocked": ("App unblocked", ft.Icons.REMOVE_CIRCLE_OUTLINE),
    "schedule.added": ("Schedule added", ft.Icons.SCHEDULE),
    "schedule.enabled": ("Schedule resumed", ft.Icons.PLAY_CIRCLE_OUTLINE),
    "schedule.paused": ("Schedule paused", ft.Icons.PAUSE_CIRCLE_OUTLINE),
    "schedule.removed": ("Schedule deleted", ft.Icons.DELETE_OUTLINE),
    "setting.changed": ("Setting changed", ft.Icons.TUNE),
    "partner.pin_changed": ("PIN changed", ft.Icons.KEY),
    "partner.totp_reset": ("Authenticator reset", ft.Icons.QR_CODE_2),
    "partner.updated": ("Partner updated", ft.Icons.PERSON_OUTLINE),
    "tamper.detected": ("Tampering detected", ft.Icons.WARNING_AMBER),
    "tamper.acknowledged": ("Tamper warning cleared", ft.Icons.VERIFIED_USER_OUTLINED),
    "onboarding.skipped": ("Partner setup skipped", ft.Icons.SKIP_NEXT),
    "filter.enabled": ("DNS filter on", ft.Icons.VPN_LOCK_OUTLINED),
    "filter.disabled": ("DNS filter off", ft.Icons.POWER_SETTINGS_NEW),
    "overlay.setup_opened": ("Overlay setup opened", ft.Icons.LAYERS_OUTLINED),
    "native.secure_dns_tip": ("Browser secure-DNS tip shown", ft.Icons.DNS_OUTLINED),
    "alerts.topic_created": ("Partner alerts set up", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED),
    "alerts.topic_changed": ("Partner alert link changed", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED),
    "alerts.test": ("Test alert sent", ft.Icons.SEND),
    "uninstall.enabled": ("Uninstall protection on", ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED),
    "uninstall.disabled": ("Uninstall protection off", ft.Icons.GPP_BAD_OUTLINED),
    "native.device_admin_removed": ("Uninstall protection removed", ft.Icons.GPP_BAD_OUTLINED),
    "native.settings_unlocked": ("Settings unlocked with PIN", ft.Icons.LOCK_OPEN),
    "native.settings_pin_failed": ("Wrong PIN at Settings", ft.Icons.GPP_BAD_OUTLINED),
    "app.updated": ("App updated", ft.Icons.SYSTEM_UPDATE),
    "data.snapshot": ("Safety copy saved", ft.Icons.SAVE_OUTLINED),
    "data.recovered": ("Data restored", ft.Icons.RESTORE),
    "native.update_installed": ("Update installed", ft.Icons.SYSTEM_UPDATE),
    "native.update_failed": ("Update failed", ft.Icons.ERROR_OUTLINE),
    "overlay.disabled": ("Security overlay off", ft.Icons.LAYERS_CLEAR_OUTLINED),
    "native.vpn_not_prepared": ("VPN permission missing", ft.Icons.GPP_MAYBE_OUTLINED),
}


# --- shared pieces ---------------------------------------------------------


def _hhmm(minutes: int) -> str:
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def _when(ts: float) -> str:
    moment = dt.datetime.fromtimestamp(ts)
    if moment.date() == dt.date.today():
        return moment.strftime("Today %H:%M")
    return moment.strftime("%d %b %H:%M")


def _lock_icon(app: App) -> ft.Control:
    """Small padlock shown next to actions that need the partner."""
    return ft.Icon(
        ft.Icons.LOCK_OUTLINE if not app.guard.unlocked else ft.Icons.LOCK_OPEN,
        size=14,
        color=theme.MUTED if not app.guard.unlocked else theme.AMBER,
    )


def _activity_tile(row) -> ft.Control:
    label, icon = ACTION_LABELS.get(row["action"], (row["action"], ft.Icons.CIRCLE_OUTLINED))
    by = {"pin": "PIN", "totp": "Code", "setup": "Setup"}.get(row["authorised_by"])
    danger = row["action"].startswith(("tamper.detected", "unlock.failed"))
    trailing = theme.pill(by, theme.AMBER, ft.Icons.KEY) if by else None
    return ft.ListTile(
        leading=ft.Icon(icon, color=theme.DANGER if danger else theme.CYAN),
        title=ft.Text(label, color=theme.TEXT, weight=ft.FontWeight.W_600),
        subtitle=ft.Text(
            f"{row['detail']}  ·  {_when(row['at'])}" if row["detail"] else _when(row["at"]),
            color=theme.MUTED,
            size=12,
        ),
        trailing=trailing,
        dense=True,
    )


def _remove_button(app: App, tooltip: str, on_click) -> ft.Control:
    return ft.IconButton(
        icon=ft.Icons.DELETE_OUTLINE,
        icon_color=theme.MUTED if not app.guard.unlocked else theme.DANGER,
        tooltip=tooltip + ("" if app.guard.unlocked else " (partner PIN)"),
        on_click=on_click,
    )


# --- Home ------------------------------------------------------------------


def home(app: App) -> list[ft.Control]:
    g = app.guard
    stats = g.stats()
    out: list[ft.Control] = []

    if g.tampered:
        out.append(
            theme.card(
                ft.Row(
                    [
                        ft.Icon(ft.Icons.WARNING_AMBER, color=theme.DANGER, size=28),
                        ft.Column(
                            [
                                ft.Text("Tampering detected", weight=ft.FontWeight.W_700, color=theme.TEXT),
                                ft.Text(
                                    "Protection was changed outside GuardPulse. Your partner has been "
                                    "alerted and must clear this warning.",
                                    size=12,
                                    color=theme.MUTED,
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                        ft.TextButton("Clear", on_click=lambda _: app.act(g.acknowledge_tamper, "Warning cleared")),
                    ]
                ),
                border_color=theme.DANGER,
            )
        )
    if not g.is_setup:
        out.append(
            theme.card(
                ft.Row(
                    [
                        ft.Icon(ft.Icons.PERSON_ADD_ALT_1_OUTLINED, color=theme.AMBER, size=28),
                        ft.Column(
                            [
                                ft.Text("No accountability partner yet", weight=ft.FontWeight.W_700, color=theme.TEXT),
                                ft.Text(
                                    "Anyone holding this phone can remove blocks until a partner is set.",
                                    size=12,
                                    color=theme.MUTED,
                                ),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                        ft.FilledButton("Set up", on_click=lambda _: _start_partner_setup(app)),
                    ]
                ),
                border_color=theme.AMBER,
            )
        )

    if app.update:
        release = app.update
        out.append(
            _notice(
                ft.Icons.NEW_RELEASES_OUTLINED,
                f"Update available: {release.version}",
                "See what's new. Updating keeps all your rules, partner and history.",
                theme.CYAN,
                action=ft.TextButton("View", on_click=lambda _: app.show_update(release)),
            )
        )

    # hero
    active = g.setting("family_dns")
    protected = app.native.filter_running
    blocked = app.native.state.get("blocked", 0)
    out.append(
        ft.Container(
            ft.Row(
                [
                    ft.Column(
                        [
                            theme.pill("Protected", theme.PULSE, ft.Icons.FAVORITE)
                            if protected
                            else theme.pill("Filter off", theme.AMBER, ft.Icons.POWER_SETTINGS_NEW),
                            ft.Text(
                                "Your shield is up" if protected else "Your shield",
                                size=24,
                                weight=ft.FontWeight.W_800,
                                color=theme.TEXT,
                            ),
                            ft.Text(
                                f"Every app's lookups are filtered. {blocked} blocked so far."
                                if protected
                                else "Your rules are saved and sealed. Turn on the DNS filter below to "
                                "start blocking."
                                if app.native.available
                                else "Blocking runs on Android. Your rules are saved and sealed.",
                                size=12,
                                color=theme.MUTED,
                            ),
                        ],
                        spacing=6,
                        expand=True,
                    ),
                    ft.Icon(
                        ft.Icons.GPP_GOOD_ROUNDED,
                        size=72,
                        color=ft.Colors.with_opacity(0.9, theme.PULSE),
                    ),
                ]
            ),
            padding=18,
            border_radius=22,
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_LEFT,
                end=ft.Alignment.BOTTOM_RIGHT,
                colors=["#0E3A6B", "#0B2147", "#073B3A"],
            ),
            border=ft.Border.all(1, ft.Colors.with_opacity(0.35, theme.CYAN)),
        )
    )

    out.append(
        ft.Row(
            [
                theme.stat_tile(stats["blocked_sites"], "Blocked sites", ft.Icons.BLOCK, theme.DANGER),
                theme.stat_tile(stats["blocked_apps"], "Blocked apps", ft.Icons.APP_BLOCKING_OUTLINED, theme.CYAN),
            ],
            spacing=12,
        )
    )
    out.append(
        ft.Row(
            [
                theme.stat_tile(stats["allowed_sites"], "Whitelisted", ft.Icons.CHECK_CIRCLE_OUTLINE, theme.PULSE),
                theme.stat_tile(stats["schedules"], "Schedules", ft.Icons.SCHEDULE, theme.AMBER),
            ],
            spacing=12,
        )
    )

    out.append(theme.section_title("Protection", ft.Icons.SHIELD_OUTLINED))
    out.append(
        theme.card(
            ft.Row(
                [
                    ft.Icon(ft.Icons.DNS_OUTLINED, color=theme.CYAN),
                    ft.Column(
                        [
                            ft.Text("Cloudflare Family DNS", weight=ft.FontWeight.W_700, color=theme.TEXT),
                            ft.Text(
                                f"Adult content + malware filtering via {' / '.join(FAMILY_DNS_V4)}",
                                size=12,
                                color=theme.MUTED,
                            ),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                    theme.pill("On" if active else "Off", theme.PULSE if active else theme.DANGER),
                ]
            ),
            padding=14,
        )
    )
    warning = app.native.private_dns_warning()
    if warning:
        out.append(_notice(ft.Icons.GPP_BAD_OUTLINED, "Private DNS is bypassing the filter", warning, theme.DANGER))
    lockdown = app.native.lockdown_warning()
    if lockdown:
        out.append(
            _notice(
                ft.Icons.WIFI_OFF,
                "Turn off \"Block connections without VPN\"",
                lockdown,
                theme.DANGER,
                action=ft.TextButton("Open", on_click=lambda _: app.open_vpn_settings()),
            )
        )
    elif app.native.needs_always_on:
        out.append(
            _notice(
                ft.Icons.AUTORENEW,
                "Turn on Always-on VPN",
                "In Android's VPN settings, tap the gear next to GuardPulse and switch on "
                "'Always-on VPN'. Leave 'Block connections without VPN' OFF - it stops all "
                "internet with GuardPulse's DNS-only filter.",
                theme.AMBER,
                action=ft.TextButton("Open", on_click=lambda _: app.open_vpn_settings()),
            )
        )
    admin_off = app.native.admin_off_warning()
    if admin_off:
        out.append(
            _notice(
                ft.Icons.GPP_BAD_OUTLINED,
                "Uninstall protection is off",
                admin_off,
                theme.DANGER,
                action=ft.TextButton("Fix", on_click=lambda _: app.enable_uninstall()),
            )
        )
    overlay_off = app.native.overlay_off_warning()
    if overlay_off:
        out.append(
            _notice(
                ft.Icons.LAYERS_CLEAR_OUTLINED,
                "Security overlay is off",
                overlay_off,
                theme.DANGER,
                action=ft.TextButton("Fix", on_click=lambda _: app.enable_overlay()),
            )
        )
    switches = {
        "vpn": (app.enable_filter, app.disable_filter),
        "accessibility": (app.enable_overlay, app.disable_overlay),
        "device_admin": (app.enable_uninstall, app.disable_uninstall),
    }
    for comp in app.native.status():
        turn_on, turn_off = switches.get(comp.key, (None, None))
        if comp.active:
            status = ft.Column(
                [theme.pill("Active", theme.PULSE, ft.Icons.CHECK)]
                + ([ft.TextButton("Turn off", on_click=lambda _, f=turn_off: f())] if turn_off else []),
                horizontal_alignment=ft.CrossAxisAlignment.END,
                spacing=0,
            )
        elif comp.available and turn_on:
            status = ft.FilledButton(
                "Turn on", icon=ft.Icons.POWER_SETTINGS_NEW, on_click=lambda _, f=turn_on: f()
            )
        elif comp.key in switches:
            status = theme.pill("Android only", theme.MUTED, ft.Icons.PHONE_ANDROID)
        else:
            status = theme.pill(f"Phase {comp.phase}", theme.MUTED, ft.Icons.CONSTRUCTION)
        out.append(
            theme.card(
                ft.Row(
                    [
                        ft.Icon(
                            {
                                "vpn": ft.Icons.VPN_LOCK_OUTLINED,
                                "accessibility": ft.Icons.LAYERS_OUTLINED,
                                "device_admin": ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED,
                            }[comp.key],
                            color=theme.CYAN,
                        ),
                        ft.Column(
                            [
                                ft.Text(comp.title, weight=ft.FontWeight.W_700, color=theme.TEXT),
                                ft.Text(comp.detail, size=12, color=theme.MUTED),
                            ],
                            spacing=2,
                            expand=True,
                        ),
                        status,
                    ]
                ),
                padding=14,
            )
        )

    out.append(theme.section_title("Recent activity", ft.Icons.HISTORY))
    rows = g.history(5)
    out.append(
        theme.card(ft.Column([_activity_tile(r) for r in rows], spacing=0), padding=4)
        if rows
        else theme.empty_state(ft.Icons.HISTORY, "Nothing yet", "Changes you make show up here.")
    )
    return out


def _notice(icon: ft.IconData, title: str, text: str, color: str, action: ft.Control | None = None) -> ft.Control:
    return theme.card(
        ft.Row(
            [
                ft.Icon(icon, color=color, size=28),
                ft.Column(
                    [
                        ft.Text(title, weight=ft.FontWeight.W_700, color=theme.TEXT),
                        ft.Text(text, size=12, color=theme.MUTED),
                    ],
                    spacing=2,
                    expand=True,
                ),
                *([action] if action else []),
            ]
        ),
        border_color=color,
    )


def _start_partner_setup(app: App) -> None:
    from .onboarding import Onboarding

    Onboarding(app).partner_form()


# --- Sites -----------------------------------------------------------------


def sites(app: App) -> list[ft.Control]:
    g = app.guard
    kind = getattr(app, "sites_kind", "block")

    def switch_kind(e):
        app.sites_kind = e.control.selected[0]
        app.render()

    field = ft.TextField(
        hint_text="example.com, *.example.com or a full link",
        prefix_icon=ft.Icons.LINK,
        keyboard_type=ft.KeyboardType.URL,
        expand=True,
        autocorrect=False,
        enable_suggestions=False,
    )

    def add(_=None):
        value = field.value or ""
        if kind == "block":
            app.act(lambda: g.add_block(value), "Blocked")
        else:
            app.act(lambda: g.add_allow(value), "Whitelisted")

    field.on_submit = add
    rules = g.rules(kind)

    out: list[ft.Control] = [
        ft.SegmentedButton(
            selected=[kind],
            segments=[
                ft.Segment(value="block", label=ft.Text("Blacklist"), icon=ft.Icon(ft.Icons.BLOCK)),
                ft.Segment(value="allow", label=ft.Text("Whitelist"), icon=ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE)),
            ],
            on_change=switch_kind,
        ),
        ft.Text(
            "Every block is a wildcard: example.com also blocks www., m. and any other "
            "sub-domain (same as *.example.com). Adding a block never needs a PIN."
            if kind == "block"
            else "Whitelisted sites are always allowed, even if a broader block or Family DNS "
            "would stop them. Whitelisting needs your partner's PIN.",
            size=12,
            color=theme.MUTED,
        ),
        theme.card(
            ft.Row(
                [
                    field,
                    ft.FilledButton(
                        "Block" if kind == "block" else "Allow",
                        icon=ft.Icons.ADD if kind == "block" or g.unlocked else ft.Icons.LOCK_OUTLINE,
                        on_click=add,
                    ),
                ]
            ),
            padding=10,
        ),
        theme.section_title(f"{len(rules)} {'blocked' if kind == 'block' else 'whitelisted'}"),
    ]
    if not rules:
        out.append(
            theme.empty_state(
                ft.Icons.BLOCK if kind == "block" else ft.Icons.CHECK_CIRCLE_OUTLINE,
                "No sites yet",
                "Add one above." if kind == "block" else "Ask your partner before adding one.",
            )
        )
    else:
        out.append(
            theme.card(
                ft.Column(
                    [
                        ft.ListTile(
                            leading=ft.Icon(
                                ft.Icons.BLOCK if kind == "block" else ft.Icons.CHECK_CIRCLE_OUTLINE,
                                color=theme.DANGER if kind == "block" else theme.PULSE,
                            ),
                            title=ft.Text(r.value, color=theme.TEXT),
                            subtitle=ft.Text(f"Added {_when(r.created_at)}", size=12, color=theme.MUTED),
                            trailing=_remove_button(
                                app, "Remove", lambda _, rid=r.id: app.act(lambda: g.remove_rule(rid), "Removed")
                            ),
                            dense=True,
                        )
                        for r in rules
                    ],
                    spacing=0,
                ),
                padding=4,
            )
        )
    return out


# --- Apps ------------------------------------------------------------------


def _app_icon(app: App, pkg: str, label: str, size: int) -> ft.Control:
    """The app's real icon from this phone, or a letter badge (nothing bundled)."""
    icon = app.native.icons.get(pkg)
    if icon:
        return ft.Image(src=base64.b64decode(icon), width=size, height=size, border_radius=size * 0.22)
    return ft.Container(
        ft.Text((label or pkg)[:1].upper(), size=size * 0.45, weight=ft.FontWeight.W_800, color=theme.NAVY),
        width=size,
        height=size,
        border_radius=size * 0.28,
        bgcolor=theme.TEAL,
        alignment=ft.Alignment.CENTER,
    )


def _fetch_icons_then_render(app: App, packages: list[str]) -> None:
    """Ask Android for any icons we haven't got; re-render the Apps tab once if some arrive."""
    if not app.native.available:
        return

    async def run():
        if await app.native.load_icons(packages) and app.tab == 2:
            app.render()

    app.page.run_task(run)


def apps(app: App) -> list[ft.Control]:
    g = app.guard
    blocked = {a.package for a in g.blocked_apps()}
    _fetch_icons_then_render(app, [pkg for _, pkg in POPULAR_APPS] + sorted(blocked))
    package = ft.TextField(
        hint_text="Package name, e.g. org.telegram.messenger",
        prefix_icon=ft.Icons.ANDROID,
        expand=True,
        autocorrect=False,
        enable_suggestions=False,
    )

    def add(_=None):
        app.act(lambda: g.add_app(package.value or ""), "App blocked")

    package.on_submit = add
    settings = g.settings()

    def toggle_feed(e, key):
        app.act(lambda: g.set_setting(key, e.control.value))

    out: list[ft.Control] = [
        theme.section_title("Quick block", ft.Icons.BOLT),
        ft.Row(
            [
                ft.Chip(
                    label=ft.Text(label),
                    leading=_app_icon(app, pkg, label, 20)
                    if pkg in app.native.icons
                    else ft.Icon(ft.Icons.CHECK if pkg in blocked else ft.Icons.ADD, size=16),
                    selected=pkg in blocked,
                    selected_color=ft.Colors.with_opacity(0.25, theme.DANGER),
                    show_checkmark=False,
                    on_click=None if pkg in blocked else (lambda _, p=pkg, n=label: app.act(lambda: g.add_app(p, n), f"{n} blocked")),
                )
                for label, pkg in POPULAR_APPS
            ],
            wrap=True,
            spacing=8,
            run_spacing=8,
        ),
        ft.FilledButton(
            "Choose from installed apps",
            icon=ft.Icons.APPS,
            height=44,
            on_click=lambda _: _open_after_loading_apps(app, _installed_picker),
            visible=app.native.available,
        ),
        theme.card(ft.Row([package, ft.FilledButton("Block", icon=ft.Icons.ADD, on_click=add)]), padding=10),
        ft.Text(
            "Blocked apps are covered by the security overlay - make sure it's on (Home)."
            if app.native.available
            else "App blocking runs on Android with the security overlay.",
            size=12,
            color=theme.MUTED,
        ),
        theme.section_title("Block short-video feeds", ft.Icons.SLOW_MOTION_VIDEO),
        theme.card(
            ft.Column(
                [
                    ft.ListTile(
                        leading=ft.Icon(icon, color=theme.CYAN),
                        title=ft.Text(f"Block {label}", color=theme.TEXT),
                        # switch ON = blocked; spell it out so "off" isn't read as "turn the feed off"
                        subtitle=ft.Text(
                            "On: blocked · the rest of the app still works"
                            if settings[key]
                            else "Off: allowed · switch on to block",
                            size=12,
                            color=theme.PULSE if settings[key] else theme.AMBER,
                        ),
                        trailing=ft.Switch(
                            value=bool(settings[key]),
                            active_color=theme.PULSE,
                            on_change=lambda e, k=key: toggle_feed(e, k),
                        ),
                        dense=True,
                    )
                    for key, label, icon in FEEDS
                ],
                spacing=0,
            ),
            padding=4,
        ),
        theme.section_title(f"{len(blocked)} blocked apps", ft.Icons.APP_BLOCKING_OUTLINED),
    ]
    rows = g.blocked_apps()
    if not rows:
        out.append(theme.empty_state(ft.Icons.APPS, "No apps blocked", "Tap a quick-block chip above."))
    else:
        out.append(
            theme.card(
                ft.Column(
                    [
                        ft.ListTile(
                            leading=_app_icon(app, a.package, a.label, 32),
                            title=ft.Text(a.label, color=theme.TEXT),
                            subtitle=ft.Text(a.package, size=12, color=theme.MUTED),
                            trailing=_remove_button(
                                app, "Unblock", lambda _, aid=a.id: app.act(lambda: g.remove_app(aid), "Unblocked")
                            ),
                            dense=True,
                        )
                        for a in rows
                    ],
                    spacing=0,
                ),
                padding=4,
            )
        )
    return out


# --- Schedule --------------------------------------------------------------


def schedule(app: App) -> list[ft.Control]:
    g = app.guard
    rows = g.schedules()
    out: list[ft.Control] = [
        ft.Text(
            "Lock chosen apps during set hours - bedtime, study, work. Adding or resuming a "
            "schedule is free; pausing or deleting one needs your partner.",
            size=12,
            color=theme.MUTED,
        ),
        ft.FilledButton(
            "New schedule",
            icon=ft.Icons.ADD_ALARM,
            on_click=lambda _: _open_after_loading_apps(app, _schedule_dialog),
            height=44,
        ),
    ]
    if not rows:
        out.append(theme.empty_state(ft.Icons.SCHEDULE, "No schedules", "Create one to lock apps on a timer."))
        return out
    now = dt.datetime.now()
    labels = {pkg: name for name, pkg in POPULAR_APPS} | {a.package: a.label for a in g.blocked_apps()}
    for s in rows:
        days = ", ".join(DAYS[i] for i in range(7) if s.days >> i & 1)
        if s.days == 0b1111111:
            days = "Every day"
        elif s.days == 0b0011111:
            days = "Weekdays"
        elif s.days == 0b1100000:
            days = "Weekends"
        live = s.active_at(now)
        out.append(
            theme.card(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.SCHEDULE, color=theme.AMBER if live else theme.CYAN),
                                ft.Text(s.name, weight=ft.FontWeight.W_700, color=theme.TEXT, expand=True),
                                theme.pill("Locking now", theme.AMBER, ft.Icons.LOCK) if live else ft.Container(),
                                ft.Switch(
                                    value=s.enabled,
                                    active_color=theme.PULSE,
                                    on_change=lambda e, sid=s.id: app.act(
                                        lambda: g.set_schedule_enabled(sid, e.control.value)
                                    ),
                                ),
                            ]
                        ),
                        ft.Text(
                            f"{_hhmm(s.start_min)} - {_hhmm(s.end_min)}  ·  {days}",
                            color=theme.MUTED,
                            size=13,
                        ),
                        ft.Row(
                            [
                                ft.Text(
                                    ", ".join(labels.get(p, p) for p in s.packages),
                                    size=12,
                                    color=theme.MUTED,
                                    expand=True,
                                ),
                                _remove_button(
                                    app,
                                    "Delete",
                                    lambda _, sid=s.id: app.act(lambda: g.remove_schedule(sid), "Schedule deleted"),
                                ),
                            ]
                        ),
                    ],
                    spacing=4,
                ),
                padding=14,
            )
        )
    return out


def _schedule_dialog(app: App) -> None:
    g = app.guard
    state = {"days": 0b0011111, "start": 22 * 60, "end": 6 * 60, "apps": set()}
    name = ft.TextField(label="Name", value="Bedtime", prefix_icon=ft.Icons.LABEL_OUTLINE)
    start_btn = ft.OutlinedButton(_hhmm(state["start"]), icon=ft.Icons.NIGHTLIGHT_OUTLINED)
    end_btn = ft.OutlinedButton(_hhmm(state["end"]), icon=ft.Icons.WB_SUNNY_OUTLINED)
    day_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
    custom = ft.TextField(hint_text="Other package name", dense=True)
    error = ft.Text("", color=theme.DANGER, size=12, visible=False)

    def draw_days():
        day_row.controls = [
            ft.Chip(
                label=ft.Text(d),
                selected=bool(state["days"] >> i & 1),
                show_checkmark=False,
                selected_color=ft.Colors.with_opacity(0.3, theme.CYAN),
                on_select=lambda e, i=i: toggle_day(i),
            )
            for i, d in enumerate(DAYS)
        ]

    def toggle_day(i):
        state["days"] ^= 1 << i
        draw_days()
        day_row.update()

    def pick_time(which, button):
        current = state[which]

        def changed(e):
            value: dt.time = e.control.value
            state[which] = value.hour * 60 + value.minute
            button.content = _hhmm(state[which])
            button.update()

        app.page.show_dialog(
            ft.TimePicker(
                value=dt.time(current // 60, current % 60),
                on_change=changed,
                help_text="Lock starts" if which == "start" else "Lock ends",
            )
        )

    start_btn.on_click = lambda _: pick_time("start", start_btn)
    end_btn.on_click = lambda _: pick_time("end", end_btn)

    choices = (
        {pkg: label for label, pkg in POPULAR_APPS}
        | {a["package"]: a["label"] for a in app.native.installed_apps}
        | {a.package: a.label for a in g.blocked_apps()}
    )
    search, checklist = _app_checklist(choices, state["apps"], lambda p, l: _app_icon(app, p, l, 24))

    def save(_):
        apps_ = set(state["apps"])
        if custom.value and custom.value.strip():
            apps_.add(custom.value.strip())
        try:
            g.add_schedule(name.value, state["days"], state["start"], state["end"], sorted(apps_))
        except (GuardError, ValueError) as exc:
            error.value, error.visible = str(exc), True
            error.update()
            return
        app.close_dialog()
        app.toast("Schedule added")
        app.render()

    draw_days()
    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("New schedule"),
            scrollable=True,
            content=ft.Column(
                [
                    name,
                    ft.Text("Days", size=12, color=theme.MUTED),
                    day_row,
                    ft.Row(
                        [
                            ft.Column([ft.Text("From", size=12, color=theme.MUTED), start_btn], spacing=4),
                            ft.Column([ft.Text("Until", size=12, color=theme.MUTED), end_btn], spacing=4),
                        ],
                        spacing=24,
                    ),
                    ft.Text("Apps to lock", size=12, color=theme.MUTED),
                    search,
                    checklist,
                    custom,
                    error,
                ],
                tight=True,
                spacing=8,
                width=360,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: app.close_dialog()),
                ft.FilledButton("Save", icon=ft.Icons.CHECK, on_click=save),
            ],
        )
    )


def _toggle(bucket: set, item: str, on: bool) -> None:
    (bucket.add if on else bucket.discard)(item)


def _app_checklist(
    choices: dict[str, str], selected: set[str], icon=None
) -> tuple[ft.TextField, ft.Column]:
    """Search box + checkbox list over ``{package: label}``; ticks land in ``selected``.

    ``icon(package, label)`` returns a leading control (the app's icon)."""
    rows = [
        ft.Row(
            ([icon(pkg, label)] if icon else [])
            + [
                ft.Checkbox(
                    label=label,
                    value=pkg in selected,
                    on_change=lambda e, p=pkg: _toggle(selected, p, e.control.value),
                    expand=True,
                )
            ],
            spacing=8,
            data=f"{label} {pkg}".lower(),
        )
        for pkg, label in sorted(choices.items(), key=lambda kv: kv[1].lower())
    ]
    column = ft.Column(rows, spacing=0, height=min(56 * len(rows), 320), scroll=ft.ScrollMode.AUTO)

    def filter_rows(e):
        needle = (e.control.value or "").strip().lower()
        for row in rows:
            row.visible = needle in row.data
        column.update()

    search = ft.TextField(
        hint_text=f"Search {len(rows)} apps",
        prefix_icon=ft.Icons.SEARCH,
        dense=True,
        on_change=filter_rows,
    )
    return search, column


def _open_after_loading_apps(app: App, opener) -> None:
    """Fetch the installed-app list (Android) before showing a picker."""

    async def run():
        await app.native.load_installed_apps()
        opener(app)

    app.page.run_task(run)


def _installed_picker(app: App) -> None:
    g = app.guard
    already = {a.package for a in g.blocked_apps()}
    choices = {a["package"]: a["label"] for a in app.native.installed_apps if a["package"] not in already}
    picked: set[str] = set()
    search, checklist = _app_checklist(choices, picked, lambda p, l: _app_icon(app, p, l, 24))

    def save(_):
        for pkg in sorted(picked):
            g.add_app(pkg, choices[pkg])
        app.close_dialog()
        if picked:
            app.toast(f"{len(picked)} app{'s' if len(picked) != 1 else ''} blocked")
        app.render()

    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("Block installed apps"),
            content=ft.Column(
                [
                    ft.Text("Blocking is free - unblocking needs your partner.", size=12, color=theme.MUTED),
                    search,
                    checklist,
                ],
                tight=True,
                spacing=8,
                width=360,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: app.close_dialog()),
                ft.FilledButton("Block selected", icon=ft.Icons.APP_BLOCKING_OUTLINED, on_click=save),
            ],
        )
    )


# --- Settings --------------------------------------------------------------


def settings(app: App) -> list[ft.Control]:
    g = app.guard
    s = g.settings()
    partner = g.partner()

    def flag(key: str, title: str, subtitle: str, icon: ft.IconData) -> ft.Control:
        return ft.ListTile(
            leading=ft.Icon(icon, color=theme.CYAN),
            title=ft.Text(title, color=theme.TEXT),
            subtitle=ft.Text(subtitle, size=12, color=theme.MUTED),
            trailing=ft.Switch(
                value=bool(s[key]),
                active_color=theme.PULSE,
                on_change=lambda e: app.act(lambda: g.set_setting(key, e.control.value)),
            ),
        )

    unlock_slider = ft.Slider(
        min=UNLOCK_MINUTES_RANGE[0],
        max=UNLOCK_MINUTES_RANGE[1],
        divisions=UNLOCK_MINUTES_RANGE[1] - UNLOCK_MINUTES_RANGE[0],
        value=int(s["unlock_minutes"]),
        label="{value} min",
        active_color=theme.CYAN,
        on_change_end=lambda e: app.act(
            lambda: g.set_setting("unlock_minutes", round(e.control.value)), "Unlock time saved"
        ),
    )

    out: list[ft.Control] = [
        theme.section_title("Protection", ft.Icons.SHIELD_OUTLINED),
        theme.card(
            ft.Column(
                [
                    flag("family_dns", "Cloudflare Family DNS", "Filter adult content + malware for every app", ft.Icons.DNS_OUTLINED),
                    flag("browser_overlay", "Security overlay", "Cover blocked sites in any browser", ft.Icons.LAYERS_OUTLINED),
                    flag(
                        "settings_guard",
                        "Guard Settings pages",
                        "Partner PIN to uninstall, force-stop or switch GuardPulse off in Android Settings",
                        ft.Icons.POLICY_OUTLINED,
                    ),
                ],
                spacing=0,
            ),
            padding=4,
        ),
        theme.section_title("Partner", ft.Icons.HANDSHAKE_OUTLINED),
    ]

    if partner is None:
        out.append(
            theme.card(
                ft.Row(
                    [
                        ft.Text("No partner set up yet.", color=theme.MUTED, expand=True),
                        ft.FilledButton("Set up", on_click=lambda _: _start_partner_setup(app)),
                    ]
                )
            )
        )
    else:
        out.append(
            theme.card(
                ft.Column(
                    [
                        ft.ListTile(
                            leading=ft.CircleAvatar(
                                content=ft.Text(partner.name[:1].upper(), weight=ft.FontWeight.W_800),
                                bgcolor=theme.TEAL,
                                color=theme.NAVY,
                            ),
                            title=ft.Text(partner.name, color=theme.TEXT, weight=ft.FontWeight.W_700),
                            subtitle=ft.Text(partner.contact or "No contact saved", size=12, color=theme.MUTED),
                            trailing=ft.IconButton(
                                icon=ft.Icons.EDIT_OUTLINED,
                                tooltip="Edit partner",
                                on_click=lambda _: app.act(lambda: _partner_dialog(app)),
                            ),
                        ),
                        ft.Row(
                            [
                                ft.OutlinedButton(
                                    "Change PIN", icon=ft.Icons.KEY, on_click=lambda _: app.act(lambda: _pin_dialog(app))
                                ),
                                ft.OutlinedButton(
                                    "Authenticator QR",
                                    icon=ft.Icons.QR_CODE_2,
                                    on_click=lambda _: app.act(lambda: _qr_dialog(app)),
                                ),
                            ],
                            wrap=True,
                        ),
                        ft.Divider(color=theme.OUTLINE),
                        ft.Text("Unlock lasts", size=12, color=theme.MUTED),
                        unlock_slider,
                        ft.Text(
                            "Shortening is free; lengthening needs the partner.", size=11, color=theme.MUTED
                        ),
                    ],
                    spacing=8,
                ),
                padding=12,
            )
        )

    out += [theme.section_title("Partner alerts", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED), _alerts_card(app)]
    out += [theme.section_title("Activity log", ft.Icons.HISTORY)]
    rows = g.history(30)
    out.append(
        theme.card(ft.Column([_activity_tile(r) for r in rows], spacing=0), padding=4)
        if rows
        else theme.empty_state(ft.Icons.HISTORY, "Nothing yet", "Every change is recorded here.")
    )
    out += [theme.section_title("About", ft.Icons.INFO_OUTLINE), _about_card(app)]
    return out


def _about_card(app: App) -> ft.Control:
    official = app.native.official_build
    if official is True:
        build = theme.pill("Official build", theme.PULSE, ft.Icons.VERIFIED_OUTLINED)
    elif official is False:
        build = theme.pill("Test build - updates via adb", theme.AMBER, ft.Icons.CONSTRUCTION)
    else:
        build = None
    newer = app.update
    def fact(icon: ft.IconData, text: str) -> ft.Control:
        return ft.Row(
            [ft.Icon(icon, size=16, color=theme.CYAN), ft.Text(text, size=12, color=theme.MUTED, expand=True)],
            spacing=8,
        )

    return theme.card(
        ft.Column(
            [
                ft.Image(src="icon.png", width=112, height=112),
                ft.Text("GuardPulse", size=22, weight=ft.FontWeight.W_800, color=theme.TEXT),
                ft.Row(
                    [theme.pill(f"Version {__version__}", theme.CYAN, ft.Icons.NEW_RELEASES_OUTLINED)]
                    + ([build] if build else []),
                    alignment=ft.MainAxisAlignment.CENTER,
                    wrap=True,
                    spacing=6,
                ),
                ft.FilledButton(
                    f"Update to {newer.version}" if newer else "Check for updates",
                    icon=ft.Icons.SYSTEM_UPDATE if newer else ft.Icons.REFRESH,
                    on_click=(lambda _: app.show_update(newer)) if newer
                    else (lambda _: app.page.run_task(app.check_for_updates, True)),
                ),
                ft.Text(
                    "A completely free content blocker with accountability controls.",
                    size=13,
                    color=theme.MUTED,
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Divider(color=theme.OUTLINE),
                fact(ft.Icons.VOLUNTEER_ACTIVISM_OUTLINED, "Free forever - no ads, no subscriptions, no accounts"),
                fact(ft.Icons.DNS_OUTLINED, f"Filtering by Cloudflare 1.1.1.1 for Families ({' / '.join(FAMILY_DNS_V4)})"),
                fact(ft.Icons.LOCK_OUTLINE, "Rules sealed with HMAC-SHA256, PIN stored as a scrypt hash"),
                fact(ft.Icons.PHONE_ANDROID, "Everything stays on this phone"),
                ft.TextButton(
                    "Source on GitHub",
                    icon=ft.Icons.CODE,
                    url="https://github.com/3th4n-J/GuardPulse",
                ),
                ft.Text(
                    spans=[
                        ft.TextSpan("Built by Ethan with "),
                        ft.TextSpan("❤️", style=ft.TextStyle(color=theme.DANGER)),
                    ],
                    size=12,
                    color=theme.MUTED,
                    text_align=ft.TextAlign.CENTER,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=8,
        ),
        padding=20,
    )


def _alerts_card(app: App) -> ft.Control:
    g = app.guard
    topic = g.setting("ntfy_topic")
    pending = len(g.pending_alerts())
    if not topic:
        body: list[ft.Control] = [
            ft.Text(
                "Once your accountability partner is set up, they get instant alerts on their phone "
                "through the free ntfy app.",
                size=12,
                color=theme.MUTED,
            )
        ]
    else:
        status = (
            f"{pending} alert{'s' if pending != 1 else ''} waiting to send (retries automatically)"
            if pending
            else "All alerts delivered"
        )
        body = [
            ft.Text(
                "Unlocks, wrong PINs, whitelisting, deletions and any protection being switched off - "
                "even outside the app - are pushed to your partner's ntfy app.",
                size=12,
                color=theme.MUTED,
            ),
            ft.Row(
                [
                    ft.Icon(
                        ft.Icons.OUTBOX_OUTLINED if pending else ft.Icons.MARK_EMAIL_READ_OUTLINED,
                        size=16,
                        color=theme.AMBER if pending else theme.PULSE,
                    ),
                    ft.Text(status, size=12, color=theme.MUTED, expand=True),
                ],
                spacing=6,
            ),
            ft.Row(
                [
                    ft.OutlinedButton(
                        "Partner: subscribe",
                        icon=ft.Icons.QR_CODE_2,
                        on_click=lambda _: app.act(lambda: _ntfy_dialog(app)),
                    ),
                    ft.OutlinedButton("Send test alert", icon=ft.Icons.SEND, on_click=lambda _: app.send_test_alert()),
                ],
                wrap=True,
            ),
        ]
    return theme.card(ft.Column(body, spacing=10), padding=14)


def ntfy_subscribe_controls(url: str) -> list[ft.Control]:
    """QR + steps for the partner to subscribe (shared by onboarding and Settings)."""
    return [
        ft.Text(
            "Partner: install the free ntfy app (Play Store / App Store), then scan this code "
            "with your camera and tap Subscribe.",
            size=12,
            color=theme.MUTED,
            text_align=ft.TextAlign.CENTER,
        ),
        ft.Container(
            ft.Image(src=qr_png(url), width=200, height=200),
            bgcolor="#FFFFFF",
            padding=10,
            border_radius=16,
        ),
        ft.Text(url, size=11, color=theme.MUTED, selectable=True, text_align=ft.TextAlign.CENTER),
    ]


def _ntfy_dialog(app: App) -> None:
    url = app.guard.alert_subscribe_url()  # needs the partner

    def new_topic(_):
        app.guard.new_alert_topic_now()
        app.close_dialog()
        app.toast("New alert link - your partner must subscribe again")
        _ntfy_dialog(app)

    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("Partner alerts"),
            content=ft.Column(
                ntfy_subscribe_controls(url),
                tight=True,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                width=320,
            ),
            actions=[
                ft.TextButton("New link", on_click=new_topic),
                ft.FilledButton("Done", on_click=lambda _: app.close_dialog()),
            ],
        )
    )


def _require_unlocked(app: App, action: str) -> None:
    if not app.guard.unlocked:
        raise Locked(action)


def _pin_dialog(app: App) -> None:
    _require_unlocked(app, "change the PIN")
    new = ft.TextField(label="New PIN", password=True, keyboard_type=ft.KeyboardType.NUMBER, max_length=12)
    again = ft.TextField(label="Confirm", password=True, keyboard_type=ft.KeyboardType.NUMBER, max_length=12)

    def save(_):
        if new.value != again.value:
            again.error = "PINs don't match."
            again.update()
            return
        try:
            app.guard.change_pin(new.value or "")
        except ValueError as exc:
            new.error = str(exc)
            new.update()
            return
        app.close_dialog()
        app.toast("PIN changed")
        app.render()

    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("Change partner PIN"),
            content=ft.Column([new, again], tight=True, width=320),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: app.close_dialog()),
                ft.FilledButton("Save", on_click=save),
            ],
        )
    )


def _partner_dialog(app: App) -> None:
    _require_unlocked(app, "change the partner details")
    partner = app.guard.partner()
    name = ft.TextField(label="Name", value=partner.name)
    contact = ft.TextField(label="Email or phone", value=partner.contact)

    def save(_):
        try:
            app.guard.update_partner(name.value, contact.value)
        except ValueError as exc:
            name.error = str(exc)
            name.update()
            return
        app.close_dialog()
        app.render()

    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("Partner details"),
            content=ft.Column([name, contact], tight=True, width=320),
            actions=[
                ft.TextButton("Cancel", on_click=lambda _: app.close_dialog()),
                ft.FilledButton("Save", on_click=save),
            ],
        )
    )


def _qr_dialog(app: App) -> None:
    uri = app.guard.totp_uri()

    def reset(_):
        app.guard.reset_totp()
        app.close_dialog()
        app.toast("New authenticator key - partner must scan again")
        _qr_dialog(app)

    app.open_dialog(
        ft.AlertDialog(
            title=ft.Text("Partner authenticator"),
            content=ft.Column(
                [
                    ft.Text("Only your partner should scan this.", size=12, color=theme.MUTED),
                    ft.Container(
                        ft.Image(src=qr_png(uri), width=220, height=220),
                        bgcolor="#FFFFFF",
                        padding=10,
                        border_radius=16,
                    ),
                ],
                tight=True,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                width=300,
            ),
            actions=[
                ft.TextButton("Reset key", on_click=reset),
                ft.FilledButton("Close", on_click=lambda _: app.close_dialog()),
            ],
        )
    )
