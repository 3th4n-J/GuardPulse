"""The five tab screens. Each builder returns a list of controls for ``App.render``."""

from __future__ import annotations

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

    # hero
    active = g.setting("family_dns")
    out.append(
        ft.Container(
            ft.Row(
                [
                    ft.Column(
                        [
                            theme.pill("Rules ready", theme.PULSE, ft.Icons.FAVORITE),
                            ft.Text("Your shield", size=24, weight=ft.FontWeight.W_800, color=theme.TEXT),
                            ft.Text(
                                "Blocking switches on once the Android protection services are "
                                "installed (coming next). Your rules are saved and sealed.",
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
    for comp in app.native.status():
        status = (
            theme.pill("Active", theme.PULSE, ft.Icons.CHECK)
            if comp.active
            else theme.pill(f"Phase {comp.phase}", theme.MUTED, ft.Icons.CONSTRUCTION)
        )
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
        hint_text="example.com or a full link",
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
            "Blocks cover every sub-domain (blocking example.com also blocks m.example.com). "
            "Adding a block never needs a PIN."
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


def apps(app: App) -> list[ft.Control]:
    g = app.guard
    blocked = {a.package for a in g.blocked_apps()}
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
                    leading=ft.Icon(ft.Icons.CHECK if pkg in blocked else ft.Icons.ADD, size=16),
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
        theme.card(ft.Row([package, ft.FilledButton("Block", icon=ft.Icons.ADD, on_click=add)]), padding=10),
        ft.Text(
            "An installed-app picker arrives with the Android protection services.",
            size=12,
            color=theme.MUTED,
        ),
        theme.section_title("Short-video feeds", ft.Icons.SLOW_MOTION_VIDEO),
        theme.card(
            ft.Column(
                [
                    ft.ListTile(
                        leading=ft.Icon(icon, color=theme.CYAN),
                        title=ft.Text(label, color=theme.TEXT),
                        subtitle=ft.Text("Rest of the app keeps working", size=12, color=theme.MUTED),
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
                            leading=ft.Icon(ft.Icons.APP_BLOCKING_OUTLINED, color=theme.DANGER),
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
            "New schedule", icon=ft.Icons.ADD_ALARM, on_click=lambda _: _schedule_dialog(app), height=44
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
    custom = ft.TextField(hint_text="Other package name", dense=True, expand=True)
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

    choices = {pkg: label for label, pkg in POPULAR_APPS} | {a.package: a.label for a in g.blocked_apps()}
    boxes = [
        ft.Checkbox(label=label, value=False, on_change=lambda e, p=pkg: _toggle(state["apps"], p, e.control.value))
        for pkg, label in sorted(choices.items(), key=lambda kv: kv[1].lower())
    ]

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
                    *boxes,
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
    webhook = ft.TextField(
        label="Alert webhook (n8n)",
        value=s["alert_webhook_url"],
        hint_text="https://n8n.example.com/webhook/guardpulse",
        prefix_icon=ft.Icons.WEBHOOK,
        keyboard_type=ft.KeyboardType.URL,
        expand=True,
    )

    out: list[ft.Control] = [
        theme.section_title("Protection", ft.Icons.SHIELD_OUTLINED),
        theme.card(
            ft.Column(
                [
                    flag("family_dns", "Cloudflare Family DNS", "Filter adult content + malware for every app", ft.Icons.DNS_OUTLINED),
                    flag("browser_overlay", "Security overlay", "Cover blocked sites in any browser", ft.Icons.LAYERS_OUTLINED),
                    flag(
                        "uninstall_protection",
                        "Uninstall protection",
                        "Partner PIN needed to remove GuardPulse",
                        ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED,
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

    pending = len(g.pending_alerts())
    out += [
        theme.section_title("Tamper alerts", ft.Icons.NOTIFICATIONS_ACTIVE_OUTLINED),
        theme.card(
            ft.Column(
                [
                    ft.Text(
                        "Unlocks, wrong PINs, whitelisting and protection being switched off are "
                        "sent to your partner through this webhook.",
                        size=12,
                        color=theme.MUTED,
                    ),
                    ft.Row(
                        [
                            webhook,
                            ft.IconButton(
                                icon=ft.Icons.SAVE_OUTLINED,
                                tooltip="Save (partner PIN)",
                                on_click=lambda _: app.act(
                                    lambda: g.set_setting("alert_webhook_url", webhook.value), "Webhook saved"
                                ),
                            ),
                        ]
                    ),
                    ft.Row(
                        [
                            ft.Icon(ft.Icons.OUTBOX_OUTLINED, size=16, color=theme.MUTED),
                            ft.Text(
                                f"{pending} alert{'s' if pending != 1 else ''} queued - sending arrives in Phase 5",
                                size=12,
                                color=theme.MUTED,
                            ),
                        ],
                        spacing=6,
                    ),
                ],
                spacing=10,
            ),
            padding=14,
        ),
        theme.section_title("Activity log", ft.Icons.HISTORY),
    ]
    rows = g.history(30)
    out.append(
        theme.card(ft.Column([_activity_tile(r) for r in rows], spacing=0), padding=4)
        if rows
        else theme.empty_state(ft.Icons.HISTORY, "Nothing yet", "Every change is recorded here.")
    )
    out.append(
        ft.Container(
            ft.Text(
                f"GuardPulse {__version__}  ·  free forever  ·  rules sealed with HMAC-SHA256",
                size=11,
                color=theme.MUTED,
                text_align=ft.TextAlign.CENTER,
            ),
            alignment=ft.Alignment.CENTER,
            padding=16,
        )
    )
    return out


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
