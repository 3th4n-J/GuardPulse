"""Colours and small building blocks matching the GuardPulse logo."""

from __future__ import annotations

import flet as ft

NAVY = "#06122B"
SURFACE = "#0C1E42"
SURFACE_HI = "#13295A"
OUTLINE = "#1F3B73"
CYAN = "#22D3EE"
TEAL = "#14B8A6"
PULSE = "#34D399"
AMBER = "#FBBF24"
DANGER = "#F87171"
TEXT = "#E6F1FF"
MUTED = "#8FA3C7"
# the logo's gradient (assets/icon.png)
BRAND_BLUE = "#1D50C5"
BRAND_TEAL = "#23C6C0"


def apply(page: ft.Page) -> None:
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = NAVY
    page.dark_theme = ft.Theme(
        color_scheme_seed=CYAN,
        color_scheme=ft.ColorScheme(
            primary=CYAN,
            secondary=PULSE,
            surface=SURFACE,
            error=DANGER,
        ),
    )
    page.theme = page.dark_theme
    page.padding = 0


def brand_mark(size: int = 40, glow: bool = False) -> ft.Container:
    """Shield + heartbeat badge used in place of the logo image inside the app."""
    return ft.Container(
        ft.Stack(
            [
                ft.Icon(ft.Icons.SHIELD_OUTLINED, size=size * 0.74, color=ft.Colors.WHITE),
                ft.Icon(ft.Icons.SHOW_CHART_ROUNDED, size=size * 0.34, color=ft.Colors.WHITE),
            ],
            alignment=ft.Alignment.CENTER,
        ),
        width=size,
        height=size,
        alignment=ft.Alignment.CENTER,
        border_radius=size * 0.28,
        gradient=ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT,
            end=ft.Alignment.BOTTOM_RIGHT,
            colors=[BRAND_BLUE, BRAND_TEAL],
        ),
        shadow=ft.BoxShadow(blur_radius=size * 0.6, color=ft.Colors.with_opacity(0.45, BRAND_TEAL))
        if glow
        else None,
    )


def card(content: ft.Control, padding: int = 16, border_color: str = OUTLINE, **kwargs) -> ft.Container:
    return ft.Container(
        content=content,
        padding=padding,
        bgcolor=SURFACE,
        border=ft.Border.all(1, border_color),
        border_radius=18,
        **kwargs,
    )


def section_title(text: str, icon: ft.IconData | None = None) -> ft.Control:
    label = ft.Text(text.upper(), size=12, weight=ft.FontWeight.W_700, color=MUTED)
    if icon is None:
        return ft.Container(label, padding=ft.Padding.only(left=4, top=8))
    return ft.Container(
        ft.Row([ft.Icon(icon, size=16, color=MUTED), label], spacing=6),
        padding=ft.Padding.only(left=4, top=8),
    )


def pill(text: str, color: str, icon: ft.IconData | None = None) -> ft.Container:
    parts: list[ft.Control] = []
    if icon is not None:
        parts.append(ft.Icon(icon, size=14, color=color))
    parts.append(ft.Text(text, size=12, weight=ft.FontWeight.W_600, color=color))
    return ft.Container(
        ft.Row(parts, spacing=4, tight=True),
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
        border_radius=999,
        bgcolor=ft.Colors.with_opacity(0.14, color),
        border=ft.Border.all(1, ft.Colors.with_opacity(0.4, color)),
    )


def stat_tile(value: int, label: str, icon: ft.IconData, color: str) -> ft.Container:
    return card(
        ft.Column(
            [
                ft.Icon(icon, color=color, size=22),
                ft.Text(str(value), size=26, weight=ft.FontWeight.W_800, color=TEXT),
                ft.Text(label, size=12, color=MUTED),
            ],
            spacing=2,
        ),
        padding=14,
        expand=True,
    )


def empty_state(icon: ft.IconData, title: str, hint: str) -> ft.Control:
    return ft.Container(
        ft.Column(
            [
                ft.Icon(icon, size=40, color=OUTLINE),
                ft.Text(title, weight=ft.FontWeight.W_600, color=TEXT),
                ft.Text(hint, size=12, color=MUTED, text_align=ft.TextAlign.CENTER),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=6,
        ),
        padding=32,
        alignment=ft.Alignment.CENTER,
    )
