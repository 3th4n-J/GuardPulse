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
FIELD = "#0A1A3A"  # text-box fill: a touch darker than cards so boxes read as inputs
EDGE = "#2A4A86"  # visible-but-quiet outline for inputs and secondary buttons
# the logo's gradient (assets/icon.png)
BRAND_BLUE = "#1D50C5"
BRAND_TEAL = "#23C6C0"

RADIUS = 14  # corners for inputs and buttons


def _states(selected: str, default: str) -> dict:
    return {ft.ControlState.SELECTED: selected, ft.ControlState.DEFAULT: default}


def apply(page: ft.Page) -> None:
    """One theme for every control, so no Material default colours show through."""
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = NAVY
    rounded = ft.RoundedRectangleBorder(radius=RADIUS)
    page.dark_theme = ft.Theme(
        use_material3=True,
        color_scheme=ft.ColorScheme(
            primary=CYAN,
            on_primary=NAVY,
            primary_container=ft.Colors.with_opacity(0.22, CYAN),
            on_primary_container=TEXT,
            secondary=PULSE,
            on_secondary=NAVY,
            secondary_container=ft.Colors.with_opacity(0.22, CYAN),
            on_secondary_container=CYAN,
            tertiary=TEAL,
            on_tertiary=NAVY,
            error=DANGER,
            on_error=NAVY,
            surface=SURFACE,
            on_surface=TEXT,
            on_surface_variant=MUTED,
            surface_container_lowest=NAVY,
            surface_container_low=SURFACE,
            surface_container=SURFACE,
            surface_container_high=SURFACE_HI,
            surface_container_highest=SURFACE_HI,
            outline=EDGE,
            outline_variant=OUTLINE,
            inverse_surface=TEXT,
            on_inverse_surface=NAVY,
            surface_tint=ft.Colors.TRANSPARENT,  # no pink/purple M3 tint on raised surfaces
        ),
        scaffold_bgcolor=NAVY,
        canvas_color=SURFACE,
        divider_color=OUTLINE,
        hint_color=MUTED,
        filled_button_theme=ft.FilledButtonTheme(
            style=ft.ButtonStyle(bgcolor=CYAN, color=NAVY, shape=rounded, icon_color=NAVY)
        ),
        outlined_button_theme=ft.OutlinedButtonTheme(
            style=ft.ButtonStyle(
                color=CYAN,
                icon_color=CYAN,
                side=ft.BorderSide(1, EDGE),
                shape=rounded,
            )
        ),
        text_button_theme=ft.TextButtonTheme(style=ft.ButtonStyle(color=CYAN, icon_color=CYAN, shape=rounded)),
        segmented_button_theme=ft.SegmentedButtonTheme(
            style=ft.ButtonStyle(
                bgcolor=_states(ft.Colors.with_opacity(0.22, CYAN), FIELD),
                color=_states(CYAN, MUTED),
                icon_color=_states(CYAN, MUTED),
                side=ft.BorderSide(1, EDGE),
                shape=rounded,
            )
        ),
        chip_theme=ft.ChipTheme(
            bgcolor=FIELD,
            selected_color=ft.Colors.with_opacity(0.22, CYAN),
            border_side=ft.BorderSide(1, EDGE),
            label_text_style=ft.TextStyle(color=TEXT),
            shape=ft.RoundedRectangleBorder(radius=10),
            check_color=CYAN,
        ),
        checkbox_theme=ft.CheckboxTheme(
            fill_color=_states(CYAN, ft.Colors.TRANSPARENT),
            check_color=NAVY,
            border_side=ft.BorderSide(1.5, MUTED),
            shape=ft.RoundedRectangleBorder(radius=4),
        ),
        # no switch_theme: a themed thumb blended into the track ("solid pill").
        # Switches keep Material's own thumb and set active_color=PULSE each.
        slider_theme=ft.SliderTheme(
            active_track_color=CYAN,
            inactive_track_color=OUTLINE,
            thumb_color=CYAN,
            value_indicator_color=SURFACE_HI,
        ),
        dialog_theme=ft.DialogTheme(
            bgcolor=SURFACE,
            shape=ft.RoundedRectangleBorder(radius=22),
            title_text_style=ft.TextStyle(color=TEXT, size=20, weight=ft.FontWeight.W_700),
            content_text_style=ft.TextStyle(color=MUTED),
            barrier_color=ft.Colors.with_opacity(0.7, NAVY),
        ),
        snackbar_theme=ft.SnackBarTheme(
            bgcolor=SURFACE_HI,
            content_text_style=ft.TextStyle(color=TEXT),
            shape=ft.RoundedRectangleBorder(radius=RADIUS),
        ),
        time_picker_theme=ft.TimePickerTheme(
            bgcolor=SURFACE,
            dial_bgcolor=FIELD,
            dial_hand_color=CYAN,
            hour_minute_color=FIELD,
            hour_minute_text_color=TEXT,
            day_period_color=ft.Colors.with_opacity(0.22, CYAN),
            entry_mode_icon_color=CYAN,
            shape=ft.RoundedRectangleBorder(radius=22),
        ),
        list_tile_theme=ft.ListTileTheme(icon_color=CYAN, text_color=TEXT),
        divider_theme=ft.DividerTheme(color=OUTLINE),
        progress_indicator_theme=ft.ProgressIndicatorTheme(color=CYAN),
        navigation_bar_theme=ft.NavigationBarTheme(
            bgcolor=SURFACE, indicator_color=ft.Colors.with_opacity(0.22, CYAN)
        ),
    )
    page.theme = page.dark_theme
    page.padding = 0


def text_field(**kwargs) -> ft.TextField:
    """The app's text box: rounded, filled, quiet outline, cyan while typing.

    Flet 1.0.5 has no global input theme, so every TextField is made here.
    Callers can still override anything (e.g. ``expand``, ``password``).
    """
    style = dict(
        border_radius=RADIUS,
        border_width=1,
        border_color=EDGE,
        focused_border_color=CYAN,
        focused_border_width=1.5,
        filled=True,
        fill_color=FIELD,
        color=TEXT,
        cursor_color=CYAN,
        label_style=ft.TextStyle(color=MUTED),
        hint_style=ft.TextStyle(color=MUTED),
        content_padding=ft.Padding.symmetric(horizontal=14, vertical=14),
    )
    style.update(kwargs)
    return ft.TextField(**style)


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
