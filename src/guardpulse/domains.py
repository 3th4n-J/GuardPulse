"""Domain normalisation and matching.

Everything stored in the block/allow lists is a bare, lower-case, IDNA-encoded
host name (``example.com``). A rule matches the host itself and every
sub-domain of it, so ``example.com`` also covers ``m.example.com``.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_PACKAGE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")


class InvalidDomain(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    """Turn user input (URL, host, ``*.host``) into a canonical host name."""
    text = (raw or "").strip()
    if not text:
        raise InvalidDomain("Enter a website address.")
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    try:
        host = urlsplit(text).hostname or ""
    except ValueError as exc:
        raise InvalidDomain("That doesn't look like a website address.") from exc
    host = host.strip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    if host.startswith("www."):
        host = host[4:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("That doesn't look like a website address.") from exc
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise InvalidDomain("That doesn't look like a website address.")
    if labels[-1].isdigit():
        raise InvalidDomain("IP addresses can't be blocked by name; block the site instead.")
    return host


def normalize_package(raw: str) -> str:
    """Validate an Android package name such as ``org.telegram.messenger``."""
    text = (raw or "").strip()
    if not _PACKAGE.match(text):
        raise InvalidDomain("Enter an Android package name, e.g. org.telegram.messenger")
    return text


def host_matches(host: str, rule: str) -> bool:
    return host == rule or host.endswith("." + rule)


def most_specific(host: str, rules: list[str]) -> str | None:
    """The longest rule in ``rules`` that matches ``host`` (or ``None``)."""
    best = None
    for rule in rules:
        if host_matches(host, rule) and (best is None or len(rule) > len(best)):
            best = rule
    return best
