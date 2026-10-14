"""Logica de verificare: pură, ușor de testat, fără I/O în afara clientului primit."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

REQUIRED_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


@dataclass(frozen=True)
class CheckResult:
    url: str
    status_code: int
    present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.missing


def evaluate_headers(url: str, status_code: int, headers: httpx.Headers) -> CheckResult:
    """httpx.Headers este case-insensitive, deci 'X-Frame-Options' == 'x-frame-options'."""
    present = [h for h in REQUIRED_HEADERS if h in headers]
    missing = [h for h in REQUIRED_HEADERS if h not in headers]
    return CheckResult(url=url, status_code=status_code, present=present, missing=missing)


def check_url(url: str, client: httpx.Client) -> CheckResult:
    response = client.get(url, follow_redirects=True)
    return evaluate_headers(str(response.url), response.status_code, response.headers)
