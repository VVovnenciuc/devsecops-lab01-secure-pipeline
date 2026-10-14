import httpx
import pytest

from headercheck.checker import REQUIRED_HEADERS, check_url, evaluate_headers
from headercheck.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

_RealClient = httpx.Client  # salvăm clasa reală înainte de monkeypatch
ALL_HEADERS = {h: "x" for h in REQUIRED_HEADERS}


def make_client(headers: dict[str, str]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers)

    return _RealClient(transport=httpx.MockTransport(handler), timeout=5.0)


def test_all_headers_present_passes() -> None:
    result = evaluate_headers("https://t.test", 200, httpx.Headers(ALL_HEADERS))
    assert result.passed
    assert result.missing == []


def test_missing_headers_are_reported_case_insensitive() -> None:
    result = evaluate_headers("https://t.test", 200, httpx.Headers({"X-Frame-Options": "DENY"}))
    assert not result.passed
    assert "x-frame-options" in result.present
    assert "content-security-policy" in result.missing


def test_check_url_uses_given_client() -> None:
    result = check_url("https://t.test", make_client({"Strict-Transport-Security": "max-age=1"}))
    assert result.status_code == 200
    assert "strict-transport-security" in result.present


@pytest.mark.parametrize(("headers", "expected"), [(ALL_HEADERS, EXIT_OK), ({}, EXIT_FINDINGS)])
def test_main_exit_codes(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str], expected: int
) -> None:
    monkeypatch.setattr(httpx, "Client", lambda **_: make_client(headers))
    assert main(["https://t.test"]) == expected


def test_main_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **_: _RealClient(transport=httpx.MockTransport(handler), timeout=5.0),
    )
    assert main(["https://t.test"]) == EXIT_ERROR
