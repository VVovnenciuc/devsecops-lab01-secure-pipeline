"""CLI: headercheck <url> [<url> ...]

Exit codes (contract pentru CI):
  0 = toate header-ele prezente, 1 = lipsesc header-e, 2 = eroare de rețea/execuție
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict
from typing import Any

import httpx

from headercheck import __version__
from headercheck.checker import check_url

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

logger = logging.getLogger("headercheck")


class JsonFormatter(logging.Formatter):
    """Log-uri JSON pe stderr: ușor de colectat în Loki/ELK. Rezultatul merge pe stdout."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    level = os.environ.get("HEADERCHECK_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, handlers=[handler], force=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="headercheck", description="Verifică header-ele HTTP de securitate."
    )
    parser.add_argument("urls", nargs="+", help="URL-uri de verificat (https://...)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("HEADERCHECK_TIMEOUT", "10")),
        help="timeout per request, în secunde (env: HEADERCHECK_TIMEOUT)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = parse_args(argv)
    results: list[dict[str, Any]] = []
    exit_code = EXIT_OK

    with httpx.Client(
        timeout=args.timeout, headers={"User-Agent": f"headercheck/{__version__}"}
    ) as client:
        for url in args.urls:
            try:
                result = check_url(url, client)
            except httpx.HTTPError as exc:
                logger.error("request failed for %s: %s", url, exc)
                exit_code = EXIT_ERROR
                continue
            results.append(asdict(result) | {"passed": result.passed})
            logger.info("checked %s, missing=%d", url, len(result.missing))
            if not result.passed and exit_code == EXIT_OK:
                exit_code = EXIT_FINDINGS

    print(json.dumps(results, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
