# syntax=docker/dockerfile:1

# Imaginile de bază sunt fixate pe DIGEST: imutabil, spre deosebire de tag
ARG PYTHON_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336

FROM ${UV_IMAGE} AS uv

# ---------- Stage 1: builder (conține uv; NU ajunge în imaginea finală) ----------
FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3
WORKDIR /app
# 1) Doar dependențele → layer cache-uit cât timp uv.lock nu se schimbă
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
# 2) Apoi codul aplicației
COPY README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

# ---------- Stage 2: runtime (minim, non-root) ----------
FROM ${PYTHON_IMAGE} AS runtime
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
# venv-ul rămâne deținut de root: procesul (uid 10001) NU își poate modifica propriul cod
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["uvicorn", "notes_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
