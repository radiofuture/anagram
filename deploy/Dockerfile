# Anagram community node. Build context: the repository root (see compose.yaml).
#
#   docker build -f deploy/Dockerfile -t anagram-node .
#
# The container runs `anagram node start`: first start from ANAGRAM_* variables
# (see src/anagram/shell/node/setup.py and docs/deploy.md), then the node on port 8787.
# All node data is in the /data volume (/data/node). Back up that one folder.

FROM python:3.13-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.7.20 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first (cached layer), then the project itself.
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra node --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra node --no-editable

FROM python:3.13-slim-bookworm
RUN useradd --system --uid 10001 --user-group --home-dir /data --no-create-home anagram \
    && mkdir -p /data/node && chown -R anagram:anagram /data
COPY --from=build --chown=anagram:anagram /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    HOME=/data \
    ANAGRAM_HOME=/data/client \
    ANAGRAM_NODE_HOME=/data/node
USER anagram
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/log/checkpoint', timeout=4)"]
ENTRYPOINT ["anagram"]
CMD ["node", "start", "--host", "0.0.0.0", "--port", "8787"]
