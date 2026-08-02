# Stage 1: Build wheel
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder
WORKDIR /build
ENV SETUPTOOLS_SCM_PRETEND_VERSION=0.1.0
RUN pip install --no-cache-dir hatchling hatch-vcs
COPY pyproject.toml README.md NOTICE.md LICENSE CHANGELOG.md ./
COPY src/ ./src/
RUN python -m hatchling build -t wheel

# Stage 2: Install dependencies into venv with require-hashes
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS venv
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt
COPY --from=builder /build/dist/*.whl ./
RUN pip install --no-cache-dir --no-deps *.whl

# Stage 3: Runtime image
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

LABEL org.opencontainers.image.title="pinterest-mcp-docker" \
      org.opencontainers.image.description="Hardened, containerized MCP server for Pinterest API v5" \
      org.opencontainers.image.authors="Carlos Lugtu (upstream author), sanjay s (fork maintainer)" \
      org.opencontainers.image.vendor="sinalkar" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/sinalkar/pinterest-mcp-docker" \
      org.opencontainers.image.upstream="https://github.com/clugtu/pinterest-mcp" \
      org.opencontainers.image.upstream.author="Carlos Lugtu"

RUN groupadd -g 10001 app && \
    useradd -u 10001 -g app -s /bin/false -m -d /home/app app && \
    mkdir -p /home/app/.local/state/pinterest-mcp && \
    chown -R app:app /home/app

WORKDIR /home/app
COPY --from=venv /opt/venv /opt/venv
COPY LICENSE NOTICE.md /home/app/

ENV PATH="/opt/venv/bin:$PATH" \
    HOME="/home/app" \
    PYTHONUNBUFFERED=1

VOLUME ["/home/app/.local/state/pinterest-mcp"]
USER 10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["python3", "-c", "import os, urllib.request, sys; sys.exit(0 if os.environ.get('MCP_TRANSPORT', 'stdio') == 'stdio' else (0 if urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"MCP_PORT\", 8080)}/healthz').getcode() == 200 else 1))"]

ENTRYPOINT ["pinterest-mcp"]
