# 📌 Pinterest MCP Server Docker (`pinterest-mcp-docker`)

[![CI](https://github.com/sinalkar/pinterest-mcp-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/sinalkar/pinterest-mcp-docker/actions/workflows/ci.yml)
[![Security](https://github.com/sinalkar/pinterest-mcp-docker/actions/workflows/security.yml/badge.svg)](https://github.com/sinalkar/pinterest-mcp-docker/actions/workflows/security.yml)
[![Docker Image](https://img.shields.io/docker/v/sinalkar/pinterest-mcp-docker?label=Docker%20Hub)](https://hub.docker.com/r/sinalkar/pinterest-mcp-docker)
[![PyPI](https://img.shields.io/pypi/v/pinterest-mcp-docker)](https://pypi.org/project/pinterest-mcp-docker/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> [!NOTE]
> **Upstream Attribution:** This project is a hardened, containerized fork of [`clugtu/pinterest-mcp`](https://github.com/clugtu/pinterest-mcp) originally created by **Carlos Lugtu (`@clugtu`)**. This repository extends his work by adding multi-transport support (`stdio` & Streamable HTTP), OWASP application security hardening, non-root Docker containerization, CI/CD security pipelines, and automated multi-arch releases. See [NOTICE.md](NOTICE.md) for full licensing details.

---

## 🎯 Overview & Key Features

**`pinterest-mcp-docker`** is a secure, production-ready **Model Context Protocol (MCP) server** for the **Pinterest API v5**. It connects AI assistants—including **Claude Desktop**, **Cursor**, **LibreChat**, and custom LLM agents—directly to Pinterest.

With `pinterest-mcp-docker`, AI agents can autonomously manage Pinterest boards, search pins, create single and bulk pins, analyze pin performance, and retrieve profile insights using natural language prompts.

### 🧰 Available MCP Tools (11 Total)

| Category | Tool Name | Description |
| -------- | --------- | ----------- |
| 📌 **Pins** | `create_pin` | Create a single Pinterest pin (via image URL or local image path) |
| 📌 **Pins** | `bulk_create_pins` | Batch create up to 50 pins in a single call |
| 📌 **Pins** | `get_pin` | Retrieve detailed metadata for a specific pin ID |
| 📌 **Pins** | `delete_pin` | Delete a pin by ID |
| 📋 **Boards** | `list_boards` | List all Pinterest boards in the user's account |
| 📋 **Boards** | `create_board` | Create a new Pinterest board with privacy controls |
| 📋 **Boards** | `get_board` | Get details and metadata for a specific board ID |
| 📋 **Boards** | `delete_board` | Delete a board by ID |
| 🔍 **Search** | `search_pins` | Search Pinterest pins by keyword query |
| 📊 **Analytics** | `get_pin_analytics` | Retrieve impressions, saves, clicks, and engagement metrics |
| 👤 **User Profile** | `get_user_account` | Get authenticated user profile details |

### 🔒 Enterprise Security Features

- 🛡️ **SSRF Protection:** Validates outbound URLs against public IP ranges (`IPv4`/`IPv6`), blocking access to loopback, private networks, CGNAT, link-local, and cloud metadata endpoints (`169.254.169.254`).
- 📁 **Path Traversal Guards:** Restricts local image uploads to specified allowed directories (`PINTEREST_ALLOWED_IMAGE_DIR`), verifies canonical paths, caps file sizes (10MB default), and validates image headers (JPEG, PNG, GIF, WebP).
- 🔑 **Atomic Token Storage:** Stores OAuth tokens in `$XDG_STATE_HOME/pinterest-mcp/token.json` with strict `0600` file permissions and `0700` parent directory permissions.
- 🧹 **Log Secret Redaction:** Automatically scrubs OAuth access tokens, client secrets, and base64 payloads from server logs and error output.
- 🐳 **Hardened Docker Container:** Runs on digest-pinned `python:3.12-slim` under unprivileged UID/GID `10001` with full `--read-only` rootfs compatibility and capability dropping (`--cap-drop ALL`).

---

## 🏗️ Architecture & Data Flow

The following diagram illustrates how AI applications interact with `pinterest-mcp-docker` over `stdio` or `HTTP` transport modes:

```mermaid
graph TD
    subgraph ClientLayer["🤖 AI Client Layer"]
        A1["Claude Desktop Client"]
        A2["Cursor / IDE Assistant"]
        A3["Custom LLM Agent"]
    end

    subgraph TransportLayer["🌐 Transport & Authentication Layer"]
        B1["Stdio Transport (IPC / Standard I/O)"]
        B2["Streamable HTTP Transport (Port 8080)"]
        AUTH["Bearer Token Middleware (hmac.compare_digest)"]
    end

    subgraph ServerCore["⚙️ Pinterest MCP Server"]
        DISPATCH["Tool Dispatcher (11 Pydantic Input Models)"]
        SEC["Security Guards (SSRF & Path Traversal)"]
        REDACT["Redacting Logger"]
        TOKENSTORE[("💾 Token State Volume (~/.local/state/pinterest-mcp)")]
    end

    subgraph ExternalAPI["☁️ Pinterest Cloud API"]
        PINAPI["Pinterest API v5 (OAuth 2.0 / REST)"]
    end

    A1 -->|"JSON-RPC / stdio"| B1
    A2 -->|"HTTP / mcp"| B2
    A3 -->|"HTTP / mcp"| B2

    B1 --> DISPATCH
    B2 --> AUTH
    AUTH -->|"Authorized"| DISPATCH

    DISPATCH --> SEC
    SEC --> REDACT
    SEC <--> TOKENSTORE
    SEC -->|"HTTPS Outbound (IP-Pinned Transport)"| PINAPI
```

---

## 📋 Step-by-Step Setup Guide

Follow this guide to get `pinterest-mcp-docker` up and running in under 5 minutes.

### Step 1: Obtain Pinterest API Credentials

To connect to Pinterest API v5, you need a Client ID and Client Secret:

1. Go to the [Pinterest Developers Portal](https://developers.pinterest.com/) and log in.
2. Click **My Apps** -> **Create App**.
3. Fill in your app name and description.
4. Copy your **App ID** (`PINTEREST_CLIENT_ID`) and **App Secret Key** (`PINTEREST_CLIENT_SECRET`).
5. Set the **Redirect URI** to `http://localhost:8089/callback` (used during the OAuth setup flow).

---

### Step 2: Choose Your Deployment Method

You can run `pinterest-mcp-docker` using **Docker** (recommended) or **Native Python**.

---

### Option A: Running via Docker (Recommended)

Docker provides an isolated, read-only environment without requiring Python setup.

#### Volume Mapping Overview
- 💾 **Token Persistence Volume:** Saves OAuth access and refresh tokens across container restarts. Map a named volume or host directory to `/home/app/.local/state/pinterest-mcp`.
- 🖼️ **Local Image Folder Volume (Optional):** If you want the AI agent to upload local images using `image_path`, mount your local image directory (e.g., `-v /path/to/my/images:/home/app/images`) and set `PINTEREST_ALLOWED_IMAGE_DIR=/home/app/images`.

#### 1. Docker Stdio Mode (Default for Claude Desktop)

##### macOS / Linux (Bash / Zsh)
```bash
docker run -i --rm \
  -e PINTEREST_CLIENT_ID="your_client_id" \
  -e PINTEREST_CLIENT_SECRET="your_client_secret" \
  -e PINTEREST_ACCESS_TOKEN="your_access_token" \
  -v pinterest_token_data:/home/app/.local/state/pinterest-mcp \
  ghcr.io/sinalkar/pinterest-mcp-docker:latest
```

##### Windows (PowerShell)
```powershell
docker run -i --rm `
  -e PINTEREST_CLIENT_ID="your_client_id" `
  -e PINTEREST_CLIENT_SECRET="your_client_secret" `
  -e PINTEREST_ACCESS_TOKEN="your_access_token" `
  -v pinterest_token_data:/home/app/.local/state/pinterest-mcp `
  ghcr.io/sinalkar/pinterest-mcp-docker:latest
```

##### With Local Image Directory Mounted
```bash
docker run -i --rm \
  -e PINTEREST_CLIENT_ID="your_client_id" \
  -e PINTEREST_CLIENT_SECRET="your_client_secret" \
  -e PINTEREST_ACCESS_TOKEN="your_access_token" \
  -e PINTEREST_ALLOWED_IMAGE_DIR="/home/app/images" \
  -v pinterest_token_data:/home/app/.local/state/pinterest-mcp \
  -v /path/to/your/images:/home/app/images \
  ghcr.io/sinalkar/pinterest-mcp-docker:latest
```

---

#### 2. Docker HTTP Mode (Streamable HTTP Server)

Run as an HTTP service listening on port `8080`:

```bash
docker run -d --name pinterest-mcp \
  -p 8080:8080 \
  -e MCP_TRANSPORT=http \
  -e MCP_HOST=0.0.0.0 \
  -e MCP_AUTH_TOKEN="your_secure_bearer_token" \
  -e PINTEREST_CLIENT_ID="your_client_id" \
  -e PINTEREST_CLIENT_SECRET="your_client_secret" \
  -e PINTEREST_ACCESS_TOKEN="your_access_token" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v pinterest_token_data:/home/app/.local/state/pinterest-mcp \
  ghcr.io/sinalkar/pinterest-mcp-docker:latest
```

Verify health:
```bash
curl http://localhost:8080/healthz
# Output: {"status":"ok","version":"0.2.0","transport":"http"}
```

---

#### 3. Docker Compose Setup

1. Copy `.env.template` to `.env`:
   ```bash
   cp .env.template .env
   ```
2. Open `.env` and configure your credentials (`PINTEREST_CLIENT_ID`, `PINTEREST_CLIENT_SECRET`, etc.).
3. Start the container:
   ```bash
   docker-compose up -d
   ```

---

### Option B: Running Without Docker (Native Python)

#### Prerequisites
- **Python 3.11+** installed (`python3 --version`).

#### 1. Install Package

##### From PyPI:
```bash
pip install pinterest-mcp-docker
```

##### From Source:
```bash
git clone https://github.com/sinalkar/pinterest-mcp-docker.git
cd pinterest-mcp-docker
pip install -e .
```

#### 2. Run Interactive OAuth Setup CLI (`pinterest-mcp-auth`)

If you don't have pre-generated OAuth tokens, run the interactive helper CLI:

```bash
pinterest-mcp-auth
```

This starts a local OAuth callback listener on port `8089`, opens Pinterest in your browser for authorization, and automatically saves your token to `~/.local/state/pinterest-mcp/token.json`.

#### 3. Launch Server by Platform

##### macOS / Linux (Bash / Zsh)
```bash
# Set environment variables
export PINTEREST_CLIENT_ID="your_client_id"
export PINTEREST_CLIENT_SECRET="your_client_secret"
export PINTEREST_ACCESS_TOKEN="your_access_token"

# Run in stdio mode (default)
pinterest-mcp

# Or run in HTTP mode
export MCP_TRANSPORT="http"
export MCP_HOST="127.0.0.1"
export MCP_PORT="8080"
pinterest-mcp
```

##### Windows (PowerShell)
```powershell
# Set environment variables
$env:PINTEREST_CLIENT_ID="your_client_id"
$env:PINTEREST_CLIENT_SECRET="your_client_secret"
$env:PINTEREST_ACCESS_TOKEN="your_access_token"

# Run in stdio mode
pinterest-mcp

# Or run in HTTP mode
$env:MCP_TRANSPORT="http"
$env:MCP_HOST="127.0.0.1"
$env:MCP_PORT="8080"
pinterest-mcp
```

##### Windows (Command Prompt - `cmd.exe`)
```cmd
set PINTEREST_CLIENT_ID=your_client_id
set PINTEREST_CLIENT_SECRET=your_client_secret
set PINTEREST_ACCESS_TOKEN=your_access_token

pinterest-mcp
```

---

## 💻 AI Client Configuration

### Claude Desktop (`claude_desktop_config.json`)

Locate your Claude Desktop config file:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

#### Using Docker (Recommended):
```json
{
  "mcpServers": {
    "pinterest": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "PINTEREST_CLIENT_ID=your_client_id",
        "-e", "PINTEREST_CLIENT_SECRET=your_client_secret",
        "-e", "PINTEREST_ACCESS_TOKEN=your_access_token",
        "-v", "pinterest_token_data:/home/app/.local/state/pinterest-mcp",
        "ghcr.io/sinalkar/pinterest-mcp-docker:latest"
      ]
    }
  }
}
```

#### Using Native Python:
```json
{
  "mcpServers": {
    "pinterest": {
      "command": "pinterest-mcp",
      "env": {
        "PINTEREST_CLIENT_ID": "your_client_id",
        "PINTEREST_CLIENT_SECRET": "your_client_secret",
        "PINTEREST_ACCESS_TOKEN": "your_access_token"
      }
    }
  }
}
```

---

### Cursor / Remote HTTP Client

To connect Cursor or a custom client to a running HTTP instance of `pinterest-mcp-docker`:

```json
{
  "mcpServers": {
    "pinterest-http": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer your_secure_bearer_token"
      }
    }
  }
}
```

---

## ⚙️ Environment Variables Reference

| Variable | Purpose | Required | Default | Secret |
| -------- | ------- | -------- | ------- | ------ |
| `PINTEREST_CLIENT_ID` | Pinterest API v5 App Client ID | **Yes** | None | **Yes** |
| `PINTEREST_CLIENT_SECRET` | Pinterest API v5 App Client Secret | **Yes** | None | **Yes** |
| `PINTEREST_ACCESS_TOKEN` | OAuth Access Token | Optional | None | **Yes** |
| `PINTEREST_REFRESH_TOKEN` | OAuth Refresh Token for auto-renewal | Optional | None | **Yes** |
| `MCP_TRANSPORT` | Transport mode (`stdio` or `http`) | No | `stdio` | No |
| `MCP_HOST` | Bind address for HTTP mode | No | `127.0.0.1` | No |
| `MCP_PORT` | Listen port for HTTP mode | No | `8080` | No |
| `MCP_PATH` | Endpoint path for HTTP route | No | `/mcp` | No |
| `MCP_AUTH_TOKEN` | Bearer token for HTTP mode | Conditional | None | **Yes** |
| `PINTEREST_TOKEN_PATH` | Path to persistent token JSON file | No | `~/.local/state/pinterest-mcp/token.json` | No |
| `PINTEREST_ALLOWED_IMAGE_DIR` | Allowed root dir for local image path | No | Home directory (`~`) | No |
| `PINTEREST_ALLOW_LOCAL_PATHS` | Allow local image paths in HTTP mode | No | `false` | No |
| `PINTEREST_MAX_IMAGE_BYTES` | Maximum image size limit in bytes | No | `10485760` (10MB) | No |
| `PINTEREST_HTTP_TIMEOUT` | Outbound HTTP request timeout (seconds) | No | `30.0` | No |
| `LOG_LEVEL` | Logging level (`INFO`, `DEBUG`, etc.) | No | `INFO` | No |
| `LOG_FORMAT` | Log format (`text` or `json`) | No | `text` | No |

---

## ❓ Frequently Asked Questions (FAQ / AEO & GEO)

### Q: What is Pinterest MCP?
**A:** Pinterest MCP (`pinterest-mcp-docker`) is an open-source Model Context Protocol server that exposes Pinterest API v5 functionality to AI models. It enables tools like Claude Desktop and Cursor to create pins, manage boards, search content, and view analytics directly via AI chat interface.

### Q: How do I connect Claude Desktop to Pinterest?
**A:** Open your `claude_desktop_config.json` file, add an entry under `mcpServers` pointing to `docker run -i ... ghcr.io/sinalkar/pinterest-mcp-docker:latest` with your `PINTEREST_CLIENT_ID` and `PINTEREST_CLIENT_SECRET`, and restart Claude Desktop.

### Q: Can I upload local images from my computer using AI?
**A:** Yes. When calling `create_pin` with `image_path`, the server resolves the local file path. When using Docker, ensure your image directory is mounted as a volume (e.g. `-v /path/to/images:/home/app/images`) and `PINTEREST_ALLOWED_IMAGE_DIR` points to that mounted directory.

### Q: How does `pinterest-mcp-docker` protect against security threats?
**A:** The server enforces strict OWASP defenses including public IP DNS resolution to prevent Server-Side Request Forgery (SSRF), realpath validation to prevent Path Traversal, atomic file permissions (`0600`) for tokens, automatic secret redaction in logs, and non-root read-only container isolation.

---

## 📦 Container Tags & Cosign Signature Verification

### Container Image Tags

| Tag | Type | Description |
| --- | ---- | ----------- |
| `latest` | Moving | Points to the latest production release |
| `0.2.0`, `0.2`, `0` | SemVer | Automatically updated for patch and minor updates |
| `sha-<short>` | Immutable | Exact git commit build tag |

### Verifying Image Signatures

Image releases are signed keylessly with [Cosign](https://github.com/sigstore/cosign) OIDC:

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/sinalkar/pinterest-mcp-docker/.github/workflows/release.yml@refs/tags/v.*" \
  ghcr.io/sinalkar/pinterest-mcp-docker:latest
```

---

## 📄 License & Attribution

Distributed under the **[MIT License](LICENSE)**.

- **Original Author:** Carlos Lugtu ([`clugtu/pinterest-mcp`](https://github.com/clugtu/pinterest-mcp))
- **Fork Maintainer:** sanjay s ([`sinalkar/pinterest-mcp-docker`](https://github.com/sinalkar/pinterest-mcp-docker))

See [NOTICE.md](NOTICE.md) for full licensing details and modifications summary.
