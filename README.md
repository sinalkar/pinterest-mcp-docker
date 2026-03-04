# pinterest-mcp

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server for the [Pinterest API v5](https://developers.pinterest.com/docs/api/v5/).

Create pins, manage boards, and track analytics — all from an AI agent.

> **First open-source Pinterest MCP server.**

---

## Features

| Tool | Description |
|------|-------------|
| `create_pin` | Create a new Pin with image, title, description, and link |
| `update_pin` | Edit an existing pin’s metadata |
| `delete_pin` | Remove a pin |
| `get_pin_analytics` | Impressions, saves, link clicks, engagement rate |
| `list_boards` | List your boards |
| `create_board` | Create a new board |
| `get_board_pins` | List all pins on a board |
| `search_pins` | Search public pins by keyword |
| `get_account_analytics` | Account-level metrics: impressions, saves, engagements |
| `bulk_create_pins` | Create multiple pins in one call (rate-limited) |
| `get_trending` | Trending searches and interests in a niche |

---

## Installation

```bash
pip install pinterest-mcp
```

Or run directly with `uvx`:

```bash
uvx pinterest-mcp
```

---

## Authentication

Pinterest uses OAuth 2.0. You need a **Pinterest Business account** and a registered app.

1. Create an app at [developers.pinterest.com](https://developers.pinterest.com/apps/)
2. Add redirect URI: `http://localhost:8089/callback`
3. Copy Client ID + Client Secret to `.env` (see `.env.template`)
4. Run the auth flow to generate your access token:

```bash
pinterest-mcp-auth
```

This opens a browser, asks you to authorize, and saves your token to `.pinterest_token.json`.

---

## MCP Client Setup

```json
{
  "mcpServers": {
    "pinterest": {
      "command": "uvx",
      "args": ["pinterest-mcp"],
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

## Rate Limits

Pinterest API v5 rate limits for organic posting:
- **10 pins per minute** per account
- **250 pins per day** per account

`bulk_create_pins` automatically respects the per-minute limit.

---

## Development

```bash
git clone https://github.com/clugtu/pinterest-mcp
cd pinterest-mcp
pip install -e ".[dev]"
pytest
```

---

## License

MIT — see [LICENSE](LICENSE)

---

## Related

- [cults3d-mcp](https://github.com/clugtu/cults3d-mcp) — Cults3D marketplace MCP server
