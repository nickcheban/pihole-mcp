# pihole-mcp

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

MCP server for Pi-hole v6.x (the new `/api` endpoint, session-based auth via `X-FTL-SID`). Besides direct Pi-hole API proxying, it provides a few composite tools for analyzing devices on the network (top domains, anomalies, suspicious activity via NXDOMAIN/block-ratio) — these aren't in the Pi-hole API itself, they're extra logic layered on top of `/api/queries`.

## Tools

**Stats and queries**

| Tool | Description |
|---|---|
| `get_stats` | Overall stats: total queries, blocked, clients, domains on Gravity |
| `get_top_domains` | Top queried/blocked domains |
| `get_top_clients` | Top clients by query count |
| `search_query_log` | Search the log by domain/client IP, with a time filter |
| `get_recently_blocked` | Most recently blocked queries |
| `check_domain` | Domain status — is it blocked, and in which list |

**Device analysis**

| Tool | Description |
|---|---|
| `get_client_info` | Client profile: queries, blocks, details |
| `get_recent_queries` | Recent queries from a specific client |
| `analyze_device` | Comprehensive analysis: top domains, block ratio, NXDOMAIN flags (possible DNS tunneling/malware) |
| `analyze_anomalies` | Clients with an anomalously high number of queries |

**Lists (allow/deny, exact and regex)**

| Tool | Description |
|---|---|
| `add_to_denylist` / `remove_from_denylist` | Exact-match domain in the denylist |
| `add_to_allowlist` | Exact-match domain in the allowlist |
| `add_to_denylist_regex` / `remove_from_denylist_regex` | Regex pattern in the denylist |
| `add_to_allowlist_regex` / `remove_from_allowlist_regex` | Regex pattern in the allowlist |

**Local DNS**

| Tool | Description |
|---|---|
| `get_local_dns` / `set_local_dns` / `remove_local_dns` | A-record overrides |
| `get_local_cname_records` / `set_local_cname_record` / `remove_local_cname_record` | CNAME records |

**Management and backup**

| Tool | Description |
|---|---|
| `toggle_blocking` / `get_blocking_status` | Turn blocking on/off, with an auto-re-enable timer |
| `gravity_update` | Update the blocklists |
| `teleporter_backup` | Full configuration backup (Teleporter) as base64. Export only — restore intentionally not implemented |

## Setup

```bash
git clone <this-repo> pihole-mcp && cd pihole-mcp
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env       # fill in PIHOLE_URL / PIHOLE_PASSWORD / MCP_SECRET
uvicorn server:app --host 0.0.0.0 --port 8002
```

Systemd unit example: [`deploy/pihole-mcp.service`](deploy/pihole-mcp.service).

## Security model

- Auth is an `Authorization: Bearer $MCP_SECRET` header on `/mcp`. Empty `MCP_SECRET` = no check (local network/VPN only).
- `/.well-known/oauth-authorization-server` + `/oauth/authorize` + `/oauth/token` are a compatible stub for claude.ai custom connectors, which [don't support a static API key](https://claude.com/docs/connectors/building/authentication) — only full OAuth 2.1 or no auth at all. The actual protection is the Bearer token on `/mcp`. Via Claude Code CLI (`claude mcp add --header ...`) you don't need the stub.
- `redirect_uri` in `/oauth/authorize` is checked against an allowlist (`claude.ai`, `anthropic.com`, `console.anthropic.com`, `localhost`).
- The Pi-hole API can't filter `/queries` by `client=` server-side — the server pulls the last N (5000 by default) records across the whole network and filters them itself, with an explicit warning in the response if the window might not cover the target client's full history.
- **Transport**: the server does not terminate TLS itself — it listens on plain HTTP. If it's reachable beyond localhost/a trusted LAN (and especially if you're connecting it as a custom connector in claude.ai, where HTTPS is required), put TLS termination in front of it: Cloudflare Tunnel, Tailscale Funnel, nginx/Caddy + Let's Encrypt, etc. Without that, the Bearer token (`MCP_SECRET`) in the `Authorization` header goes out in plaintext.

## Requirements

- Pi-hole v6.x (not v5 — the `/api/...` endpoints only appeared in v6).
- Python 3.11+.

## License

MIT — see [LICENSE](LICENSE).
