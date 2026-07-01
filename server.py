import os, json, asyncio, logging
from urllib.parse import quote, urlparse
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response, RedirectResponse
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pihole-mcp")

PIHOLE_URL      = os.getenv("PIHOLE_URL", "http://192.168.1.7")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD", "")
BASE_URL        = os.getenv("BASE_URL", "https://pihole-mcp.example.com")
MCP_SECRET      = os.getenv("MCP_SECRET", "")

app = FastAPI()

_sid      = None
_sid_lock = asyncio.Lock()


def check_auth(request: Request):
    if not MCP_SECRET:
        return
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {MCP_SECRET}":
        raise HTTPException(status_code=401, detail="Unauthorized")


ALLOWED_REDIRECT_HOSTS = {"claude.ai", "anthropic.com", "console.anthropic.com"}

def validate_redirect_uri(uri: str):
    parsed = urlparse(uri)
    host = (parsed.hostname or "").lower()
    is_local = host in ("localhost", "127.0.0.1")
    is_trusted = host in ALLOWED_REDIRECT_HOSTS or any(host.endswith("." + h) for h in ALLOWED_REDIRECT_HOSTS)
    ok = (parsed.scheme == "http" and is_local) or (parsed.scheme == "https" and (is_local or is_trusted))
    if not ok:
        raise HTTPException(status_code=400, detail=f"redirect_uri not allowed: {uri}")

ALLOWED_STATUSES = {"FORWARDED", "CACHE", "CACHE_STALE", "RETRIED", "RETRIED_DNSSEC", "IN_PROGRESS", "DNSSEC"}
BLOCKED_STATUSES = {"GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME"}
NXDOMAIN_STATUS  = "NXDOMAIN"

# How many of the most recent records (across the whole network) we actually pull
# from /api/queries when client-side filtering by client IP is required.
# The Pi-hole API doesn't support a server-side client= filter (see search_query_log).
CLIENT_FILTER_FETCH_LENGTH = 5000


async def get_sid() -> str | None:
    global _sid
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{PIHOLE_URL}/api/auth", json={"password": PIHOLE_PASSWORD})
            r.raise_for_status()
            session = r.json().get("session", {})
            if session.get("valid") and session.get("sid"):
                _sid = session["sid"]
                logger.info("Pi-hole session OK")
                return _sid
    except Exception as e:
        logger.error(f"Pi-hole auth error: {e}")
    _sid = None
    return None


async def ensure_sid() -> str:
    global _sid
    async with _sid_lock:
        if not _sid:
            await get_sid()
    if not _sid:
        raise RuntimeError("Pi-hole authentication failed — check PIHOLE_PASSWORD")
    return _sid


async def api(method: str, path: str, params=None, timeout: float = 10.0, **kwargs):
    global _sid
    sid = await ensure_sid()
    async with httpx.AsyncClient(timeout=timeout) as client:
        url     = f"{PIHOLE_URL}/api{path}"
        headers = {"X-FTL-SID": sid}
        r = await getattr(client, method)(url, headers=headers, params=params, **kwargs)
        if r.status_code == 401:
            logger.warning("SID expired, refreshing...")
            async with _sid_lock:
                _sid = None
                await get_sid()
            if not _sid:
                raise RuntimeError("Pi-hole re-authentication failed")
            headers = {"X-FTL-SID": _sid}
            r = await getattr(client, method)(url, headers=headers, params=params, **kwargs)
        r.raise_for_status()
        if not r.content:
            return {"ok": True, "status_code": r.status_code}
        try:
            return r.json()
        except Exception:
            return {"raw": r.text, "status_code": r.status_code}


async def api_raw(method: str, path: str, params=None, timeout: float = 30.0, **kwargs):
    """Like api(), but returns the httpx.Response as-is, without json()/text decoding —
    needed for binary responses like the Teleporter zip archive."""
    global _sid
    sid = await ensure_sid()
    async with httpx.AsyncClient(timeout=timeout) as client:
        url     = f"{PIHOLE_URL}/api{path}"
        headers = {"X-FTL-SID": sid}
        r = await getattr(client, method)(url, headers=headers, params=params, **kwargs)
        if r.status_code == 401:
            async with _sid_lock:
                _sid = None
                await get_sid()
            if not _sid:
                raise RuntimeError("Pi-hole re-authentication failed")
            headers = {"X-FTL-SID": _sid}
            r = await getattr(client, method)(url, headers=headers, params=params, **kwargs)
        r.raise_for_status()
        return r


def clamp(value, default, min_val, max_val) -> int:
    try:
        return max(min_val, min(int(value), max_val))
    except (TypeError, ValueError):
        return default


def _client_filter_warning(total_fetched: int, fetch_length: int, matched: int) -> str | None:
    """
    The Pi-hole API doesn't filter /queries by client= — we pull the most recent
    `fetch_length` records across the whole network and filter server-side.
    If the api returned exactly `fetch_length` records (i.e. there are more in the
    DB than we requested), the result only covers that time depth — older matches
    for the target client may not have been captured.
    """
    if total_fetched >= fetch_length:
        return (
            f"Note: the sample is limited to the {fetch_length} most recent queries across "
            f"the whole network (the Pi-hole API doesn't support a server-side client filter). "
            f"Matches found in this window: {matched}. "
            f"If you expected more, or older records, narrow from_time/until_time "
            f"or account for the fact that part of the history may not be covered."
        )
    return None


TOOLS = [
    {"name": "get_stats", "description": "Overall Pi-hole stats: total queries, blocked, unique clients, domains on Gravity", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_top_domains", "description": "Top queried or blocked domains. blocked=true — blocked only, blocked=false — all queries", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "description": "Number of entries (default: 10, max: 100)"}, "blocked": {"type": "boolean", "description": "true — top blocked, false/unset — top of all queries"}}, "required": []}},
    {"name": "get_top_clients", "description": "Top clients by number of DNS queries", "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "description": "Number of entries (default: 10, max: 100)"}}, "required": []}},
    {"name": "search_query_log", "description": "Search the DNS query log by domain or client IP", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Domain to search for"}, "client": {"type": "string", "description": "Client IP"}, "limit": {"type": "integer", "description": "Max entries (default: 50, max: 500)"}, "from_time": {"type": "integer", "description": "Period start (Unix timestamp)"}, "until_time": {"type": "integer", "description": "Period end (Unix timestamp)"}}, "required": []}},
    {"name": "check_domain", "description": "Check a domain's status — is it blocked, and in which list", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Domain to check"}}, "required": ["domain"]}},
    {"name": "add_to_denylist", "description": "Add a domain to the denylist (exact match)", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "comment": {"type": "string", "description": "Comment (optional)"}}, "required": ["domain"]}},
    {"name": "remove_from_denylist", "description": "Remove a domain from the denylist", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "add_to_allowlist", "description": "Add a domain to the allowlist (unblock it)", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}, "comment": {"type": "string", "description": "Comment (optional)"}}, "required": ["domain"]}},
    {"name": "set_local_dns", "description": "Set or update a local DNS A-record override — Pi-hole serves the given IP for the domain, bypassing normal upstream resolution. Doesn't affect ad blocking for other domains", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Domain (e.g. nas.home)"}, "ip": {"type": "string", "description": "IP address for the override"}}, "required": ["domain", "ip"]}},
    {"name": "remove_local_dns", "description": "Remove a local DNS A-record override for a domain", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "get_local_dns", "description": "Get the list of all current local DNS A-record overrides", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "toggle_blocking", "description": "Turn Pi-hole blocking on or off", "inputSchema": {"type": "object", "properties": {"enable": {"type": "boolean", "description": "true — enable, false — disable"}, "duration": {"type": "integer", "description": "Seconds until auto re-enable when disabling (0 = indefinitely, max: 86400)"}}, "required": ["enable"]}},
    {"name": "get_blocking_status", "description": "Current Pi-hole blocking status (enabled/disabled)", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "gravity_update", "description": "Update the blocklists (gravity update). Takes 1-3 minutes", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "get_recently_blocked", "description": "Most recently blocked DNS queries (Gravity, regex, exact, CNAME)", "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "description": "Number of entries (default: 20, max: 200)"}}, "required": []}},
    {"name": "analyze_anomalies", "description": "Find clients with an anomalously high number of DNS queries", "inputSchema": {"type": "object", "properties": {"threshold": {"type": "integer", "description": "Query-count threshold to flag an anomaly (default: 1000)"}}, "required": []}},
    {"name": "get_client_info", "description": "Client profile by IP: query count, blocked count, details", "inputSchema": {"type": "object", "properties": {"client": {"type": "string", "description": "Client IP address"}}, "required": ["client"]}},
    {"name": "get_recent_queries", "description": "Most recent DNS queries for a specific client", "inputSchema": {"type": "object", "properties": {"client": {"type": "string", "description": "Client IP address"}, "limit": {"type": "integer", "description": "Number of entries (default: 50, max: 200)"}, "from_time": {"type": "integer", "description": "Period start (Unix timestamp)"}, "until_time": {"type": "integer", "description": "Period end (Unix timestamp)"}}, "required": ["client"]}},
    {"name": "analyze_device", "description": "Comprehensive per-device analysis by IP: stats, top domains, blocks, NXDOMAIN, suspicious activity", "inputSchema": {"type": "object", "properties": {"client": {"type": "string", "description": "Device IP address"}, "limit": {"type": "integer", "description": "Queries to analyze (default: 200, max: 500)"}, "from_time": {"type": "integer", "description": "Period start (Unix timestamp)"}, "until_time": {"type": "integer", "description": "Period end (Unix timestamp)"}}, "required": ["client"]}},
    {"name": "get_local_cname_records", "description": "Get the list of all local CNAME records (DNS aliases)", "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "set_local_cname_record", "description": "Set or update a local CNAME record (alias one domain to another)", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Alias domain (source)"}, "target": {"type": "string", "description": "Target domain the alias points to"}, "ttl": {"type": "integer", "description": "TTL in seconds (optional)"}}, "required": ["domain", "target"]}},
    {"name": "remove_local_cname_record", "description": "Remove a local CNAME record by its source domain", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string", "description": "Alias domain (source) to remove"}}, "required": ["domain"]}},
    {"name": "add_to_denylist_regex", "description": "Add a regex pattern to the denylist (blocks all domains matching the pattern)", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Regex pattern, e.g. (\\.|^)ads\\.example\\.com$"}, "comment": {"type": "string", "description": "Comment (optional)"}}, "required": ["pattern"]}},
    {"name": "remove_from_denylist_regex", "description": "Remove a regex pattern from the denylist", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}},
    {"name": "add_to_allowlist_regex", "description": "Add a regex pattern to the allowlist (unblocks all domains matching the pattern)", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Regex pattern"}, "comment": {"type": "string", "description": "Comment (optional)"}}, "required": ["pattern"]}},
    {"name": "remove_from_allowlist_regex", "description": "Remove a regex pattern from the allowlist", "inputSchema": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}},
    {"name": "teleporter_backup", "description": "Full Pi-hole configuration backup (Teleporter) — lists, settings, groups — as a base64-encoded zip archive. Export only; restore (uploading it back) is intentionally not supported by this tool.", "inputSchema": {"type": "object", "properties": {}, "required": []}},
]


async def run_tool(name: str, args: dict):
    logger.info(f"Tool: {name}  args: {args}")

    if name == "get_stats":
        return await api("get", "/stats/summary")

    elif name == "get_top_domains":
        params = {"count": clamp(args.get("count"), 10, 1, 100)}
        if args.get("blocked") is True:
            params["blocked"] = "true"
        return await api("get", "/stats/top_domains", params=params)

    elif name == "get_top_clients":
        return await api("get", "/stats/top_clients", params={"count": clamp(args.get("count"), 10, 1, 100)})

    elif name == "search_query_log":
        limit = clamp(args.get("limit"), 50, 1, 500)
        client_filter = args.get("client")
        domain_filter = args.get("domain")
        # The Pi-hole API ignores the client= parameter — filter server-side ourselves
        fetch_limit = CLIENT_FILTER_FETCH_LENGTH if client_filter else limit
        params = {"length": fetch_limit}
        if domain_filter: params["domain"] = domain_filter
        if args.get("from_time"):  params["from"]  = int(args["from_time"])
        if args.get("until_time"): params["until"] = int(args["until_time"])
        result = await api("get", "/queries", params=params)
        all_queries = result.get("queries", [])
        queries = all_queries
        if client_filter:
            matched = [q for q in all_queries if q.get("client", {}).get("ip") == client_filter]
            queries = matched[:limit]
            warning = _client_filter_warning(len(all_queries), fetch_limit, len(matched))
            if warning:
                result["warning"] = warning
        result["queries"] = queries
        result["filtered_count"] = len(queries)
        return result

    elif name == "check_domain":
        domain = args["domain"]
        try:
            return await api("get", f"/search/{quote(domain, safe='')}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"domain": domain, "found": False, "message": "Domain not found in Pi-hole database"}
            raise
        except httpx.HTTPError as e:
            return {"error": str(e), "type": e.__class__.__name__}

    elif name == "add_to_denylist":
        return await api("post", "/domains/deny/exact", json={"domain": args["domain"], "comment": args.get("comment", "Added via Claude MCP"), "enabled": True})

    elif name == "remove_from_denylist":
        domain  = args["domain"]
        result  = await api("get", "/domains/deny/exact")
        domains = result.get("domains", [])
        matches = [d for d in domains if d.get("domain") == domain]
        if not matches:
            return {"error": f"Domain '{domain}' not found in denylist"}
        deleted, failed = [], []
        for d in matches:
            try:
                # The Pi-hole v6 API DELETE endpoint takes the domain itself in the path, not a numeric id
                await api("delete", f"/domains/deny/exact/{quote(d['domain'], safe='')}")
                deleted.append(d["domain"])
            except Exception as e:
                failed.append({"domain": d["domain"], "error": str(e)})
        return {"deleted": deleted, "failed": failed, "domain": domain, "count": len(deleted)}

    elif name == "add_to_allowlist":
        return await api("post", "/domains/allow/exact", json={"domain": args["domain"], "comment": args.get("comment", "Added via Claude MCP"), "enabled": True})

    elif name == "get_local_dns":
        return await api("get", "/config/dns/hosts")

    elif name == "set_local_dns":
        domain = args["domain"]
        ip     = args["ip"]
        current = await api("get", "/config/dns/hosts")
        hosts = current.get("config", {}).get("dns", {}).get("hosts", [])
        hosts = [h for h in hosts if not h.strip().endswith(f" {domain}")]
        hosts.append(f"{ip} {domain}")
        return await api("patch", "/config", json={"config": {"dns": {"hosts": hosts}}})

    elif name == "remove_local_dns":
        domain  = args["domain"]
        current = await api("get", "/config/dns/hosts")
        hosts   = current.get("config", {}).get("dns", {}).get("hosts", [])
        new_hosts = [h for h in hosts if not h.strip().endswith(f" {domain}")]
        if len(new_hosts) == len(hosts):
            return {"domain": domain, "found": False, "message": "Record not found"}
        return await api("patch", "/config", json={"config": {"dns": {"hosts": new_hosts}}})

    elif name == "toggle_blocking":
        enable = args.get("enable")
        if not isinstance(enable, bool):
            enable = str(enable).lower() == "true"
        if enable:
            return await api("post", "/dns/blocking", json={"blocking": True})
        body = {"blocking": False}
        duration = clamp(args.get("duration"), 0, 0, 86400)
        if duration > 0:
            body["timer"] = duration
        return await api("post", "/dns/blocking", json=body)

    elif name == "get_blocking_status":
        return await api("get", "/dns/blocking")

    elif name == "gravity_update":
        return await api("post", "/action/gravity", timeout=180.0)

    elif name == "get_recently_blocked":
        limit  = clamp(args.get("limit"), 20, 1, 200)
        params = [("length", limit), ("status", "GRAVITY"), ("status", "REGEX"), ("status", "DENYLIST"), ("status", "GRAVITY_CNAME"), ("status", "REGEX_CNAME"), ("status", "DENYLIST_CNAME")]
        return await api("get", "/queries", params=params)

    elif name == "analyze_anomalies":
        threshold   = clamp(args.get("threshold"), 1000, 1, 1000000)
        result      = await api("get", "/stats/top_clients", params={"count": 50})
        all_clients = result.get("clients", [])
        anomalies   = [c for c in all_clients if c.get("count", 0) > threshold]
        return {"anomalies": anomalies, "threshold": threshold, "total_checked": len(all_clients), "anomaly_count": len(anomalies)}

    elif name == "get_client_info":
        client       = args["client"]
        result       = await api("get", "/stats/top_clients", params={"count": 100})
        clients_list = result.get("clients", [])
        match        = next((c for c in clients_list if c.get("ip") == client or c.get("name") == client), None)
        if not match:
            logger.debug(f"Client {client} not found in top-100. Available IPs: {[c.get('ip') for c in clients_list[:5]]}")
        try:
            details = await api("get", f"/clients/{quote(client, safe='')}")
        except httpx.HTTPStatusError as e:
            details = {
                "details_available": False,
                "error": str(e),
                "status_code": e.response.status_code if e.response is not None else None,
            }
        except httpx.HTTPError as e:
            details = {
                "details_available": False,
                "error": str(e),
                "type": e.__class__.__name__,
            }
        except Exception as e:
            details = {
                "details_available": False,
                "error": str(e),
                "type": e.__class__.__name__,
            }
        return {"client": client, "stats": match or {"note": "not in top-100"}, "details": details}

    elif name == "get_recent_queries":
        client = args["client"]
        limit  = clamp(args.get("limit"), 50, 1, 200)
        fetch_limit = CLIENT_FILTER_FETCH_LENGTH
        params = {"length": fetch_limit}
        if args.get("from_time"):  params["from"]  = int(args["from_time"])
        if args.get("until_time"): params["until"] = int(args["until_time"])
        result = await api("get", "/queries", params=params)
        all_queries = result.get("queries", [])
        matched = [q for q in all_queries if q.get("client", {}).get("ip") == client]
        queries = matched[:limit]
        warning = _client_filter_warning(len(all_queries), fetch_limit, len(matched))
        if warning:
            result["warning"] = warning
        result["queries"] = queries
        result["filtered_count"] = len(queries)
        return result

    elif name == "analyze_device":
        client = args["client"]
        limit  = clamp(args.get("limit"), 200, 1, 500)
        fetch_limit = CLIENT_FILTER_FETCH_LENGTH
        q_params = {"length": fetch_limit}
        if args.get("from_time"):  q_params["from"]  = int(args["from_time"])
        if args.get("until_time"): q_params["until"] = int(args["until_time"])
        queries_raw, top_clients = await asyncio.gather(
            api("get", "/queries", params=q_params),
            api("get", "/stats/top_clients", params={"count": 100}),
        )
        all_queries_global = queries_raw.get("queries") or queries_raw.get("data") or []
        matched = [q for q in all_queries_global if q.get("client", {}).get("ip") == client]
        queries = matched[:limit]
        if not isinstance(queries, list):
            queries = []
        if not all_queries_global:
            logger.warning(f"analyze_device: unexpected response keys: {list(queries_raw.keys())}")
        total    = len(queries)
        blocked  = [q for q in queries if q.get("status") in BLOCKED_STATUSES]
        nxdomain = [q for q in queries if q.get("status") == NXDOMAIN_STATUS]
        allowed  = [q for q in queries if q.get("status") in ALLOWED_STATUSES]
        domain_counts: dict = {}
        for q in queries:
            d = q.get("domain")
            if d: domain_counts[d] = domain_counts.get(d, 0) + 1
        blocked_counts: dict = {}
        for q in blocked:
            d = q.get("domain")
            if d: blocked_counts[d] = blocked_counts.get(d, 0) + 1
        nxdomain_counts: dict = {}
        for q in nxdomain:
            d = q.get("domain")
            if d: nxdomain_counts[d] = nxdomain_counts.get(d, 0) + 1
        suspicion = []
        if total > 0:
            block_ratio = len(blocked) / total
            if block_ratio > 0.5:
                suspicion.append(f"High block ratio: {block_ratio:.0%}")
            if len(nxdomain) > 20:
                suspicion.append(f"Lots of NXDOMAIN: {len(nxdomain)} — possibly a broken app")
            if len(nxdomain) > 50:
                suspicion.append("⚠️ Very high NXDOMAIN count — possible DNS tunneling or malware")
        else:
            suspicion.append("No active DNS queries in the selected log period")
        clients_list = top_clients.get("clients", []) if isinstance(top_clients, dict) else []
        rank = next((i+1 for i, c in enumerate(clients_list) if c.get("ip") == client), None)
        response = {
            "client": client, "analyzed_queries": total,
            "summary": {"total": total, "allowed": len(allowed), "blocked": len(blocked), "nxdomain": len(nxdomain), "block_pct": f"{len(blocked)/total:.0%}" if total else "0%"},
            "top_domains":         [{"domain": d, "count": c} for d, c in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:15]],
            "top_blocked_domains": [{"domain": d, "count": c} for d, c in sorted(blocked_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
            "top_nxdomain":        [{"domain": d, "count": c} for d, c in sorted(nxdomain_counts.items(), key=lambda x: x[1], reverse=True)[:10]],
            "suspicion_flags": suspicion, "rank_in_top_clients": rank
        }
        warning = _client_filter_warning(len(all_queries_global), fetch_limit, len(matched))
        if warning:
            response["warning"] = warning
        return response

    elif name == "get_local_cname_records":
        return await api("get", "/config/dns/cnameRecords")

    elif name == "set_local_cname_record":
        domain = args["domain"]
        target = args["target"]
        ttl    = args.get("ttl")
        current  = await api("get", "/config/dns/cnameRecords")
        records  = current.get("config", {}).get("dns", {}).get("cnameRecords", [])
        records  = [r for r in records if r.split(",", 1)[0].strip() != domain]
        entry    = f"{domain},{target}" + (f",{int(ttl)}" if ttl else "")
        records.append(entry)
        return await api("patch", "/config", json={"config": {"dns": {"cnameRecords": records}}})

    elif name == "remove_local_cname_record":
        domain  = args["domain"]
        current = await api("get", "/config/dns/cnameRecords")
        records = current.get("config", {}).get("dns", {}).get("cnameRecords", [])
        new_records = [r for r in records if r.split(",", 1)[0].strip() != domain]
        if len(new_records) == len(records):
            return {"domain": domain, "found": False, "message": "CNAME record not found"}
        return await api("patch", "/config", json={"config": {"dns": {"cnameRecords": new_records}}})

    elif name == "add_to_denylist_regex":
        return await api("post", "/domains/deny/regex", json={"domain": args["pattern"], "comment": args.get("comment", "Added via Claude MCP"), "enabled": True})

    elif name == "remove_from_denylist_regex":
        pattern = args["pattern"]
        result  = await api("get", "/domains/deny/regex")
        domains = result.get("domains", [])
        matches = [d for d in domains if d.get("domain") == pattern]
        if not matches:
            return {"error": f"Regex pattern '{pattern}' not found in denylist"}
        deleted, failed = [], []
        for d in matches:
            try:
                await api("delete", f"/domains/deny/regex/{quote(d['domain'], safe='')}")
                deleted.append(d["domain"])
            except Exception as e:
                failed.append({"pattern": d["domain"], "error": str(e)})
        return {"deleted": deleted, "failed": failed, "pattern": pattern, "count": len(deleted)}

    elif name == "add_to_allowlist_regex":
        return await api("post", "/domains/allow/regex", json={"domain": args["pattern"], "comment": args.get("comment", "Added via Claude MCP"), "enabled": True})

    elif name == "remove_from_allowlist_regex":
        pattern = args["pattern"]
        result  = await api("get", "/domains/allow/regex")
        domains = result.get("domains", [])
        matches = [d for d in domains if d.get("domain") == pattern]
        if not matches:
            return {"error": f"Regex pattern '{pattern}' not found in allowlist"}
        deleted, failed = [], []
        for d in matches:
            try:
                await api("delete", f"/domains/allow/regex/{quote(d['domain'], safe='')}")
                deleted.append(d["domain"])
            except Exception as e:
                failed.append({"pattern": d["domain"], "error": str(e)})
        return {"deleted": deleted, "failed": failed, "pattern": pattern, "count": len(deleted)}

    elif name == "teleporter_backup":
        import base64
        r = await api_raw("get", "/teleporter", timeout=30.0)
        content = r.content
        return {
            "filename":      "pihole_teleporter_backup.zip",
            "content_type":  r.headers.get("content-type", "application/zip"),
            "size_bytes":    len(content),
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    else:
        return {"error": f"Unknown tool: {name}"}


@app.get("/")
async def root():
    return {"status": "pihole-mcp running", "pihole": PIHOLE_URL, "version": "1.5.1"}

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    return {"issuer": BASE_URL, "authorization_endpoint": f"{BASE_URL}/oauth/authorize", "token_endpoint": f"{BASE_URL}/oauth/token", "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"]}

@app.get("/oauth/authorize")
async def oauth_authorize(request: Request):
    params = dict(request.query_params)
    redirect_uri = params.get("redirect_uri", "")
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri required")
    validate_redirect_uri(redirect_uri)
    return RedirectResponse(url=f"{redirect_uri}?code=pihole-mcp-static-code&state={params.get('state', '')}")

@app.post("/oauth/token")
async def oauth_token(request: Request):
    form = await request.form()
    if MCP_SECRET and form.get("client_secret") != MCP_SECRET:
        raise HTTPException(status_code=401, detail="Invalid client_secret")
    return {"access_token": MCP_SECRET or "pihole-mcp-static-token", "token_type": "bearer", "expires_in": 86400}

@app.get("/mcp")
async def mcp_info(request: Request):
    check_auth(request)
    return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "pihole-mcp", "version": "1.5.1"}}

@app.post("/mcp")
async def mcp_handler(request: Request):
    check_auth(request)
    body   = await request.json()
    method = body.get("method")
    req_id = body.get("id")
    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "pihole-mcp", "version": "1.5.1"}}})
    elif method in ("notifications/initialized", "notifications/cancelled"):
        return Response(status_code=204)
    elif method == "ping":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})
    elif method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})
    elif method == "resources/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}})
    elif method == "prompts/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}})
    elif method == "tools/call":
        params    = body.get("params", {})
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        try:
            result = await run_tool(tool_name, tool_args)
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]}})
        except Exception as e:
            logger.error(f"Tool error [{tool_name}]: {e}")
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True}})
    else:
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})
