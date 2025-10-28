import asyncio
import time
import urllib.parse
from typing import Dict, List, Tuple, Optional

from pyrogram import filters
from pyrogram.types import Message

from Extractor import app

import aiohttp


SAFE_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0 Safari/537.36"
)


def _shorten(text: str, max_len: int = 180) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _mask_query(query: Dict[str, List[str]]) -> Dict[str, List[str]]:
    sensitive_keys = {
        "token",
        "signature",
        "sig",
        "hmac",
        "key",
        "policy",
        "Policy",
        "Key-Pair-Id",
        "X-Amz-Signature",
        "X-Amz-Credential",
        "X-Amz-Security-Token",
        "Expires",
        "exp",
        "e",
        "st",
        "hdnea",
        "valid_till",
    }
    masked: Dict[str, List[str]] = {}
    for k, vals in query.items():
        if k in sensitive_keys:
            masked[k] = ["<redacted>"] * len(vals)
        else:
            masked[k] = vals
    return masked


def _estimate_ttl_seconds(query: Dict[str, List[str]]) -> Optional[int]:
    now = int(time.time())
    candidates = [
        ("Expires", None),
        ("exp", None),
        ("e", None),
        ("valid_till", None),
    ]
    for key, _ in candidates:
        if key in query and query[key]:
            v = query[key][0]
            try:
                ts = int(v)
                return ts - now
            except Exception:
                continue
    return None


async def _head_with_fallback(session: aiohttp.ClientSession, url: str) -> Tuple[aiohttp.ClientResponse, bytes]:
    # Try HEAD first; fall back to GET with Range for minimal bytes
    try:
        resp = await session.request("HEAD", url, allow_redirects=True)
        # some servers return 200 with no body; normalize body to empty
        await resp.release()
        return resp, b""
    except Exception:
        pass

    # Fallback minimal GET
    try:
        resp = await session.request(
            "GET",
            url,
            headers={"Range": "bytes=0-0"},
            allow_redirects=True,
        )
        body = await resp.content.readexactly(1) if resp.status in (200, 206) else b""
        await resp.release()
        return resp, body
    except Exception as e:
        raise e


def _grade_cache(headers: aiohttp.typedefs.LooseHeaders) -> str:
    cache_control = headers.get("Cache-Control", "")
    if "no-store" in cache_control:
        return "OK (no-store)"
    if "private" in cache_control:
        return "OK (private)"
    if "public" in cache_control:
        # risk if long-lived
        if "max-age" in cache_control:
            try:
                parts = dict(
                    p.split("=", 1) if "=" in p else (p, "")
                    for p in [x.strip() for x in cache_control.split(",")]
                )
                max_age = int(parts.get("max-age", "0"))
                if max_age > 3600:
                    return f"Risk: public cache, long max-age={max_age}s"
                return f"Caution: public cache, max-age={max_age}s"
            except Exception:
                return "Caution: public cache"
        return "Caution: public cache"
    return "Unclear"


def _bool_str(value: bool) -> str:
    return "yes" if value else "no"


def _collect_header(headers: aiohttp.typedefs.LooseHeaders, name: str) -> str:
    return headers.get(name, "-")


def _analyze_headers(url: str, resp: aiohttp.ClientResponse) -> str:
    h = resp.headers
    parsed = urllib.parse.urlparse(str(resp.url))
    query = urllib.parse.parse_qs(parsed.query)

    masked_query = _mask_query(query)
    ttl = _estimate_ttl_seconds(query)

    cors_origin = h.get("Access-Control-Allow-Origin")
    cors_creds = h.get("Access-Control-Allow-Credentials")

    is_tls = parsed.scheme == "https"
    is_m3u8 = parsed.path.endswith(".m3u8")
    is_mpd = parsed.path.endswith(".mpd") or "dash+xml" in h.get("Content-Type", "")

    accept_ranges = "bytes" in h.get("Accept-Ranges", "").lower()
    content_disp = h.get("Content-Disposition", "")
    inline_vs_attachment = "attachment" if "attachment" in content_disp.lower() else ("inline" if content_disp else "-")

    cdn_hints = []
    for key in [
        "CF-Cache-Status",
        "CF-Ray",
        "X-Cache",
        "X-Cache-Hits",
        "X-Served-By",
        "Via",
        "X-Amz-Cf-Id",
        "X-Amz-Version-Id",
        "X-Akamai-Staging",
        "X-Fastly-Request-ID",
    ]:
        if key in h:
            cdn_hints.append(f"{key}:{h.get(key)}")

    risks: List[str] = []

    # TLS enforcement
    if not is_tls:
        risks.append("High: URL is not HTTPS")

    # Token TTL risk
    if ttl is not None:
        if ttl > 7200:
            risks.append(f"Medium: token TTL appears long (~{ttl}s)")
        elif ttl <= 0:
            risks.append("Info: token expired per query params")

    # CORS
    if cors_origin == "*" and cors_creds not in (None, "false", "False"):
        risks.append("High: ACAO=* with credentials allows cross-site reads")
    elif cors_origin == "*":
        risks.append("Medium: ACAO=* enables broad cross-origin reads")

    # Range
    if accept_ranges:
        risks.append("Info: Range requests enabled (common for media)")

    # Content-Disposition
    if content_disp and "filename=" not in content_disp:
        risks.append("Low: Content-Disposition lacks filename")

    # Manifest type
    if is_m3u8 and "application/vnd.apple.mpegurl" not in h.get("Content-Type", "") and "application/x-mpegURL" not in h.get("Content-Type", ""):
        risks.append("Info: .m3u8 served with non-standard content-type")

    cache_grade = _grade_cache(h)

    lines = []
    lines.append(f"Audit: {_shorten(url, 300)}")
    lines.append("")
    lines.append(f"Final URL: {parsed.scheme}://{parsed.netloc}{_shorten(parsed.path + ('?' + parsed.query if parsed.query else ''), 200)}")
    lines.append(f"Status: {resp.status}")
    lines.append(f"Content-Type: {_collect_header(h, 'Content-Type')}")
    lines.append(f"Content-Length: {_collect_header(h, 'Content-Length')}")
    lines.append(f"Accept-Ranges: {_bool_str(accept_ranges)}")
    lines.append(f"Cache-Control: {_collect_header(h, 'Cache-Control')} ({cache_grade})")
    lines.append(f"CORS: origin={cors_origin or '-'} creds={cors_creds or '-'}")
    lines.append(f"HSTS: {_collect_header(h, 'Strict-Transport-Security')}")
    lines.append(f"CSP: {_shorten(_collect_header(h, 'Content-Security-Policy'))}")
    lines.append(f"Referrer-Policy: {_collect_header(h, 'Referrer-Policy')}")
    lines.append(f"Content-Disposition: {inline_vs_attachment}")
    if masked_query:
        lines.append(f"Query: {masked_query}")
    if ttl is not None:
        lines.append(f"Token TTL (from query): ~{ttl}s")
    if cdn_hints:
        lines.append("CDN Hints: " + "; ".join(cdn_hints))
    if is_m3u8:
        lines.append("Type: HLS manifest (.m3u8)")
    if is_mpd:
        lines.append("Type: DASH manifest (.mpd)")

    if risks:
        lines.append("")
        lines.append("Findings:")
        for r in risks[:12]:
            lines.append(f"- {r}")

    lines.append("")
    lines.append("Note: Read-only header audit. No content downloaded.")

    report = "\n".join(lines)
    if len(report) > 3500:
        report = report[:3450] + "\n… (truncated)"
    return report


@app.on_message(filters.command("audit"))
async def audit_command(client, message: Message):
    try:
        # Extract URL from command or reply
        parts = message.text.split(maxsplit=1)
        url = None
        if len(parts) > 1:
            url = parts[1].strip()
        elif message.reply_to_message and message.reply_to_message.text:
            url = message.reply_to_message.text.strip()

        if not url:
            await message.reply_text(
                "Usage: /audit <url>\nSends a safe, read-only header check and basic findings."
            )
            return

        # Validate URL
        if not (url.startswith("http://") or url.startswith("https://")):
            await message.reply_text("Please provide an absolute URL starting with http:// or https://")
            return

        timeout = aiohttp.ClientTimeout(total=12)
        connector = aiohttp.TCPConnector(ssl=False, limit=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": SAFE_USER_AGENT},
        ) as session:
            try:
                resp, _ = await _head_with_fallback(session, url)
            except Exception as e:
                await message.reply_text(f"Request failed: {e}")
                return

            report = _analyze_headers(url, resp)
            await message.reply_text(report)
    except Exception as e:
        await message.reply_text(f"Error: {e}")


@app.on_message(filters.command(["audithelp", "audithelp"]))
async def audit_help(client, message: Message):
    await message.reply_text(
        """
/audit <url>
- Safe, read-only audit of response headers
- Checks TLS, CORS, cache, range support, content-type, CDN hints
- Flags long-lived tokens in query (Expires/exp/e)
- Detects HLS/DASH manifests by type only (no downloads)
        """.strip()
    )
