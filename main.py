"""
OSINT LOOKUP BOT — Telegram Bot API 10.3
========================================

A private-by-default OSINT search bot. The data source is configured once by an
admin and is NEVER exposed to end users: they only ever see clean, rich result
cards.

Rich Messages (Bot API 10.3) support
------------------------------------
Bot API 10.3 added RichMessageButton / RichTextButton / RichBlockButtons /
RichBlockExpandableBlockQuotation / RichBlockTable(is_compact) /
RichBlockDocument. Python wrappers have not shipped those classes yet, so this
bot targets the same on-screen result with the transport that is available
today, block for block:

  RichBlockButtons                  -> inline keyboard rows (rich button grid)
  RichMessageButton / RichTextButton-> InlineKeyboardButton (callback / url)
  RichBlockExpandableBlockQuotation -> <blockquote expandable>
  RichBlockTable(is_compact=True)   -> compact monospace key/value table
  RichBlockDocument / tg://document -> sendDocument export of a record

Button colors use the NATIVE `style` field added to InlineKeyboardButton in
Bot API 9.4 (Feb 9, 2026) and supported by python-telegram-bot since v22.7:
only 'primary' (blue), 'success' (green) and 'danger' (red) are real values —
anything else is omitted so the client falls back to its default button look.

Every renderer below is written as a small "block" so swapping in the native
Rich Message classes later is a one-function change.

Deploy: Render (webhook) or anywhere (long polling).

Requirements: python-telegram-bot>=22.7 (needed for InlineKeyboardButton.style)
"""

from __future__ import annotations

import asyncio
import html
import io
import json
import logging
import os
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

import aiohttp
from telegram import (
    BotCommand,
    BotCommandScopeAllGroupChats,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile,
    LinkPreviewOptions,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    AIORateLimiter,
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8748100209:AAECZA5WYFZ-xId0XgIFl4Ct4dyza8pWOH8").strip()
BOT_NAME = os.environ.get("BOT_NAME", "OSINT Lookup")

SEARCH_API_URL = os.environ.get("SEARCH_API_URL", "https://icmr-and-hitek-95hp.onrender.com/search?q={q}").strip()
API_HEADERS_RAW = os.environ.get("API_HEADERS", "").strip()

PAGE_SIZE = max(1, min(10, int(os.environ.get("PAGE_SIZE", "4"))))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "25"))
COOLDOWN_SECONDS = float(os.environ.get("COOLDOWN_SECONDS", "3"))
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "50"))  # 0 disables the limit

ADMIN_IDS = {
    int(x) for x in re.split(r"[,\s]+", os.environ.get("ADMIN_IDS", "6846112069, 7910994767")) if x.strip().isdigit()
}

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://numinfo-bot-w2qp.onrender.com").strip().rstrip("/")
PORT = int(os.environ.get("PORT", "10000"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "") or secrets.token_urlsafe(24)

CACHE_TTL = 3600
MAX_MESSAGE = 3900

logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", level=logging.INFO
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("osint-bot")

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN environment variable is required")


def _parse_headers() -> dict[str, str]:
    if not API_HEADERS_RAW:
        return {}
    try:
        return {str(k): str(v) for k, v in json.loads(API_HEADERS_RAW).items()}
    except Exception:  # noqa: BLE001
        log.warning("API_HEADERS is not valid JSON — ignored")
        return {}


API_HEADERS = _parse_headers()


def is_admin(user_id: int | None) -> bool:
    return bool(user_id) and (not ADMIN_IDS or user_id in ADMIN_IDS) if ADMIN_IDS else False


# --------------------------------------------------------------------------- #
# Runtime state                                                                #
# --------------------------------------------------------------------------- #


@dataclass
class SearchResult:
    query: str
    items: list[Any]
    meta: dict[str, Any]
    raw: Any
    elapsed_ms: int
    created_at: float = field(default_factory=time.time)


CACHE: dict[str, SearchResult] = {}
REQUESTED_BY: dict[str, str] = {}  # cache key -> display name, for group "Requested by" line
HISTORY: dict[int, deque[str]] = {}
LAST_CALL: dict[int, float] = {}
USAGE: dict[int, tuple[str, int]] = {}
RUNTIME: dict[str, Any] = {"api_url": SEARCH_API_URL}
STATS = {"searches": 0, "hits": 0, "errors": 0, "started": time.time(), "users": set()}


def cache_put(result: SearchResult) -> str:
    now = time.time()
    for key in [k for k, v in CACHE.items() if now - v.created_at > CACHE_TTL]:
        CACHE.pop(key, None)
        REQUESTED_BY.pop(key, None)
    key = secrets.token_hex(5)
    CACHE[key] = result
    return key


def remember(user_id: int, query: str) -> None:
    bucket = HISTORY.setdefault(user_id, deque(maxlen=8))
    if query in bucket:
        bucket.remove(query)
    bucket.appendleft(query)


def quota_check(user_id: int) -> str | None:
    """Return an error string when the user must wait, else None."""
    now = time.time()
    last = LAST_CALL.get(user_id, 0.0)
    if now - last < COOLDOWN_SECONDS:
        return f"⏳ Easy there — try again in {COOLDOWN_SECONDS - (now - last):.0f}s."
    if DAILY_LIMIT and not is_admin(user_id):
        today = time.strftime("%Y-%m-%d")
        day, count = USAGE.get(user_id, (today, 0))
        if day != today:
            day, count = today, 0
        if count >= DAILY_LIMIT:
            return f"🚦 Daily limit reached ({DAILY_LIMIT} lookups). Resets at midnight UTC."
        USAGE[user_id] = (day, count + 1)
    LAST_CALL[user_id] = now
    return None


# --------------------------------------------------------------------------- #
# Rich block primitives                                                        #
# --------------------------------------------------------------------------- #


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False)


def block_expandable_quote(body: str) -> str:
    """RichBlockExpandableBlockQuotation equivalent."""
    return f"<blockquote expandable>{body}</blockquote>"


def block_code(payload: str, language: str = "json") -> str:
    return f'<pre><code class="language-{language}">{esc(payload)}</code></pre>'


def block_table(pairs: list[tuple[str, str]], is_compact: bool = True) -> str:
    """RichBlockTable equivalent. is_compact mirrors the 10.3 field."""
    if not pairs:
        return ""
    if is_compact:
        return "\n".join(f"   ▪️ <b>{esc(k)}</b> · {esc(v)}" for k, v in pairs)
    width = min(18, max(len(k) for k, _ in pairs))
    rows = "\n".join(f"{k[:width].ljust(width)} │ {v}" for k, v in pairs)
    return f"<pre>{esc(rows)}</pre>"


def rich_buttons(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    """RichBlockButtons equivalent."""
    return InlineKeyboardMarkup([row for row in rows if row])


# --------------------------------------------------------------------------- #
# Native button colors (Bot API 9.4, Feb 9 2026)
# --------------------------------------------------------------------------- #
# InlineKeyboardButton got a real `style` field: 'primary' (blue),
# 'success' (green) and 'danger' (red). That's the FULL set Telegram supports —
# there is no 'warning'/'ghost'/etc. Any style outside VALID_STYLES is simply
# omitted, so the client renders its normal default-colored button instead of
# erroring out. Requires python-telegram-bot >= 22.7.
VALID_STYLES = {"primary", "success", "danger"}

# --------------------------------------------------------------------------- #
# Premium/custom emoji icons on buttons (Bot API 9.4, icon_custom_emoji_id)
# --------------------------------------------------------------------------- #
# IMPORTANT — this field only actually renders if EITHER:
#   1. this bot account owns a Fragment-purchased collectible username, or
#   2. the account that created this bot in @BotFather has Telegram Premium,
#      and only for messages sent directly to private/group/supergroup chats.
# If neither is true, Telegram silently ignores the field — the button just
# shows plain text, no error. "Animated" isn't a setting: if the emoji ID you
# put here belongs to an animated custom emoji, it plays automatically;
# static ones just show a static icon.
#
# Telegram doesn't expose these IDs in any normal client UI. Get them by
# sending the emoji to this bot and running /emojiid on that message (see the
# cmd_emoji_id handler below) — it reads the numeric ID out of the message's
# entities and prints it back to you, ready to paste in here.
#
# Fill these in with real IDs once you have them; leave a slot as None (or
# omit it) to skip the icon for that button.
CUSTOM_EMOJI: dict[str, str | None] = {
    "search": "5319104996510286116",  # used on the "Start a lookup" CTA
    "usage": None,
    "help": None,
    "export": None,
    "save": None,
    "close": None,
    "menu": None,
    "record": None,
}


def tg_emoji(emoji_id: str, fallback: str = "🆔") -> str:
    """Inline custom-emoji tag for use INSIDE message text (not buttons).

    Same eligibility rules as icon_custom_emoji_id apply: only renders if
    this bot has a Fragment username or its owner has Premium, and only in
    messages the bot sends directly (HTML parse mode required). `fallback`
    is what clients without custom-emoji support show instead, so always
    pick a fallback that's a close visual match to the real emoji.
    """
    return f'<tg-emoji emoji-id="{esc(emoji_id)}">{esc(fallback)}</tg-emoji>'


def btn(
    text: str,
    data: str,
    style: str = "primary",
    icon: str | None = None,
) -> InlineKeyboardButton:
    """RichMessageButton equivalent (callback button, styled + optional icon).

    Defaults to 'primary' (blue) rather than leaving buttons uncolored, so
    the keyboard reads as an intentional, fully-styled grid rather than a
    mix of colored and flat-gray buttons. Pass 'success' or 'danger'
    explicitly to override for confirm/destructive actions.

    `icon` should be a custom_emoji_id string (see CUSTOM_EMOJI above).
    Omitted/None means no icon — safe default until real IDs are configured.
    """
    kwargs: dict[str, Any] = {}
    if style in VALID_STYLES:
        kwargs["style"] = style
    if icon:
        kwargs["icon_custom_emoji_id"] = icon
    return InlineKeyboardButton(text, callback_data=data, **kwargs)


def link_btn(
    text: str,
    url: str,
    style: str = "primary",
    icon: str | None = None,
) -> InlineKeyboardButton:
    """RichTextButton equivalent (URL button, styled + optional icon)."""
    kwargs: dict[str, Any] = {}
    if style in VALID_STYLES:
        kwargs["style"] = style
    if icon:
        kwargs["icon_custom_emoji_id"] = icon
    return InlineKeyboardButton(text, url=url, **kwargs)


# --------------------------------------------------------------------------- #
# Generic JSON understanding                                                   #
# --------------------------------------------------------------------------- #

TITLE_KEYS = (
    "title", "name", "full_name", "display_name", "username", "handle", "email",
    "phone", "number", "domain", "ip", "address", "label", "heading", "subject",
)
BODY_KEYS = (
    "description", "summary", "snippet", "text", "content", "body", "abstract",
    "excerpt", "overview", "bio", "about", "notes", "detail", "details",
)
URL_KEYS = ("url", "link", "href", "permalink", "profile", "profile_url", "web_url", "source_url")
ARRAY_KEYS = (
    "results", "items", "data", "hits", "docs", "records", "list", "entries",
    "rows", "matches", "accounts", "profiles", "leaks", "breaches", "values",
    "response", "payload",
)
SENSITIVE_HINTS = ("password", "passwd", "pass", "hash", "token", "secret", "otp", "pin", "cvv")
NOISE_KEYS = {"_id", "__typename", "_index", "_score", "_type"}

MARKERS = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")


def humanize_key(key: str) -> str:
    key = re.sub(r"[_\-.]+", " ", str(key)).strip()
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key)
    return key[:1].upper() + key[1:]


def shorten(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", str(text))


def is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def mask_if_sensitive(key: str, value: str) -> str:
    if any(hint in str(key).lower() for hint in SENSITIVE_HINTS) and len(value) > 4:
        return value[:2] + "•" * min(10, len(value) - 4) + value[-2:]
    return value


def format_scalar(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "✅ Yes" if value else "❌ No"
    if isinstance(value, int) and abs(value) >= 1000:
        return f"{value:,}"
    if isinstance(value, (int, float)):
        return str(value)
    return shorten(strip_tags(value), 220)


def pick(obj: dict[str, Any], keys: Iterable[str]) -> tuple[str | None, Any]:
    lowered = {str(k).lower(): k for k in obj}
    for candidate in keys:
        real = lowered.get(candidate)
        if real is not None and obj[real] not in (None, "", [], {}):
            return real, obj[real]
    return None, None


def extract_items(payload: Any, depth: int = 0) -> tuple[list[Any], dict[str, Any]]:
    if isinstance(payload, list):
        return payload, {}
    if not isinstance(payload, dict) or depth > 3:
        return ([payload] if payload not in (None, "") else []), {}

    meta = {k: v for k, v in payload.items() if is_scalar(v) and v not in (None, "")}

    for candidate in ARRAY_KEYS:
        for real_key in payload:
            if str(real_key).lower() != candidate:
                continue
            value = payload[real_key]
            if isinstance(value, list):
                return value, meta
            if isinstance(value, dict):
                nested, nested_meta = extract_items(value, depth + 1)
                if nested:
                    return nested, {**meta, **nested_meta}

    for value in payload.values():
        if isinstance(value, list) and value:
            return value, meta
    for value in payload.values():
        if isinstance(value, dict):
            nested, nested_meta = extract_items(value, depth + 1)
            if nested:
                return nested, {**meta, **nested_meta}
    return ([payload] if payload else []), meta


def flatten(obj: Any, prefix: str = "", out: list[tuple[str, Any]] | None = None, depth: int = 0):
    out = [] if out is None else out
    if depth > 3:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in NOISE_KEYS:
                continue
            label = f"{prefix}{humanize_key(key)}"
            if is_scalar(value):
                if value not in (None, ""):
                    out.append((label, value))
            elif isinstance(value, list) and all(is_scalar(v) for v in value):
                if value:
                    out.append((label, ", ".join(format_scalar(v) for v in value[:8])))
            else:
                flatten(value, f"{label} › ", out, depth + 1)
    elif isinstance(obj, list):
        for i, value in enumerate(obj[:8]):
            flatten(value, f"{prefix}{i + 1} › ", out, depth + 1)
    elif obj not in (None, ""):
        out.append((prefix.rstrip(" ›") or "Value", obj))
    return out


def item_title(item: Any, index: int) -> str:
    if not isinstance(item, dict):
        return shorten(strip_tags(item), 64) or f"Record {index + 1}"
    _, value = pick(item, TITLE_KEYS)
    if value is not None and is_scalar(value):
        return shorten(strip_tags(value), 64)
    for key, value in item.items():
        if isinstance(value, str) and 1 < len(value) < 120 and str(key).lower() not in NOISE_KEYS:
            return shorten(strip_tags(value), 64)
    return f"Record {index + 1}"


def item_url(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    _, value = pick(item, URL_KEYS)
    if isinstance(value, str) and value.startswith(("http://", "https://", "tg://")):
        return value
    return None


# --------------------------------------------------------------------------- #
# Rich renderers                                                               #
# --------------------------------------------------------------------------- #


def render_card(item: Any, index: int, compact: bool) -> str:
    marker = MARKERS[index % len(MARKERS)]
    title = esc(item_title(item, index))
    lines = [f"{marker} <b>{title}</b>"]

    if not isinstance(item, dict):
        return "\n".join(lines)

    used: set[str] = set()
    title_key, _ = pick(item, TITLE_KEYS)
    if title_key:
        used.add(title_key)

    body_key, body = pick(item, BODY_KEYS)
    if body_key and isinstance(body, str):
        used.add(body_key)
        lines.append(f"<i>{esc(shorten(strip_tags(body), 150 if compact else 420))}</i>")

    pairs: list[tuple[str, str]] = []
    budget = 4 if compact else 18
    for key, value in flatten({k: v for k, v in item.items() if k not in used}):
        if len(pairs) >= budget:
            break
        pairs.append((key, mask_if_sensitive(key, format_scalar(value))))

    table = block_table(pairs, is_compact=True)
    if table:
        lines.append(table)
    return "\n".join(lines)


def render_results(key: str, result: SearchResult, page: int) -> tuple[str, InlineKeyboardMarkup]:
    total = len(result.items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    start = page * PAGE_SIZE
    chunk = result.items[start : start + PAGE_SIZE]

    head = [
        "🛰 <b>LOOKUP COMPLETE</b>",
        f"🎯 Target · <code>{esc(shorten(result.query, 64))}</code>",
        f"📦 Records · <code>{total}</code>   📑 Page · <code>{page + 1}/{pages}</code>"
        f"   ⚡ <code>{result.elapsed_ms} ms</code>",
    ]
    requester = REQUESTED_BY.get(key)
    if requester:
        head.append(f"🙋 Requested by <b>{esc(requester)}</b>")
    extra = [
        f"{humanize_key(k)}: {format_scalar(v)}"
        for k, v in list(result.meta.items())[:3]
        if str(k).lower() not in {"query", "q"}
    ]
    if extra:
        head.append(f"<i>{esc(' · '.join(extra))}</i>")

    body = "\n\n".join(render_card(item, start + i, True) for i, item in enumerate(chunk))
    text = "\n".join(head) + "\n\n" + "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n\n" + (body or "<i>Empty page.</i>")
    if len(text) > MAX_MESSAGE:
        text = text[: MAX_MESSAGE - 1] + "…"

    rows: list[list[InlineKeyboardButton]] = []
    opens = [
        btn(MARKERS[(start + i) % len(MARKERS)], f"d|{key}|{start + i}") for i in range(len(chunk))
    ]
    if opens:
        rows.append(opens)

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(btn("⏮", f"p|{key}|0"))
        nav.append(btn("◀️", f"p|{key}|{page - 1}", "primary"))
    nav.append(btn(f"· {page + 1}/{pages} ·", "noop"))
    if page < pages - 1:
        nav.append(btn("▶️", f"p|{key}|{page + 1}", "primary"))
        nav.append(btn("⏭", f"p|{key}|{pages - 1}"))
    rows.append(nav)

    rows.append([
        btn("🔁 Re-run", f"r|{key}|{page}", "primary"),
        btn("📥 Export", f"x|{key}|{page}", "success", icon=CUSTOM_EMOJI["export"]),
    ])
    rows.append([
        btn("🏠 New lookup", "menu|0|0", icon=CUSTOM_EMOJI["menu"]),
        btn("✖️ Close", "close|0|0", "danger", icon=CUSTOM_EMOJI["close"]),
    ])
    return text, rich_buttons(rows)


def render_detail(key: str, result: SearchResult, index: int) -> tuple[str, InlineKeyboardMarkup]:
    index = max(0, min(index, len(result.items) - 1))
    item = result.items[index]
    page = index // PAGE_SIZE

    pairs = [
        (k, mask_if_sensitive(k, format_scalar(v)))
        for k, v in flatten(item if isinstance(item, dict) else {"value": item})
    ]
    text = (
        f"🗂 <b>RECORD {index + 1}/{len(result.items)}</b>\n"
        f"🎯 <code>{esc(shorten(result.query, 60))}</code>\n\n"
        f"{render_card(item, index, False)}\n\n"
        f"<b>All fields</b>\n{block_table(pairs[:40], is_compact=True) or '<i>—</i>'}\n\n"
        + block_expandable_quote(
            block_code(shorten(json.dumps(item, indent=2, ensure_ascii=False, default=str), 2200))
        )
    )
    if len(text) > MAX_MESSAGE:
        text = text[: MAX_MESSAGE - 30] + "…</code></pre></blockquote>"

    nav: list[InlineKeyboardButton] = []
    if index > 0:
        nav.append(btn("⬅️ Prev", f"d|{key}|{index - 1}", "primary"))
    nav.append(btn(f"· {index + 1}/{len(result.items)} ·", "noop"))
    if index < len(result.items) - 1:
        nav.append(btn("Next ➡️", f"d|{key}|{index + 1}", "primary"))

    actions = [btn("💾 Save record", f"f|{key}|{index}", "success", icon=CUSTOM_EMOJI["save"])]
    url = item_url(item)
    if url:
        actions.insert(0, link_btn("🔗 Open source", url, "primary"))

    return text, rich_buttons([nav, actions, [btn("◀️ Back to results", f"p|{key}|{page}")]])


def render_menu(user_id: int) -> tuple[str, InlineKeyboardMarkup]:
    recent = list(HISTORY.get(user_id, []))[:4]
    text = (
        f"{tg_emoji(CUSTOM_EMOJI['search'], '🕵️') if CUSTOM_EMOJI['search'] else '🕵️'} "
        f"<b>{esc(BOT_NAME)}</b>\n"
        "<i>Open-source intelligence lookups, straight in Telegram.</i>\n\n"
        "Send any <b>name, username, email, phone, domain or IP</b> — "
        "or tap a button below.\n\n"
        "<b>How it works</b>\n"
        "🔎 One query, matched across the connected intelligence source\n"
        "🗂 Every hit becomes a readable record card\n"
        "📑 Browse hits with the arrows, open any record in full\n"
        "📥 Export a record or a whole result set as a file\n"
        "🔐 Sensitive-looking fields are masked automatically\n\n"
        + block_expandable_quote(
            "<b>Fair use</b>\nThis bot queries publicly available data only. "
            "Use it for research, verification and security work — never for "
            "harassment, stalking or anything unlawful. Lookups are rate limited."
        )
    )
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(
            "🔍 Start a lookup",
            switch_inline_query_current_chat="",
            style="success",
            **({"icon_custom_emoji_id": CUSTOM_EMOJI["search"]} if CUSTOM_EMOJI["search"] else {}),
        )],
    ]
    for query in recent:
        rows.append(
            [btn(f"🕘 {shorten(query, 26)}", f"h|{abs(hash(query)) % 10**8}|0", "primary")]
        )
        RUNTIME.setdefault("history_map", {})[str(abs(hash(query)) % 10**8)] = query
    rows.append([
        btn("📊 My usage", "usage|0|0", "primary", icon=CUSTOM_EMOJI["usage"]),
        btn("❓ Help", "help|0|0", icon=CUSTOM_EMOJI["help"]),
    ])
    return text, rich_buttons(rows)


HELP_TEXT = (
    "❓ <b>Help</b>\n\n"
    "<b>Searching</b>\n"
    "In a private chat: just send your query as a normal message, or use "
    "<code>/search &lt;query&gt;</code>.\n"
    "In a group: use <code>/num &lt;query&gt;</code> — it's the only command "
    "the bot responds to there.\n"
    "Works with names, usernames, emails, phone numbers, domains and IPs.\n\n"
    "<b>Reading results</b>\n"
    "▪️ Numbered buttons open a record in full\n"
    "▪️ Arrows move between pages and records\n"
    "▪️ 📥 exports what you are viewing as a file\n"
    "▪️ 🔁 runs the same query again for fresh data\n\n"
    "<b>Commands</b>\n"
    "<code>/search</code> — run a lookup (private chats)\n"
    "<code>/num</code> — run a lookup (groups)\n"
    "<code>/recent</code> — your last queries\n"
    "<code>/menu</code> — main menu\n"
    "<code>/usage</code> — your remaining lookups\n"
    "<code>/help</code> — this page\n"
    "<code>/emojiid</code> — admin: extract a custom emoji's ID (reply to a "
    "message containing it)"
)


# --------------------------------------------------------------------------- #
# Search engine                                                                #
# --------------------------------------------------------------------------- #


class ApiError(Exception):
    pass


class NotConfigured(Exception):
    pass


def build_url(query: str) -> str:
    base = RUNTIME.get("api_url") or ""
    if not base:
        raise NotConfigured
    from urllib.parse import quote

    encoded = quote(query, safe="")
    if "{q}" in base:
        return base.replace("{q}", encoded)
    if base.endswith(("q=", "query=", "search=", "term=", "s=")):
        return base + encoded
    return f"{base}{'&' if '?' in base else '?'}q={encoded}"


_SESSION: aiohttp.ClientSession | None = None
QUERY_CACHE: dict[str, SearchResult] = {}
QUERY_TTL = float(os.environ.get("QUERY_CACHE_TTL", "90"))
INFLIGHT: dict[str, asyncio.Task] = {}


async def get_session() -> aiohttp.ClientSession:
    """One keep-alive pooled session for the whole process (much faster)."""
    global _SESSION
    if _SESSION is None or _SESSION.closed:
        _SESSION = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=8),
            connector=aiohttp.TCPConnector(
                limit=100, limit_per_host=30, ttl_dns_cache=300, keepalive_timeout=60
            ),
            headers={"Accept": "application/json", "User-Agent": "osint-bot/1.0", **API_HEADERS},
        )
    return _SESSION


async def search_cached(query: str) -> SearchResult:
    """Deduplicate identical concurrent lookups and serve hot repeats instantly."""
    key = query.strip().lower()
    hit = QUERY_CACHE.get(key)
    if hit and time.time() - hit.created_at < QUERY_TTL:
        return hit
    task = INFLIGHT.get(key)
    if task is None:
        task = asyncio.create_task(run_search(query))
        INFLIGHT[key] = task
        try:
            result = await task
        finally:
            INFLIGHT.pop(key, None)
        QUERY_CACHE[key] = result
        if len(QUERY_CACHE) > 500:
            for stale in sorted(QUERY_CACHE, key=lambda k: QUERY_CACHE[k].created_at)[:100]:
                QUERY_CACHE.pop(stale, None)
        return result
    return await asyncio.shield(task)


async def run_search(query: str) -> SearchResult:
    url = build_url(query)
    started = time.perf_counter()
    headers = {"Accept": "application/json", "User-Agent": "osint-bot/1.0", **API_HEADERS}
    try:
        session = await get_session()
        async with session.get(url, headers=headers) as response:
            body = await response.text()
            if response.status == 404:
                payload: Any = {}
            elif response.status >= 400:
                log.error("source error %s: %s", response.status, body[:400])
                raise ApiError("The intelligence source rejected that lookup. Try again shortly.")
            else:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    payload = {"response": shorten(body, 2000)}
    except asyncio.TimeoutError as exc:
        raise ApiError("The source timed out. Please try again in a moment.") from exc
    except aiohttp.ClientError as exc:
        log.error("source unreachable: %s", exc)
        raise ApiError("The intelligence source is unreachable right now.") from exc

    elapsed = int((time.perf_counter() - started) * 1000)
    items, meta = extract_items(payload)
    meta.pop("q", None)
    return SearchResult(query=query, items=items, meta=meta, raw=payload, elapsed_ms=elapsed)


# --------------------------------------------------------------------------- #
# Handlers                                                                     #
# --------------------------------------------------------------------------- #


async def send_menu(update: Update) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    text, markup = render_menu(user_id)
    await update.effective_message.reply_html(
        text, reply_markup=markup, link_preview_options=LinkPreviewOptions(is_disabled=True)
    )


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user:
        STATS["users"].add(update.effective_user.id)
    await send_menu(update)


async def cmd_menu(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await send_menu(update)


async def cmd_help(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_html(
        HELP_TEXT, reply_markup=rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]])
    )


async def cmd_usage(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    day, count = USAGE.get(user_id, (time.strftime("%Y-%m-%d"), 0))
    left = "unlimited" if not DAILY_LIMIT or is_admin(user_id) else str(max(0, DAILY_LIMIT - count))
    await update.effective_message.reply_html(
        "📊 <b>Your usage</b>\n"
        f"▪️ Lookups today · <code>{count}</code>\n"
        f"▪️ Remaining · <code>{left}</code>\n"
        f"▪️ Cooldown · <code>{COOLDOWN_SECONDS:g}s</code>"
    )


async def cmd_emoji_id(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin utility: send/forward a message containing a custom emoji, then
    reply to it with /emojiid (or just include the emoji in the same message)
    to read back its custom_emoji_id — the value CUSTOM_EMOJI needs.

    Telegram doesn't surface this ID anywhere in the normal app UI, so this
    is the practical way to collect it for your Premium/animated emoji.
    """
    user_id = update.effective_user.id if update.effective_user else 0
    if not is_admin(user_id):
        await update.effective_message.reply_html("🚫 Not available.")
        return

    target = update.effective_message.reply_to_message or update.effective_message
    entities = list(target.entities or []) + list(target.caption_entities or [])
    found = [e.custom_emoji_id for e in entities if e.type == "custom_emoji" and e.custom_emoji_id]

    if not found:
        await update.effective_message.reply_html(
            "🔎 No custom emoji found there.\n"
            "Send a message containing the custom/Premium emoji, or reply to "
            "one that has it, then run <code>/emojiid</code> again."
        )
        return

    lines = "\n".join(f"<code>{esc(cid)}</code>" for cid in found)
    await update.effective_message.reply_html(
        f"🆔 <b>custom_emoji_id found</b>\n{lines}\n\n"
        "Paste this into <code>CUSTOM_EMOJI</code> at the top of the file."
    )


async def cmd_recent(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    recent = list(HISTORY.get(user_id, []))
    if not recent:
        await update.effective_message.reply_html("🕘 No lookups yet.")
        return
    rows = []
    for query in recent:
        token = str(abs(hash(query)) % 10**8)
        RUNTIME.setdefault("history_map", {})[token] = query
        rows.append([btn(f"🕘 {shorten(query, 28)}", f"h|{token}|0", "primary")])
    await update.effective_message.reply_html(
        "🕘 <b>Recent lookups</b>", reply_markup=rich_buttons(rows)
    )


# ---- admin ---------------------------------------------------------------- #


async def cmd_connect(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    if not is_admin(user_id):
        await update.effective_message.reply_html("🚫 Not available.")
        return
    if not context.args:
        await update.effective_message.reply_html(
            "Usage: <code>/connect https://source.example/search?q={q}</code>"
        )
        return
    url = context.args[0].strip()
    if not url.startswith(("http://", "https://")):
        await update.effective_message.reply_html("🚫 That is not a valid URL.")
        return
    RUNTIME["api_url"] = url
    try:
        await update.effective_message.delete()
    except Exception:  # noqa: BLE001
        pass
    await context.bot.send_message(
        user_id,
        "✅ <b>Source connected.</b> Your message was deleted so the endpoint stays private.",
        parse_mode=ParseMode.HTML,
    )


async def cmd_source(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    if not is_admin(user_id):
        await update.effective_message.reply_html("🚫 Not available.")
        return
    url = RUNTIME.get("api_url") or "not connected"
    await update.effective_message.reply_html(
        "🔐 <b>Connected source</b> (admin only)\n"
        + block_expandable_quote(f"<code>{esc(url)}</code>")
    )


async def cmd_admin(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id if update.effective_user else 0
    if not is_admin(user_id):
        await update.effective_message.reply_html("🚫 Not available.")
        return
    uptime = int(time.time() - STATS["started"])
    hours, rest = divmod(uptime, 3600)
    minutes, seconds = divmod(rest, 60)
    await update.effective_message.reply_html(
        "🛠 <b>Admin panel</b>\n"
        + block_table(
            [
                ("Uptime", f"{hours}h {minutes}m {seconds}s"),
                ("Lookups", str(STATS["searches"])),
                ("With hits", str(STATS["hits"])),
                ("Failures", str(STATS["errors"])),
                ("Users", str(len(STATS["users"]))),
                ("Cached sets", str(len(CACHE))),
                ("Source", "connected" if RUNTIME.get("api_url") else "NOT connected"),
            ]
        )
        + "\n\n<code>/connect &lt;url&gt;</code> · <code>/source</code>"
    )


# ---- searching ------------------------------------------------------------ #


def is_group(update: Update) -> bool:
    chat = update.effective_chat
    return bool(chat) and chat.type in ("group", "supergroup")


async def do_search(update: Update, query: str, raw_output: bool = False) -> None:
    message = update.effective_message
    user_id = update.effective_user.id if update.effective_user else 0
    query = (query or "").strip()

    if len(query) < 10:
        await message.reply_html("🔎 Please provide at least 10 characters.")
        return
    if len(query) > 200:
        query = query[:200]

    blocked = quota_check(user_id)
    if blocked:
        await message.reply_html(blocked)
        return

    STATS["users"].add(user_id)
    group = is_group(update)
    typing = asyncio.create_task(message.chat.send_action(ChatAction.TYPING))
    placeholder = await message.reply_html(
        f"🛰 <b>Scanning</b> for <code>{esc(shorten(query, 60))}</code>…"
    )

    try:
        result = await search_cached(query)
    except NotConfigured:
        await placeholder.edit_text(
            "🔌 <b>No source connected yet.</b>\nThe operator has to connect one before "
            "lookups can run.",
            parse_mode=ParseMode.HTML,
        )
        return
    except ApiError as exc:
        STATS["errors"] += 1
        await placeholder.edit_text(f"⚠️ {exc}", parse_mode=ParseMode.HTML)
        return
    except Exception:  # noqa: BLE001
        STATS["errors"] += 1
        log.exception("lookup failed")
        await placeholder.edit_text(
            "💥 Something went wrong on our side. Please try again.", parse_mode=ParseMode.HTML
        )
        return

    STATS["searches"] += 1
    remember(user_id, query)

    if not result.items:
        if raw_output:
            # No data found: simple text without buttons
            await placeholder.edit_text("No data found.", parse_mode=ParseMode.HTML)
        else:
            await placeholder.edit_text(
                f"🫥 <b>No records</b> for <code>{esc(shorten(query, 60))}</code>.\n"
                "<i>Try a different spelling, a username, or a full email address.</i>",
                parse_mode=ParseMode.HTML,
                reply_markup=rich_buttons([[btn("🔁 Try again", "menu|0|0", "primary")]]),
            )
        return

    STATS["hits"] += 1
    if not typing.done():
        typing.cancel()

    if raw_output:
        # Build summary line: "🛰 LOOKUP COMPLETE 🎯 Target {query} 📦 Records · {len} 📑 Page · 1/1 ⚡️ {elapsed} ms 🙋 Requested by {name}"
        summary_parts = [
            "🛰 LOOKUP COMPLETE",
            f"🎯 Target <code>{esc(shorten(result.query, 64))}</code>",
            f"📦 Records · <code>{len(result.items)}</code>",
            "📑 Page · <code>1/1</code>",
            f"⚡️ <code>{result.elapsed_ms} ms</code>",
        ]
        # Add "Requested by" if applicable
        requester = None
        # We need to add it only if group and we have the user
        # But the key is not available here because we don't cache for raw_output? Actually we don't cache for raw_output? We can either not cache or still cache but we don't have a key yet.
        # For raw_output, we don't need the cache key; we can directly add the user's name if group.
        if group and update.effective_user:
            requester = update.effective_user.full_name or (
                f"@{update.effective_user.username}" if update.effective_user.username else "Someone"
            )
        if requester:
            summary_parts.append(f"🙋 Requested by <b>{esc(requester)}</b>")
        summary = "\n".join(summary_parts)

        # Full JSON from result.raw
        json_pretty = json.dumps(result.raw, indent=2, ensure_ascii=False, default=str)
        # Truncate if too long? We'll let Telegram truncate if it's too long, but we can keep it under MAX_MESSAGE.
        if len(summary) + len(json_pretty) + 100 > MAX_MESSAGE:
            json_pretty = json_pretty[:MAX_MESSAGE - len(summary) - 100] + "…"
        full_text = f"{summary}\n\n{block_code(json_pretty)}"
        await placeholder.edit_text(
            full_text,
            parse_mode=ParseMode.HTML,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
            # No reply_markup
        )
        return

    # Normal (non-raw) flow: use cached key and render interactive cards
    key = cache_put(result)
    if group and update.effective_user:
        REQUESTED_BY[key] = update.effective_user.full_name or (
            f"@{update.effective_user.username}" if update.effective_user.username else "Someone"
        )
    text, markup = render_results(key, result, 0)
    await placeholder.edit_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=markup,
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await do_search(update, " ".join(context.args or []), raw_output=False)


async def cmd_num(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Group-safe search command: /num <query>.

    Telegram's default group privacy mode only delivers *commands* to bots,
    not plain text or @mentions, unless the bot owner disables it via
    @BotFather -> /setprivacy. Rather than depend on that setting, /num
    always reaches the bot in any group, so it's the one thing guaranteed
    to work there.
    """
    await do_search(update, " ".join(context.args or []), raw_output=True)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if is_group(update):
        # Intentionally inert in groups: only /num triggers a search there.
        # No plain-text, @mention, or reply auto-search, to keep the bot
        # quiet unless explicitly asked via the command.
        return
    await do_search(update, update.effective_message.text or "", raw_output=False)


# ---- callbacks ------------------------------------------------------------ #


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    data = query.data or ""
    user_id = query.from_user.id if query.from_user else 0

    if data == "noop":
        await query.answer()
        return

    try:
        action, key, raw_index = data.split("|", 2)
        index = int(raw_index)
    except ValueError:
        await query.answer("Unsupported button.")
        return

    if action == "close":
        await query.answer("Closed")
        try:
            await query.message.delete()
        except Exception:  # noqa: BLE001
            pass
        return

    if action == "menu":
        await query.answer()
        text, markup = render_menu(user_id)
        await _safe_edit(query, text, markup)
        return

    if action == "help":
        await query.answer()
        await _safe_edit(query, HELP_TEXT, rich_buttons([[btn("🏠 Menu", "menu|0|0")]]))
        return

    if action == "usage":
        day, count = USAGE.get(user_id, (time.strftime("%Y-%m-%d"), 0))
        left = "∞" if not DAILY_LIMIT or is_admin(user_id) else str(max(0, DAILY_LIMIT - count))
        await query.answer(f"Today: {count} lookups · remaining: {left}", show_alert=True)
        return

    if action == "h":
        stored = RUNTIME.get("history_map", {}).get(key)
        await query.answer("Re-running…" if stored else "That query expired.")
        if stored:
            await do_search(update, stored, raw_output=False)  # history recall from menu should use normal UI
        return

    result = CACHE.get(key)
    if not result:
        await query.answer("This result set expired — run the lookup again.", show_alert=True)
        return

    if action == "r":
        if blocked := quota_check(user_id):
            await query.answer(blocked, show_alert=True)
            return
        await query.answer("Refreshing…")
        try:
            result = await run_search(result.query)
        except Exception as exc:  # noqa: BLE001
            await query.answer(str(exc)[:190] or "Refresh failed.", show_alert=True)
            return
        CACHE[key] = result
        action = "p"

    if action in {"x", "f"}:
        payload = result.raw if action == "x" else result.items[min(index, len(result.items) - 1)]
        blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", result.query)[:40] or "lookup"
        name = f"{safe}{'' if action == 'x' else f'_record_{index + 1}'}.json"
        await query.answer("Preparing file…")
        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=InputFile(io.BytesIO(blob), filename=name),
            caption=f"📥 <b>{esc(shorten(result.query, 50))}</b> · "
            f"{'full result set' if action == 'x' else f'record {index + 1}'}",
            parse_mode=ParseMode.HTML,
        )
        return

    if action == "p":
        text, markup = render_results(key, result, index)
    elif action == "d":
        text, markup = render_detail(key, result, index)
    else:
        await query.answer("Unsupported button.")
        return

    await query.answer()
    await _safe_edit(query, text, markup)


async def _safe_edit(query, text: str, markup: InlineKeyboardMarkup) -> None:
    try:
        await query.edit_message_text(
            text,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            log.warning("edit failed: %s", exc)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("handler error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_html("💥 Something went wrong. Please try again.")
        except Exception:  # noqa: BLE001
            pass


async def post_init(app: Application) -> None:
    await app.bot.set_my_commands(
        [
            BotCommand("start", "Open the main menu"),
            BotCommand("search", "Run an OSINT lookup"),
            BotCommand("num", "Run an OSINT lookup"),
            BotCommand("recent", "Your recent lookups"),
            BotCommand("usage", "Your remaining lookups"),
            BotCommand("menu", "Main menu"),
            BotCommand("help", "How to use this bot"),
        ]
    )
    # Groups only ever have /num — every other command is private-chat only,
    # so this is the entire command list Telegram shows group members.
    await app.bot.set_my_commands(
        [BotCommand("num", "Run an OSINT lookup")],
        scope=BotCommandScopeAllGroupChats(),
    )
    for admin_id in ADMIN_IDS:
        try:
            await app.bot.set_my_commands(
                [
                    BotCommand("start", "Open the main menu"),
                    BotCommand("search", "Run an OSINT lookup"),
                    BotCommand("recent", "Your recent lookups"),
                    BotCommand("admin", "Admin panel"),
                    BotCommand("connect", "Connect the data source"),
                    BotCommand("source", "Show the connected source"),
                    BotCommand("emojiid", "Extract a custom emoji's ID"),
                    BotCommand("help", "How to use this bot"),
                ],
                scope=BotCommandScopeChat(admin_id),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("could not set admin commands for %s: %s", admin_id, exc)
    me = await app.bot.get_me()
    log.info("Online as @%s | source %s", me.username, "connected" if RUNTIME["api_url"] else "MISSING")


async def post_shutdown(_: Application) -> None:
    if _SESSION and not _SESSION.closed:
        await _SESSION.close()


def main() -> None:
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .rate_limiter(AIORateLimiter())
        .concurrent_updates(256)
        .connection_pool_size(256)
        .pool_timeout(20.0)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # Every command except /num is private-chat only. In groups the bot stays
    # completely silent for /start, /help, /menu, etc. — /num is the one and
    # only thing it responds to there.
    app.add_handler(CommandHandler("start", cmd_start, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("menu", cmd_menu, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("help", cmd_help, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("search", cmd_search, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("num", cmd_num))
    app.add_handler(CommandHandler("recent", cmd_recent, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("usage", cmd_usage, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("emojiid", cmd_emoji_id, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("admin", cmd_admin, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("connect", cmd_connect, filters=filters.ChatType.PRIVATE))
    app.add_handler(CommandHandler("source", cmd_source, filters=filters.ChatType.PRIVATE))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)

    if WEBHOOK_URL:
        log.info("webhook mode on :%s", PORT)
        app.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path="telegram",
            webhook_url=f"{WEBHOOK_URL}/telegram",
            secret_token=WEBHOOK_SECRET,
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )
    else:
        log.info("long-polling mode")
        app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
