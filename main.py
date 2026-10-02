"""
OSINT LOOKUP BOT - private, admin-only, group-allowlisted
=========================================================

Access model
------------
* Private chats : ONLY admins (ADMIN_IDS) get any response.
* Groups         : the bot works ONLY in groups on the allowlist. Everywhere
                   else it is completely silent.
* Adding the bot : added by an admin  -> group is authorized automatically
                   added by anyone else -> bot stays SILENT in 'pending' state, admins get
                   [Approve] / [Reject] buttons. No decision in PENDING_TTL_HOURS -> it leaves.
* Buttons        : in groups, result buttons only work for the person who ran
                   the search (and for admins).
* The data source URL is never shown to end users.

Admin commands (private chat with the bot)
------------------------------------------
/admin  /connect <url>  /source  /groups  /allowgroup [id]  /denygroup <id>
/emojiid

Environment variables
---------------------
BOT_TOKEN        required   (never hard-code it)
ADMIN_IDS        required   e.g. "111111,222222"
SEARCH_API_URL   optional   can also be set later with /connect
                            use {q} as the placeholder, e.g. https://x.y/s?q={q}
API_HEADERS      optional   JSON object of extra headers for the source
WEBHOOK_URL      optional   public https URL (falls back to RENDER_EXTERNAL_URL);
                            empty => long polling
WEBHOOK_SECRET   optional   random value is generated if empty
GROUPS_FILE      optional   default allowed_groups.json (use /data/... on a disk)
ALLOWED_GROUPS   optional   seed list "-100123,-100456" (applied on every start)
GROUP_MEMBERS_CAN_SEARCH  1 = any member of an allowed group may use /num,
                          0 = only admins          (default 1)
AUTO_APPROVE_ADMIN_ADDS   1 = group auto-allowed when an admin adds the bot
SILENT_DENY      1 = non-admins in DMs get no reply at all (default 0)
GROUP_RAW        1 = /num in groups answers with raw JSON (default 0 = cards)
PENDING_TTL_HOURS  hours an unapproved group may keep the bot before it leaves (default 24)
PAGE_SIZE, REQUEST_TIMEOUT, COOLDOWN_SECONDS, DAILY_LIMIT, MIN_QUERY,
QUERY_CACHE_TTL, BOT_NAME

Requirements: python-telegram-bot[rate-limiter,webhooks]>=22.7, aiohttp
"""

from __future__ import annotations

import asyncio
import hashlib
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
from urllib.parse import quote

import aiohttp
from telegram import (
    BotCommand,
    BotCommandScopeAllChatAdministrators,
    BotCommandScopeAllGroupChats,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputFile,
    LinkPreviewOptions,
    Update,
)
from telegram.constants import ChatAction, ChatMemberStatus, ChatType, ParseMode
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    AIORateLimiter,
    Application,
    ApplicationBuilder,
    ApplicationHandlerStop,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    TypeHandler,
    filters,
)

# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #


def _env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


BOT_TOKEN = os.environ.get("BOT_TOKEN", "8748100209:AAGZptgEMNrkMT5ZZ89VQYQfHHKd0zk3mto").strip()
BOT_NAME = os.environ.get("BOT_NAME", "OSINT Lookup")

ADMIN_IDS: set[int] = {
    int(x) for x in re.split(r"[,\s]+", os.environ.get("ADMIN_IDS", "6846112069, 7910994767")) if x.strip().isdigit()
}

SEARCH_API_URL = os.environ.get("SEARCH_API_URL", "https://icmr-and-hitek-7fdc.vercel.app/search?q={q}").strip()
API_HEADERS_RAW = os.environ.get("API_HEADERS", "").strip()

PAGE_SIZE = max(1, min(10, int(os.environ.get("PAGE_SIZE", "4"))))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "25"))
COOLDOWN_SECONDS = float(os.environ.get("COOLDOWN_SECONDS", "3"))
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "50"))  # 0 disables; admins exempt
MIN_QUERY = int(os.environ.get("MIN_QUERY", "10"))
QUERY_TTL = float(os.environ.get("QUERY_CACHE_TTL", "90"))

WEBHOOK_URL = (
    os.environ.get("WEBHOOK_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "https://numinfo-bot-eeek.onrender.com"
).strip().rstrip("/")
PORT = int(os.environ.get("PORT", "10000"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip() or secrets.token_urlsafe(24)

GROUPS_FILE = os.environ.get("GROUPS_FILE", "allowed_groups.json")
SEED_GROUPS = os.environ.get("ALLOWED_GROUPS", "")
SILENT_DENY = _env_bool("SILENT_DENY")
AUTO_APPROVE_ADMIN_ADDS = _env_bool("AUTO_APPROVE_ADMIN_ADDS", "1")
MEMBERS_CAN_SEARCH = _env_bool("GROUP_MEMBERS_CAN_SEARCH", "1")
GROUP_RAW = _env_bool("GROUP_RAW")
PENDING_TTL = float(os.environ.get("PENDING_TTL_HOURS", "24")) * 3600

CACHE_TTL = 3600
MAX_MESSAGE = 3900
GROUP_TYPES = (ChatType.GROUP, ChatType.SUPERGROUP)

logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", level=logging.INFO
)
for noisy in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(noisy).setLevel(logging.WARNING)
log = logging.getLogger("osint-bot")

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN environment variable is required")
if not ADMIN_IDS:
    raise SystemExit("ADMIN_IDS is required - this bot is admin-only")


def _parse_headers() -> dict[str, str]:
    if not API_HEADERS_RAW:
        return {}
    try:
        return {str(k): str(v) for k, v in json.loads(API_HEADERS_RAW).items()}
    except Exception:  # noqa: BLE001
        log.warning("API_HEADERS is not valid JSON - ignored")
        return {}


API_HEADERS = _parse_headers()


def is_admin(user_id: int | None) -> bool:
    return bool(user_id) and user_id in ADMIN_IDS


def today_utc() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


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
META: dict[str, dict[str, Any]] = {}  # cache key -> {owner, group, by}
HISTORY: dict[int, deque[str]] = {}
LAST_CALL: dict[int, float] = {}
USAGE: dict[int, tuple[str, int]] = {}
RUNTIME: dict[str, Any] = {"api_url": SEARCH_API_URL}
STATS: dict[str, Any] = {
    "searches": 0, "hits": 0, "errors": 0, "started": time.time(), "users": set(),
}

ALLOWED_GROUPS: dict[int, dict[str, Any]] = {}
PENDING: dict[int, dict[str, Any]] = {}  # groups waiting for admin approval
_DENY_NOTICE: dict[int, float] = {}


def cache_put(result: SearchResult, owner: int, group: bool, by: str | None) -> str:
    now = time.time()
    for k in [k for k, v in CACHE.items() if now - v.created_at > CACHE_TTL]:
        CACHE.pop(k, None)
        META.pop(k, None)
    if len(CACHE) > 1000:
        for k in sorted(CACHE, key=lambda x: CACHE[x].created_at)[:200]:
            CACHE.pop(k, None)
            META.pop(k, None)
    key = secrets.token_hex(5)
    CACHE[key] = result
    META[key] = {"owner": owner, "group": group, "by": by}
    return key


def remember(user_id: int, query: str) -> None:
    bucket = HISTORY.setdefault(user_id, deque(maxlen=8))
    if query in bucket:
        bucket.remove(query)
    bucket.appendleft(query)


def qtoken(query: str) -> str:
    return hashlib.sha1(query.encode("utf-8")).hexdigest()[:8]


def quota_check(user_id: int) -> str | None:
    """Return an error string when the user must wait, else None."""
    now = time.time()
    last = LAST_CALL.get(user_id, 0.0)
    if now - last < COOLDOWN_SECONDS:
        return f"⏳ Easy there - try again in {max(1, round(COOLDOWN_SECONDS - (now - last)))}s."
    if DAILY_LIMIT and not is_admin(user_id):
        today = today_utc()
        day, count = USAGE.get(user_id, (today, 0))
        if day != today:
            day, count = today, 0
        if count >= DAILY_LIMIT:
            return f"🚦 Daily limit reached ({DAILY_LIMIT} lookups). Resets at midnight UTC."
        USAGE[user_id] = (day, count + 1)
    LAST_CALL[user_id] = now
    return None


# --------------------------------------------------------------------------- #
# Group allowlist (persistent)                                                 #
# --------------------------------------------------------------------------- #


def load_groups() -> None:
    try:
        with open(GROUPS_FILE, encoding="utf-8") as fh:
            ALLOWED_GROUPS.update({int(k): v for k, v in json.load(fh).items()})
    except FileNotFoundError:
        pass
    except Exception:  # noqa: BLE001
        log.exception("could not read %s", GROUPS_FILE)
    for gid in re.split(r"[,\s]+", SEED_GROUPS):
        if gid.lstrip("-").isdigit():
            ALLOWED_GROUPS.setdefault(int(gid), {"title": "seeded", "by": 0, "ts": int(time.time())})
    log.info("%d authorized group(s) loaded", len(ALLOWED_GROUPS))


def save_groups() -> None:
    tmp = f"{GROUPS_FILE}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({str(k): v for k, v in ALLOWED_GROUPS.items()}, fh, indent=2)
        os.replace(tmp, GROUPS_FILE)
    except OSError:
        log.exception("could not persist groups to %s", GROUPS_FILE)


def authorize_group(chat_id: int, title: str | None, by: int) -> None:
    ALLOWED_GROUPS[chat_id] = {"title": title or str(chat_id), "by": by, "ts": int(time.time())}
    PENDING.pop(chat_id, None)
    save_groups()


def revoke_group(chat_id: int) -> bool:
    removed = ALLOWED_GROUPS.pop(chat_id, None) is not None
    if removed:
        save_groups()
    return removed


async def notify_admins(bot, text: str, markup: InlineKeyboardMarkup | None = None) -> None:
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(
                admin_id, text, parse_mode=ParseMode.HTML, reply_markup=markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except TelegramError:
            pass


async def bot_status_in(bot, chat_id: int) -> str | None:
    """Return the bot's membership status in a chat, or None if it has no access."""
    try:
        member = await bot.get_chat_member(chat_id, bot.id)
    except TelegramError:
        return None
    if member.status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED):
        return None
    return member.status


# --------------------------------------------------------------------------- #
# Access gate - runs before EVERY handler                                      #
# --------------------------------------------------------------------------- #


async def access_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.my_chat_member or update.chat_member:
        return  # membership events are validated in on_my_chat_member
    chat, user = update.effective_chat, update.effective_user
    if chat is None or user is None:
        raise ApplicationHandlerStop
    msg = update.effective_message

    if chat.type == ChatType.PRIVATE:
        if is_admin(user.id):
            return
        now = time.time()
        if not SILENT_DENY and msg and now - _DENY_NOTICE.get(user.id, 0) > 60:
            _DENY_NOTICE[user.id] = now
            try:
                await msg.reply_text("🔒 This is a private bot.")
            except TelegramError:
                pass
        if update.callback_query:
            try:
                await update.callback_query.answer()
            except TelegramError:
                pass
        raise ApplicationHandlerStop

    if chat.type in GROUP_TYPES:
        # group -> supergroup upgrade: carry the authorization to the new id
        if msg and msg.migrate_to_chat_id and chat.id in ALLOWED_GROUPS:
            meta = ALLOWED_GROUPS.pop(chat.id)
            ALLOWED_GROUPS[msg.migrate_to_chat_id] = meta
            save_groups()
            raise ApplicationHandlerStop

        if chat.id in ALLOWED_GROUPS:
            if MEMBERS_CAN_SEARCH or is_admin(user.id):
                return
            raise ApplicationHandlerStop

        text = (msg.text or "") if msg else ""
        if is_admin(user.id) and re.match(r"^/allowgroup(@\w+)?(\s|$)", text):
            return  # lets an admin authorize the group they are standing in
        raise ApplicationHandlerStop  # unauthorized group: total silence

    raise ApplicationHandlerStop  # channels etc.


# --------------------------------------------------------------------------- #
# Rich block primitives                                                        #
# --------------------------------------------------------------------------- #

DIV = "━━━━━━━━━━━━━━━━━━━━"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False)


def block_expandable_quote(body: str) -> str:
    return f"<blockquote expandable>{body}</blockquote>"


def block_code(payload: str, language: str = "json") -> str:
    return f'<pre><code class="language-{language}">{esc(payload)}</code></pre>'


def block_table(pairs: list[tuple[str, str]]) -> str:
    """Plain key/value tree (admin panels)."""
    if not pairs:
        return ""
    last = len(pairs) - 1
    return "\n".join(
        f"{'┗' if i == last else '┣'} <b>{esc(k)}</b> ▸ {esc(v)}" for i, (k, v) in enumerate(pairs)
    )


ICON_RULES: list[tuple[frozenset, str]] = [
    (frozenset({"name", "fullname", "father", "mother", "owner", "user", "username", "handle", "surname", "first", "last"}), "👤"),
    (frozenset({"phone", "mobile", "number", "msisdn", "contact", "alt", "alternate", "tel", "whatsapp"}), "📞"),
    (frozenset({"email", "mail"}), "📧"),
    (frozenset({"address", "addr", "street", "house", "locality", "landmark"}), "🏠"),
    (frozenset({"city", "district", "state", "country", "region", "location", "circle", "pincode", "pin", "zip", "postal", "area"}), "📍"),
    (frozenset({"ip", "domain", "host", "url", "link", "website", "site", "dns"}), "🌐"),
    (frozenset({"date", "time", "created", "updated", "dob", "birth", "age", "year", "since"}), "📅"),
    (frozenset({"id", "uid", "uuid", "aadhaar", "aadhar", "pan", "ref", "reference"}), "🆔"),
    (frozenset({"operator", "carrier", "provider", "network", "sim", "isp", "telecom"}), "📡"),
    (frozenset({"company", "org", "organization", "employer", "job", "work", "business"}), "🏢"),
    (frozenset({"password", "passwd", "pass", "hash", "token", "secret", "otp", "cvv"}), "🔐"),
    (frozenset({"status", "active", "verified", "valid", "type", "category"}), "✅"),
    (frozenset({"score", "count", "total", "rank", "rating"}), "📊"),
    (frozenset({"gender", "sex"}), "🧬"),
    (frozenset({"source", "database", "breach", "leak"}), "🗄"),
]


def key_icon(label: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", label)
    tokens = [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]
    for tok in reversed(tokens):
        for keys, icon in ICON_RULES:
            if tok in keys:
                return icon
    return "▫️"


def fields_block(pairs: list[tuple[str, str]]) -> str:
    """Icon + label + tap-to-copy value, drawn as a tree."""
    if not pairs:
        return ""
    last = len(pairs) - 1
    return "\n".join(
        f"{'┗' if i == last else '┣'} {key_icon(k)} <b>{esc(k)}</b> ▸ <code>{esc(v)}</code>"
        for i, (k, v) in enumerate(pairs)
    )


def rich_buttons(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([row for row in rows if row])


# --------------------------------------------------------------------------- #
# Buttons (native colors + optional premium emoji, with safe fallback)         #
# --------------------------------------------------------------------------- #

VALID_STYLES = {"primary", "success", "danger"}

CUSTOM_EMOJI: dict[str, str | None] = {
    "search": os.environ.get("EMOJI_SEARCH") or None,
    "usage": None, "help": None, "export": None, "save": None,
    "close": None, "menu": None, "record": None,
}


def tg_emoji(emoji_id: str, fallback: str) -> str:
    return f'<tg-emoji emoji-id="{esc(emoji_id)}">{esc(fallback)}</tg-emoji>'


def _button(text: str, style: str | None, icon: str | None, **kw: Any) -> InlineKeyboardButton:
    extra: dict[str, Any] = {}
    if style in VALID_STYLES:
        extra["style"] = style
    if icon:
        extra["icon_custom_emoji_id"] = icon
    try:
        return InlineKeyboardButton(text, **kw, **extra)
    except TypeError:  # older python-telegram-bot without style/icon support
        return InlineKeyboardButton(text, **kw)


def btn(text: str, data: str, style: str | None = None, icon: str | None = None) -> InlineKeyboardButton:
    return _button(text, style, icon, callback_data=data)


def link_btn(text: str, url: str, style: str | None = "primary", icon: str | None = None) -> InlineKeyboardButton:
    return _button(text, style, icon, url=url)


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
SENSITIVE_TOKENS = {"password", "passwd", "pass", "hash", "token", "secret", "otp", "pin", "cvv"}
NOISE_KEYS = {"_id", "__typename", "_index", "_score", "_type"}
MARKERS = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")


def humanize_key(key: str) -> str:
    key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    key = re.sub(r"[_\-.]+", " ", key).strip()
    return key[:1].upper() + key[1:]


def shorten(text: Any, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def strip_tags(text: Any) -> str:
    return re.sub(r"<[^>]+>", "", str(text))


def is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def mask_if_sensitive(key: str, value: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    tokens = set(re.split(r"[^a-z0-9]+", spaced.lower()))
    if tokens & SENSITIVE_TOKENS and len(value) > 4:
        return value[:2] + "•" * min(10, len(value) - 4) + value[-2:]
    return value


def masked_copy(obj: Any, key: str = "") -> Any:
    """Deep copy with sensitive-looking string values masked (display only)."""
    if isinstance(obj, dict):
        return {k: masked_copy(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [masked_copy(v, key) for v in obj]
    if isinstance(obj, str):
        return mask_if_sensitive(key, obj)
    return obj


def format_scalar(value: Any) -> str:
    if value is None:
        return "-"
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
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        return value
    return None


def display_name(user) -> str:
    if user is None:
        return "Someone"
    return user.full_name or (f"@{user.username}" if user.username else "Someone")


# --------------------------------------------------------------------------- #
# Renderers                                                                    #
# --------------------------------------------------------------------------- #


CARD_SEP = "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈"
FOOTER = "🔐 <i>Sensitive fields are masked · tap any value to copy</i>"


def render_card(item: Any, index: int, max_pairs: int, body_limit: int = 150) -> str:
    marker = MARKERS[index % len(MARKERS)]
    lines = [f"{marker} <b>{esc(item_title(item, index))}</b>"]
    if not isinstance(item, dict):
        return "\n".join(lines)

    used: set[str] = set()
    title_key, _ = pick(item, TITLE_KEYS)
    if title_key:
        used.add(title_key)

    body_key, body = pick(item, BODY_KEYS)
    if body_key and isinstance(body, str):
        used.add(body_key)
        if body_limit:
            lines.append(f"💬 <i>{esc(shorten(strip_tags(body), body_limit))}</i>")

    if max_pairs:
        pairs: list[tuple[str, str]] = []
        for key, value in flatten({k: v for k, v in item.items() if k not in used}):
            if len(pairs) >= max_pairs:
                break
            pairs.append((key, mask_if_sensitive(key, format_scalar(value))))
        table = fields_block(pairs)
        if table:
            lines.append(table)
    return "\n".join(lines)


def export_payload(result: SearchResult, index: int | None = None) -> dict[str, Any]:
    meta = {
        "query": result.query,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_records": len(result.items),
        "latency_ms": result.elapsed_ms,
    }
    if index is None:
        return {"meta": meta, "results": result.items}
    return {"meta": {**meta, "record_index": index + 1}, "record": result.items[index]}


def render_results(key: str, result: SearchResult, page: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    in_group = bool(meta.get("group"))
    total = len(result.items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    start = page * PAGE_SIZE
    chunk = result.items[start : start + PAGE_SIZE]

    head = [
        "🛰 <b>LOOKUP COMPLETE</b> ✅",
        DIV,
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 64))}</code>",
        f"📦 <b>Records</b> ▸ <code>{total}</code>   📄 <b>Page</b> ▸ <code>{page + 1}/{pages}</code>",
        f"⚡ <b>Speed</b> ▸ <code>{result.elapsed_ms} ms</code>   "
        f"🕒 <code>{time.strftime('%H:%M', time.gmtime())} UTC</code>",
    ]
    if meta.get("by"):
        head.append(f"🙋 <b>Requested by</b> ▸ {esc(meta['by'])}")
    extra = [
        f"{humanize_key(k)}: {format_scalar(v)}"
        for k, v in list(result.meta.items())[:3]
        if str(k).lower() not in {"query", "q"}
    ]
    if extra:
        head.append(f"ℹ️ <i>{esc(' · '.join(extra))}</i>")
    header = "\n".join(head) + "\n" + DIV + "\n\n"
    footer = "\n\n" + DIV + "\n" + FOOTER

    text = header
    for budget in (5, 4, 3, 2, 1, 0):
        body = f"\n\n{CARD_SEP}\n\n".join(
            render_card(it, start + i, budget) for i, it in enumerate(chunk)
        )
        text = header + (body or "<i>Empty page.</i>") + footer
        if len(text) <= MAX_MESSAGE:
            break

    rows: list[list[InlineKeyboardButton]] = []
    opens = [
        btn(
            f"{MARKERS[(start + i) % len(MARKERS)]} {shorten(item_title(it, start + i), 14)}",
            f"d|{key}|{start + i}",
            "primary",
        )
        for i, it in enumerate(chunk)
    ]
    for i in range(0, len(opens), 2):
        rows.append(opens[i : i + 2])

    if pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav += [btn("⏮", f"p|{key}|0"), btn("◀️", f"p|{key}|{page - 1}", "primary")]
        nav.append(btn(f"📄 {page + 1}/{pages}", "noop"))
        if page < pages - 1:
            nav += [btn("▶️", f"p|{key}|{page + 1}", "primary"), btn("⏭", f"p|{key}|{pages - 1}")]
        rows.append(nav)

    rows.append([btn("📥 Export JSON", f"x|{key}|{page}", "success", CUSTOM_EMOJI["export"])])
    tail = [btn("🗑 Close", f"close|{key}|0", "danger", CUSTOM_EMOJI["close"])]
    if not in_group:
        tail.insert(0, btn("🏠 Menu", "menu|0|0", None, CUSTOM_EMOJI["menu"]))
    rows.append(tail)
    return text, rich_buttons(rows)


def render_detail(key: str, result: SearchResult, index: int) -> tuple[str, InlineKeyboardMarkup]:
    index = max(0, min(index, len(result.items) - 1))
    item = result.items[index]
    page = index // PAGE_SIZE

    pairs_all = [
        (k, mask_if_sensitive(k, format_scalar(v)))
        for k, v in flatten(item if isinstance(item, dict) else {"value": item})
    ]
    raw_json = json.dumps(masked_copy(item), indent=2, ensure_ascii=False, default=str)

    head = (
        f"🗂 <b>RECORD {index + 1} OF {len(result.items)}</b> ✨\n{DIV}\n"
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 60))}</code>\n{DIV}\n\n"
        f"{render_card(item, index, 0, 420)}\n"
    )
    text = head
    for n_pairs, n_json in ((40, 1800), (30, 1200), (20, 700), (12, 400), (6, 0)):
        parts = [head, f"\n📋 <b>ALL FIELDS</b>\n{fields_block(pairs_all[:n_pairs]) or '<i>-</i>'}"]
        if n_json:
            snippet = raw_json[:n_json] + ("\n…" if len(raw_json) > n_json else "")
            parts.append("\n\n🧾 <b>RAW JSON</b> <i>(tap to expand)</i>\n" + block_expandable_quote(block_code(snippet)))
        parts.append(f"\n\n{DIV}\n{FOOTER}")
        text = "".join(parts)
        if len(text) <= MAX_MESSAGE:
            break

    nav: list[InlineKeyboardButton] = []
    if index > 0:
        nav.append(btn("⬅️ Prev", f"d|{key}|{index - 1}", "primary"))
    nav.append(btn(f"📌 {index + 1}/{len(result.items)}", "noop"))
    if index < len(result.items) - 1:
        nav.append(btn("Next ➡️", f"d|{key}|{index + 1}", "primary"))

    actions = [btn("💾 Save JSON", f"f|{key}|{index}", "success", CUSTOM_EMOJI["save"])]
    url = item_url(item)
    if url:
        actions.insert(0, link_btn("🔗 Open source", url))
    return text, rich_buttons([nav, actions, [btn("◀️ Back to results", f"p|{key}|{page}")]])


def render_raw(result: SearchResult, requester: str | None) -> str:
    parts = [
        "🛰 <b>LOOKUP COMPLETE</b> ✅",
        DIV,
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 64))}</code>",
        f"📦 <b>Records</b> ▸ <code>{len(result.items)}</code>   ⚡ <code>{result.elapsed_ms} ms</code>",
    ]
    if requester:
        parts.append(f"🙋 <b>Requested by</b> ▸ {esc(requester)}")
    header = "\n".join(parts) + "\n" + DIV + "\n\n🧾 <b>RAW JSON</b>\n"
    pretty = json.dumps(result.raw, indent=2, ensure_ascii=False, default=str)
    room = MAX_MESSAGE - len(header) - 80
    if len(pretty) > room:
        pretty = pretty[: max(0, room)] + "\n…"
    return header + block_code(pretty)


def render_menu(user_id: int) -> tuple[str, InlineKeyboardMarkup]:
    recent = list(HISTORY.get(user_id, []))[:4]
    icon = CUSTOM_EMOJI["search"]
    logo = tg_emoji(icon, "🕵️") if icon else "🕵️"
    text = (
        f"{logo} <b>{esc(BOT_NAME)}</b>\n"
        "<i>Fast, private, professional intelligence lookups.</i>\n"
        f"{DIV}\n\n"
        "🔎 <b>Send</b> a name, username, email, phone, domain or IP.\n\n"
        "✨ <b>What you get</b>\n"
        "🗂 Clean, readable record cards\n"
        "📑 Paged browsing with a full detail view\n"
        "📥 One-tap JSON export\n"
        "🔐 Auto-masked sensitive fields\n"
        "⚡ Cached and rate-limited for speed\n\n"
        + block_expandable_quote(
            "<b>Fair use</b>\nUse this for research, verification and security work - "
            "never for harassment, stalking or anything unlawful."
        )
    )
    rows: list[list[InlineKeyboardButton]] = [
        [btn("🔍 Start a lookup", "prompt|0|0", "success", icon)],
    ]
    for q in recent:
        rows.append([btn(f"🕘 {shorten(q, 26)}", f"h|{qtoken(q)}|0", "primary")])
    rows.append([
        btn("📊 My usage", "usage|0|0", "primary", CUSTOM_EMOJI["usage"]),
        btn("❓ Help", "help|0|0", None, CUSTOM_EMOJI["help"]),
    ])
    if is_admin(user_id):
        rows.append([btn("🛠 Admin panel", "admin|0|0", "danger")])
    return text, rich_buttons(rows)


def render_admin() -> tuple[str, InlineKeyboardMarkup]:
    uptime = int(time.time() - STATS["started"])
    hours, rest = divmod(uptime, 3600)
    minutes, seconds = divmod(rest, 60)
    text = (
        f"🛠 <b>ADMIN PANEL</b>\n{DIV}\n"
        + block_table([
            ("⏱ Uptime", f"{hours}h {minutes}m {seconds}s"),
            ("🔎 Lookups", str(STATS["searches"])),
            ("✅ With hits", str(STATS["hits"])),
            ("⚠️ Failures", str(STATS["errors"])),
            ("👥 Users", str(len(STATS["users"]))),
            ("🗃 Cached sets", str(len(CACHE))),
            ("🛡 Groups", f"{len(ALLOWED_GROUPS)} allowed · {len(PENDING)} pending"),
            ("🔌 Source", "connected" if RUNTIME.get("api_url") else "NOT connected"),
        ])
        + "\n\n<code>/connect &lt;url&gt;</code> · <code>/source</code> · <code>/groups</code>\n"
        "<code>/allowgroup [id]</code> · <code>/denygroup &lt;id&gt;</code>"
    )
    return text, rich_buttons([
        [btn("🔄 Refresh", "admin|0|0", "primary"), btn("🏠 Menu", "menu|0|0")],
    ])


HELP_TEXT = (
    f"❓ <b>HELP</b>\n{DIV}\n\n"
    "🔎 <b>Searching</b>\n"
    "▪️ Private chat: send a query, or <code>/search &lt;query&gt;</code>\n"
    "▪️ Allowed groups: <code>/num &lt;query&gt;</code>\n\n"
    "📖 <b>Reading results</b>\n"
    "▪️ Name buttons open a record in full\n"
    "▪️ Arrows move between pages and records\n"
    "▪️ 📥 exports what you are viewing as JSON\n\n"
    "⌨️ <b>Commands</b>\n"
    "<code>/search</code> <code>/num</code> <code>/recent</code> <code>/usage</code> <code>/menu</code>\n\n"
    "🛠 <b>Admin</b>\n"
    "<code>/admin</code> <code>/connect</code> <code>/source</code> <code>/groups</code>\n"
    "<code>/allowgroup</code> <code>/denygroup</code> <code>/emojiid</code>"
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
    encoded = quote(query, safe="")
    if "{q}" in base:
        return base.replace("{q}", encoded)
    if base.endswith(("q=", "query=", "search=", "term=", "s=")):
        return base + encoded
    return f"{base}{'&' if '?' in base else '?'}q={encoded}"


_SESSION: aiohttp.ClientSession | None = None
QUERY_CACHE: dict[str, SearchResult] = {}
INFLIGHT: dict[str, asyncio.Task] = {}


async def get_session() -> aiohttp.ClientSession:
    global _SESSION
    if _SESSION is None or _SESSION.closed:
        _SESSION = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=8),
            connector=aiohttp.TCPConnector(
                limit=100, limit_per_host=30, ttl_dns_cache=300, keepalive_timeout=60
            ),
            headers={"Accept": "application/json", "User-Agent": "osint-bot/2.0", **API_HEADERS},
        )
    return _SESSION


async def run_search(query: str) -> SearchResult:
    url = build_url(query)
    started = time.perf_counter()
    try:
        session = await get_session()
        async with session.get(url) as response:
            body = await response.text()
            if response.status == 404:
                payload: Any = {}
            elif response.status >= 400:
                log.error("source error %s: %s", response.status, body[:300])
                raise ApiError("The intelligence source rejected that lookup. Try again shortly.")
            else:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    payload = {"response": shorten(body, 2000)}
    except asyncio.TimeoutError as exc:
        raise ApiError("The source timed out. Please try again in a moment.") from exc
    except aiohttp.ClientError as exc:
        log.error("source unreachable: %s", type(exc).__name__)  # never log the URL
        raise ApiError("The intelligence source is unreachable right now.") from exc

    elapsed = int((time.perf_counter() - started) * 1000)
    items, meta = extract_items(payload)
    meta.pop("q", None)
    return SearchResult(query=query, items=items, meta=meta, raw=payload, elapsed_ms=elapsed)


async def search_cached(query: str) -> SearchResult:
    """Deduplicate identical concurrent lookups and serve hot repeats instantly."""
    key = query.strip().lower()
    hit = QUERY_CACHE.get(key)
    if hit and time.time() - hit.created_at < QUERY_TTL:
        return hit
    task = INFLIGHT.get(key)
    if task is not None:
        return await asyncio.shield(task)

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


# --------------------------------------------------------------------------- #
# User handlers                                                                #
# --------------------------------------------------------------------------- #

NO_PREVIEW = LinkPreviewOptions(is_disabled=True)


def uid_of(update: Update) -> int:
    return update.effective_user.id if update.effective_user else 0


async def send_menu(update: Update) -> None:
    text, markup = render_menu(uid_of(update))
    await update.effective_message.reply_html(text, reply_markup=markup, link_preview_options=NO_PREVIEW)


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    STATS["users"].add(uid_of(update))
    await send_menu(update)


async def cmd_menu(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await send_menu(update)


async def cmd_help(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_html(
        HELP_TEXT, reply_markup=rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]])
    )


def usage_numbers(user_id: int) -> tuple[int, str]:
    day, count = USAGE.get(user_id, (today_utc(), 0))
    if day != today_utc():
        count = 0
    left = "unlimited" if not DAILY_LIMIT or is_admin(user_id) else str(max(0, DAILY_LIMIT - count))
    return count, left


async def cmd_usage(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    count, left = usage_numbers(uid_of(update))
    await update.effective_message.reply_html(
        f"📊 <b>YOUR USAGE</b>\n{DIV}\n"
        + block_table([
            ("Lookups today", str(count)),
            ("Remaining", left),
            ("Cooldown", f"{COOLDOWN_SECONDS:g}s"),
        ])
    )


async def cmd_recent(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    recent = list(HISTORY.get(uid_of(update), []))
    if not recent:
        await update.effective_message.reply_html("🕘 No lookups yet.")
        return
    rows = [[btn(f"🕘 {shorten(q, 28)}", f"h|{qtoken(q)}|0", "primary")] for q in recent]
    await update.effective_message.reply_html(
        f"🕘 <b>RECENT LOOKUPS</b>\n{DIV}", reply_markup=rich_buttons(rows)
    )


async def do_search(update: Update, query: str, force_cards: bool = False) -> None:
    message = update.effective_message
    user = update.effective_user
    user_id = user.id if user else 0
    group = bool(update.effective_chat and update.effective_chat.type in GROUP_TYPES)
    query = (query or "").strip()[:200]

    if len(query) < MIN_QUERY:
        await message.reply_html(f"🔎 Please provide at least <b>{MIN_QUERY}</b> characters.")
        return

    blocked = quota_check(user_id)
    if blocked:
        await message.reply_html(blocked)
        return

    STATS["users"].add(user_id)
    try:
        await message.chat.send_action(ChatAction.TYPING)
    except TelegramError:
        pass
    placeholder = await message.reply_html(
        f"🛰 <b>Scanning</b> for <code>{esc(shorten(query, 60))}</code>…"
    )

    try:
        result = await search_cached(query)
    except NotConfigured:
        await placeholder.edit_text(
            "🔌 <b>No source connected yet.</b>\nThe operator has to connect one first.",
            parse_mode=ParseMode.HTML,
        )
        return
    except ApiError as exc:
        STATS["errors"] += 1
        await placeholder.edit_text(f"⚠️ {esc(exc)}", parse_mode=ParseMode.HTML)
        return
    except Exception:  # noqa: BLE001
        STATS["errors"] += 1
        log.exception("lookup failed")
        await placeholder.edit_text("💥 Something went wrong on our side. Please try again.")
        return

    STATS["searches"] += 1
    remember(user_id, query)

    if not result.items:
        await placeholder.edit_text(
            f"🫥 <b>No records</b> for <code>{esc(shorten(query, 60))}</code>.\n"
            "<i>Try a different spelling, a username, or a full email address.</i>",
            parse_mode=ParseMode.HTML,
            reply_markup=None if group else rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]]),
        )
        return

    STATS["hits"] += 1
    requester = display_name(user) if group else None

    if group and GROUP_RAW and not force_cards:
        await placeholder.edit_text(
            render_raw(result, requester), parse_mode=ParseMode.HTML, link_preview_options=NO_PREVIEW
        )
        return

    key = cache_put(result, user_id, group, requester)
    text, markup = render_results(key, result, 0)
    await placeholder.edit_text(
        text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW
    )


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await do_search(update, " ".join(context.args or []))


async def cmd_num(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Group-safe command: always reaches the bot even with group privacy ON."""
    query = " ".join(context.args or [])
    if not query and update.effective_message.reply_to_message:
        query = update.effective_message.reply_to_message.text or ""
    await do_search(update, query)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await do_search(update, update.effective_message.text or "")


# --------------------------------------------------------------------------- #
# Admin handlers                                                               #
# --------------------------------------------------------------------------- #


async def cmd_admin(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_admin()
    await update.effective_message.reply_html(text, reply_markup=markup)


async def cmd_connect(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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
    QUERY_CACHE.clear()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    await context.bot.send_message(
        update.effective_user.id,
        "✅ <b>Source connected.</b> Your message was deleted so the endpoint stays private.\n"
        "<i>Set SEARCH_API_URL in your host's env to keep it across restarts.</i>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_source(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    url = RUNTIME.get("api_url") or "not connected"
    await update.effective_message.reply_html(
        "🔐 <b>Connected source</b> (admin only)\n" + block_expandable_quote(f"<code>{esc(url)}</code>")
    )


async def cmd_emoji_id(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    target = update.effective_message.reply_to_message or update.effective_message
    entities = list(target.entities or []) + list(target.caption_entities or [])
    found = [e.custom_emoji_id for e in entities if e.type == "custom_emoji" and e.custom_emoji_id]
    if not found:
        await update.effective_message.reply_html(
            "🔎 No custom emoji found. Send a message containing one (or reply to it) "
            "and run <code>/emojiid</code> again."
        )
        return
    lines = "\n".join(f"<code>{esc(c)}</code>" for c in found)
    await update.effective_message.reply_html(
        f"🆔 <b>custom_emoji_id</b>\n{lines}\n\nSet it via the <code>EMOJI_SEARCH</code> env var."
    )


async def cmd_allowgroup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user, chat = update.effective_user, update.effective_chat
    if not user or not is_admin(user.id):
        return
    if context.args:
        try:
            gid = int(context.args[0])
        except ValueError:
            await update.effective_message.reply_html("Usage: <code>/allowgroup [chat_id]</code>")
            return
    elif chat.type in GROUP_TYPES:
        gid = chat.id
    else:
        await update.effective_message.reply_html("Usage: <code>/allowgroup &lt;chat_id&gt;</code>")
        return

    if await bot_status_in(context.bot, gid) is None:
        await update.effective_message.reply_html(
            "⚠️ The bot is not in that chat. Add it there first, then retry."
        )
        return
    try:
        title = (await context.bot.get_chat(gid)).title
    except TelegramError:
        title = str(gid)
    authorize_group(gid, title, user.id)
    await update.effective_message.reply_html(
        f"✅ <b>Authorized</b>\n{block_table([('Group', title or str(gid)), ('ID', str(gid))])}"
    )


async def cmd_denygroup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        gid = int(context.args[0])
    except (IndexError, ValueError):
        await update.effective_message.reply_html("Usage: <code>/denygroup &lt;chat_id&gt;</code>")
        return
    removed = revoke_group(gid)
    try:
        await context.bot.leave_chat(gid)
    except TelegramError:
        pass
    await update.effective_message.reply_html(
        "🗑 Revoked &amp; left." if removed else "That group wasn't authorized (left it anyway if I was in it)."
    )


async def cmd_groups(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not ALLOWED_GROUPS and not PENDING:
        await update.effective_message.reply_html("🛡 No groups authorized yet.")
        return
    items = list(ALLOWED_GROUPS.items())[:40]
    statuses = await asyncio.gather(*(bot_status_in(context.bot, gid) for gid, _ in items))
    lines, ok = [], 0
    for (gid, meta), status in zip(items, statuses):
        if status is None:
            mark, note = "❌", "bot not in group"
        else:
            ok += 1
            mark = "✅"
            note = "working (admin)" if status == ChatMemberStatus.ADMINISTRATOR else "working"
        lines.append(f"{mark} <b>{esc(meta.get('title', gid))}</b>\n   <code>{gid}</code> · {note}")
    text = (
        f"🛡 <b>AUTHORIZED GROUPS</b>\n{DIV}\n"
        f"✅ {ok} working · ❌ {len(items) - ok} inactive · ⏳ {len(PENDING)} pending\n\n"
        + ("\n\n".join(lines) if lines else "<i>None yet.</i>")
    )
    markup = None
    if PENDING:
        text += f"\n\n{DIV}\n⏳ <b>WAITING FOR APPROVAL</b>"
        rows = []
        for gid, info in list(PENDING.items())[:10]:
            text += f"\n▪️ <b>{esc(info['title'])}</b> · <code>{gid}</code> · by {esc(info['name'])}"
            rows.append([
                btn(f"✅ {shorten(info['title'], 16)}", f"ap|{gid}|0", "success"),
                btn("❌ Reject", f"rj|{gid}|0", "danger"),
            ])
        markup = rich_buttons(rows)
    await update.effective_message.reply_html(text, reply_markup=markup)


async def on_my_chat_member(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ev = update.my_chat_member
    chat, adder = ev.chat, ev.from_user
    if chat.type not in GROUP_TYPES:
        return
    old, new = ev.old_chat_member.status, ev.new_chat_member.status
    gone = (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED)
    present = (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR)
    title = esc(chat.title)

    if new in present and old in gone:
        if is_admin(adder.id) and AUTO_APPROVE_ADMIN_ADDS:
            authorize_group(chat.id, chat.title, adder.id)
            await notify_admins(
                context.bot, f"✅ <b>Added &amp; authorized</b>\n<b>{title}</b> · <code>{chat.id}</code>"
            )
        elif is_admin(adder.id):
            await notify_admins(
                context.bot,
                f"ℹ️ Added to <b>{title}</b> but not authorized.\n<code>/allowgroup {chat.id}</code>",
            )
        else:
            PENDING[chat.id] = {
                "title": chat.title or str(chat.id), "by": adder.id,
                "name": adder.full_name, "ts": time.time(),
            }
            hours = max(1, round(PENDING_TTL / 3600))
            await notify_admins(
                context.bot,
                f"🆕 <b>APPROVAL NEEDED</b>\n{DIV}\n"
                + block_table([
                    ("👥 Group", chat.title or str(chat.id)),
                    ("🆔 ID", str(chat.id)),
                    ("👤 Added by", f"{adder.full_name} ({adder.id})"),
                ])
                + f"\n\n<i>The bot stays silent until you decide, and leaves by itself after {hours}h.</i>",
                rich_buttons([[
                    btn("✅ Approve", f"ap|{chat.id}|0", "success"),
                    btn("❌ Reject & leave", f"rj|{chat.id}|0", "danger"),
                ]]),
            )
            try:
                await context.bot.send_message(
                    chat.id,
                    "⏳ <b>Awaiting approval</b>\nThis is a private bot. The owner has been notified "
                    "and will approve or reject this group shortly.",
                    parse_mode=ParseMode.HTML,
                )
            except TelegramError:
                pass
    elif new in gone:
        was_pending = PENDING.pop(chat.id, None) is not None
        if revoke_group(chat.id):
            await notify_admins(context.bot, f"👋 Removed from <b>{title}</b> - authorization cleared.")
        elif was_pending:
            await notify_admins(context.bot, f"👋 Removed from pending group <b>{title}</b>.")


async def pending_sweeper(bot) -> None:
    """Leave groups that were never approved."""
    while True:
        await asyncio.sleep(600)
        now = time.time()
        for gid, info in list(PENDING.items()):
            if now - info["ts"] > PENDING_TTL:
                PENDING.pop(gid, None)
                try:
                    await bot.leave_chat(gid)
                except TelegramError:
                    pass
                await notify_admins(
                    bot, f"⌛ Left <b>{esc(info['title'])}</b> - no approval within the time limit."
                )


# --------------------------------------------------------------------------- #
# Callbacks                                                                    #
# --------------------------------------------------------------------------- #

KEYED_ACTIONS = {"p", "d", "x", "f", "close"}


async def _safe_edit(query, text: str, markup: InlineKeyboardMarkup | None) -> None:
    try:
        await query.edit_message_text(
            text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW
        )
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            log.warning("edit failed: %s", exc)


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

    chat_type = query.message.chat.type if query.message else None
    in_group = chat_type in GROUP_TYPES

    # ---- ownership lock for buttons in groups ----
    if action in KEYED_ACTIONS and in_group and not is_admin(user_id):
        meta = META.get(key)
        if meta is None or meta["owner"] != user_id:
            who = meta["by"] if meta and meta.get("by") else "the person who ran the search"
            await query.answer(f"🔒 Only {who} can use these buttons.", show_alert=True)
            return

    if action in {"ap", "rj"}:
        if not is_admin(user_id):
            await query.answer("Not available.", show_alert=True)
            return
        try:
            gid = int(key)
        except ValueError:
            await query.answer("Bad request.")
            return
        info = PENDING.get(gid) or ALLOWED_GROUPS.get(gid) or {}
        title = info.get("title") or str(gid)
        done = InlineKeyboardMarkup([])
        if action == "ap":
            if await bot_status_in(context.bot, gid) is None:
                PENDING.pop(gid, None)
                await query.answer("The bot is no longer in that group.", show_alert=True)
                await _safe_edit(query, f"⚪ <b>{esc(title)}</b> - the bot is no longer in this group.", done)
                return
            authorize_group(gid, title, user_id)
            await query.answer("Approved ✅")
            await _safe_edit(
                query,
                f"✅ <b>APPROVED</b>\n{DIV}\n"
                + block_table([("👥 Group", title), ("🆔 ID", str(gid))]),
                done,
            )
            try:
                await context.bot.send_message(
                    gid,
                    f"✅ <b>Approved.</b>\nUse <code>/num &lt;query&gt;</code> to run a lookup.",
                    parse_mode=ParseMode.HTML,
                )
            except TelegramError:
                pass
        else:
            PENDING.pop(gid, None)
            revoke_group(gid)
            try:
                await context.bot.leave_chat(gid)
            except TelegramError:
                pass
            await query.answer("Rejected")
            await _safe_edit(
                query,
                f"🚫 <b>REJECTED &amp; LEFT</b>\n{DIV}\n"
                + block_table([("👥 Group", title), ("🆔 ID", str(gid))]),
                done,
            )
        return

    if action == "close":
        await query.answer("Closed")
        try:
            await query.message.delete()
        except TelegramError:
            pass
        return

    if action == "prompt":
        await query.answer(
            "Just type a name, username, email, phone, domain or IP and send it.", show_alert=True
        )
        return

    if action == "menu":
        await query.answer()
        text, markup = render_menu(user_id)
        await _safe_edit(query, text, markup)
        return

    if action == "help":
        await query.answer()
        await _safe_edit(query, HELP_TEXT, rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]]))
        return

    if action == "admin":
        if not is_admin(user_id):
            await query.answer("Not available.", show_alert=True)
            return
        await query.answer()
        text, markup = render_admin()
        await _safe_edit(query, text, markup)
        return

    if action == "usage":
        count, left = usage_numbers(user_id)
        await query.answer(f"Today: {count} lookups · remaining: {left}", show_alert=True)
        return

    if action == "h":
        stored = next((q for q in HISTORY.get(user_id, []) if qtoken(q) == key), None)
        await query.answer("Re-running…" if stored else "That query expired.")
        if stored:
            await do_search(update, stored)
        return

    result = CACHE.get(key)
    if not result:
        await query.answer("This result set expired - run the lookup again.", show_alert=True)
        return

    if action in {"x", "f"}:
        record = min(index, len(result.items) - 1)
        payload = export_payload(result, None if action == "x" else record)
        blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", result.query)[:40] or "lookup"
        name = f"{safe}_results.json" if action == "x" else f"{safe}_record_{record + 1}.json"
        await query.answer("Preparing file…")
        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=InputFile(io.BytesIO(blob), filename=name),
            caption=(
                f"📥 <b>EXPORT READY</b>\n"
                f"🎯 <code>{esc(shorten(result.query, 50))}</code>\n"
                f"📦 {'Full result set · ' + str(len(result.items)) + ' records' if action == 'x' else 'Record ' + str(record + 1)}"
            ),
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


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("handler error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message and update.effective_chat:
        if update.effective_chat.type == ChatType.PRIVATE:
            try:
                await update.effective_message.reply_html("💥 Something went wrong. Please try again.")
            except TelegramError:
                pass


# --------------------------------------------------------------------------- #
# Lifecycle                                                                    #
# --------------------------------------------------------------------------- #


async def post_init(app: Application) -> None:
    bot = app.bot
    # Non-admins see no commands in DMs; groups only ever show /num.
    try:
        await bot.delete_my_commands()
        await bot.set_my_commands([BotCommand("num", "Run an OSINT lookup")], scope=BotCommandScopeAllGroupChats())
        await bot.set_my_commands(
            [BotCommand("num", "Run an OSINT lookup")], scope=BotCommandScopeAllChatAdministrators()
        )
    except TelegramError as exc:
        log.warning("could not set base commands: %s", exc)

    admin_commands = [
        BotCommand("start", "Open the main menu"),
        BotCommand("search", "Run an OSINT lookup"),
        BotCommand("recent", "Your recent lookups"),
        BotCommand("usage", "Your usage"),
        BotCommand("admin", "Admin panel"),
        BotCommand("groups", "List authorized groups"),
        BotCommand("allowgroup", "Authorize a group"),
        BotCommand("denygroup", "Revoke a group"),
        BotCommand("connect", "Connect the data source"),
        BotCommand("source", "Show the connected source"),
        BotCommand("emojiid", "Extract a custom emoji's ID"),
        BotCommand("help", "Help"),
    ]
    for admin_id in ADMIN_IDS:
        try:
            await bot.set_my_commands(admin_commands, scope=BotCommandScopeChat(admin_id))
        except TelegramError as exc:
            log.warning("could not set admin commands for %s: %s", admin_id, exc)

    app.bot_data["sweeper"] = asyncio.create_task(pending_sweeper(bot))
    me = await bot.get_me()
    log.info(
        "Online as @%s | source %s | %d admin(s) | %d group(s)",
        me.username, "connected" if RUNTIME["api_url"] else "MISSING", len(ADMIN_IDS), len(ALLOWED_GROUPS),
    )
    await notify_admins(
        bot,
        f"🟢 <b>{esc(BOT_NAME)} online</b>\n"
        + block_table([
            ("Source", "connected" if RUNTIME["api_url"] else "NOT connected"),
            ("Groups", str(len(ALLOWED_GROUPS))),
        ]),
    )


async def post_shutdown(app: Application) -> None:
    task = app.bot_data.get("sweeper")
    if task:
        task.cancel()
    if _SESSION and not _SESSION.closed:
        await _SESSION.close()


def main() -> None:
    load_groups()
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

    private = filters.ChatType.PRIVATE

    # 1) gate - runs first for every update; anything unauthorized stops here
    app.add_handler(TypeHandler(Update, access_gate), group=-1)

    # 2) membership events (bot added to / removed from groups)
    app.add_handler(ChatMemberHandler(on_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER))

    # 3) commands - everything except /num and /allowgroup is private-only
    app.add_handler(CommandHandler("start", cmd_start, filters=private))
    app.add_handler(CommandHandler("menu", cmd_menu, filters=private))
    app.add_handler(CommandHandler("help", cmd_help, filters=private))
    app.add_handler(CommandHandler("search", cmd_search, filters=private))
    app.add_handler(CommandHandler("recent", cmd_recent, filters=private))
    app.add_handler(CommandHandler("usage", cmd_usage, filters=private))
    app.add_handler(CommandHandler("emojiid", cmd_emoji_id, filters=private))
    app.add_handler(CommandHandler("admin", cmd_admin, filters=private))
    app.add_handler(CommandHandler("connect", cmd_connect, filters=private))
    app.add_handler(CommandHandler("source", cmd_source, filters=private))
    app.add_handler(CommandHandler("groups", cmd_groups, filters=private))
    app.add_handler(CommandHandler("denygroup", cmd_denygroup, filters=private))
    app.add_handler(CommandHandler("num", cmd_num))
    app.add_handler(CommandHandler("allowgroup", cmd_allowgroup))  # works inside groups too

    # 4) buttons and plain text (text only reacts in private chats)
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & private, on_text))
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
