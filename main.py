"""
OSINT LOOKUP BOT - private, admin-only, group-allowlisted, self-cleaning
========================================================================

Access model
------------
* Private chats : ONLY admins (ADMIN_IDS) get any response.
* Groups         : the bot works ONLY in allowlisted groups; elsewhere it is silent.
* Adding the bot : added by an admin  -> group authorized automatically
                   added by anyone else -> bot stays SILENT in "pending" state, admins get
                   [Approve] / [Reject] buttons; no decision in PENDING_TTL_HOURS -> it leaves.
* Buttons        : in groups, result buttons only work for the person who ran the search.
* Privacy        : every lookup result (and the query that triggered it) is auto-deleted
                   after AUTO_DELETE_SECONDS (default 120 = 2 minutes). Adjustable live.

Admin control center (/admin)
-----------------------------
Dashboard, live settings (auto-delete timer, lockdown mode, masking, limits ...),
group manager, activity log, top users, ban list, source health test, cache clear,
log export. Commands: /admin /groups /allowgroup /denygroup /ban /unban /banned
/connect /source /emojiid

Custom commands (owner-defined, no redeploy)
--------------------------------------------
/addcmd <name> <url-with-{q}>  creates e.g. /tg <query>. Then /cmds opens an in-Telegram editor:
title, header emoji (Premium emoji OK), API URL, button colour, per-field icons, hidden
fields, footer note, min length, private headers, test, enable/disable, delete.

Environment variables
---------------------
BOT_TOKEN, ADMIN_IDS (required)
SEARCH_API_URL, API_HEADERS, WEBHOOK_URL (falls back to RENDER_EXTERNAL_URL), WEBHOOK_SECRET
GROUPS_FILE   default allowed_groups.json   (use /data/... on a persistent disk)
STATE_FILE    default bot_state.json        (settings + ban list; same advice)
ALLOWED_GROUPS seed list "-100123,-100456"
AUTO_DELETE_SECONDS (120), DELETE_QUERIES (1), GROUP_MEMBERS_CAN_SEARCH (1),
AUTO_APPROVE_ADMIN_ADDS (1), SILENT_DENY (0), GROUP_RAW (0), PENDING_TTL_HOURS (24),
PAGE_SIZE, REQUEST_TIMEOUT, COOLDOWN_SECONDS, DAILY_LIMIT, MIN_QUERY, QUERY_CACHE_TTL,
BOT_NAME, EMOJI_SEARCH

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
from urllib.parse import quote, urlparse

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
STATE_FILE = os.environ.get("STATE_FILE", "bot_state.json")
SEED_GROUPS = os.environ.get("ALLOWED_GROUPS", "")
SILENT_DENY = _env_bool("SILENT_DENY")
AUTO_APPROVE_ADMIN_ADDS = _env_bool("AUTO_APPROVE_ADMIN_ADDS", "1")
PENDING_TTL = float(os.environ.get("PENDING_TTL_HOURS", "24")) * 3600

CACHE_TTL = 3600
MAX_MESSAGE = 3900
GROUP_TYPES = (ChatType.GROUP, ChatType.SUPERGROUP)

# Live, admin-editable settings (persisted to STATE_FILE).
SETTINGS: dict[str, Any] = {
    "auto_delete": int(os.environ.get("AUTO_DELETE_SECONDS", "120")),  # seconds, 0 = off
    "delete_queries": _env_bool("DELETE_QUERIES", "1"),
    "lockdown": False,
    "members_can_search": _env_bool("GROUP_MEMBERS_CAN_SEARCH", "1"),
    "group_raw": _env_bool("GROUP_RAW"),
    "mask": True,
    "cooldown": float(os.environ.get("COOLDOWN_SECONDS", "3")),
    "daily_limit": int(os.environ.get("DAILY_LIMIT", "50")),  # 0 = unlimited (admins exempt)
}

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


def clock(ts: float | None = None) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def fmt_dur(seconds: float) -> str:
    seconds = int(seconds)
    if seconds <= 0:
        return "off"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds}s"


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
    source: str | None = None


CACHE: dict[str, SearchResult] = {}
META: dict[str, dict[str, Any]] = {}  # cache key -> {owner, group, by, born}
HISTORY: dict[int, deque[str]] = {}
LAST_CALL: dict[int, float] = {}
USAGE: dict[int, tuple[str, int]] = {}
RUNTIME: dict[str, Any] = {"api_url": SEARCH_API_URL}
STATS: dict[str, Any] = {
    "searches": 0, "hits": 0, "errors": 0, "lat_total": 0, "lat_n": 0,
    "started": time.time(), "users": set(),
}
LOG: deque[dict[str, Any]] = deque(maxlen=100)  # activity / audit log
USER_STATS: dict[int, dict[str, Any]] = {}
BANNED: set[int] = set()
SOURCES: dict[str, dict[str, Any]] = {}  # owner-defined custom commands
INPUT: dict[int, dict[str, Any]] = {}    # admin id -> pending text-input state
INPUT_TTL = 300

RESERVED = {
    "start", "menu", "help", "search", "recent", "usage", "emojiid", "admin", "connect", "source",
    "groups", "denygroup", "allowgroup", "banned", "ban", "unban", "num", "addcmd", "cmds",
    "delcmd", "cancel",
}
CMD_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
STYLE_CYCLE = ["primary", "success", "danger", "default"]
SOURCE_DEFAULTS: dict[str, Any] = {
    "url": "", "title": "", "emoji": "🛰", "emoji_id": None, "style": "primary",
    "icons": {}, "hide": [], "footer": "", "min_len": MIN_QUERY, "headers": {}, "enabled": True,
}
DEFAULT_PROFILE: dict[str, Any] = {
    "emoji": "🛰", "emoji_id": None, "title": "Lookup", "style": "primary",
    "icons": {}, "hide": [], "footer": "", "min_len": None,
}


def new_source(name: str, url: str) -> dict[str, Any]:
    src = json.loads(json.dumps(SOURCE_DEFAULTS))
    src["url"] = url
    src["title"] = f"{name.upper()} Lookup"
    return src


def profile(name: str | None) -> dict[str, Any]:
    src = SOURCES.get(name) if name else None
    return src if src else DEFAULT_PROFILE


def emoji_html(p: dict[str, Any]) -> str:
    if p.get("emoji_id"):
        return tg_emoji(p["emoji_id"], p.get("emoji") or "🛰")
    return esc(p.get("emoji") or "🛰")


def btn_style(p: dict[str, Any]) -> str | None:
    style = p.get("style", "primary")
    return None if style == "default" else style


def hidden(label: str, hide: list[str]) -> bool:
    low = label.lower()
    return any(h in low for h in hide)


def host_of(url: str) -> str:
    return urlparse(url).netloc or "?"

ALLOWED_GROUPS: dict[int, dict[str, Any]] = {}
PENDING: dict[int, dict[str, Any]] = {}
_DENY_NOTICE: dict[int, float] = {}
_BG: set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _BG.add(task)
    task.add_done_callback(_BG.discard)
    return task


def cache_put(result: SearchResult, owner: int, group: bool, by: str | None, src: str | None = None) -> str:
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
    META[key] = {"owner": owner, "group": group, "by": by, "born": now, "src": src}
    return key


def remember(user_id: int, query: str) -> None:
    bucket = HISTORY.setdefault(user_id, deque(maxlen=8))
    if query in bucket:
        bucket.remove(query)
    bucket.appendleft(query)


def qtoken(query: str) -> str:
    return hashlib.sha1(query.encode("utf-8")).hexdigest()[:8]


def quota_check(user_id: int) -> str | None:
    now = time.time()
    cooldown = float(SETTINGS["cooldown"])
    last = LAST_CALL.get(user_id, 0.0)
    if now - last < cooldown:
        return f"⏳ Easy there - try again in {max(1, round(cooldown - (now - last)))}s."
    limit = int(SETTINGS["daily_limit"])
    if limit and not is_admin(user_id):
        today = today_utc()
        day, count = USAGE.get(user_id, (today, 0))
        if day != today:
            day, count = today, 0
        if count >= limit:
            return f"🚦 Daily limit reached ({limit} lookups). Resets at midnight UTC."
        USAGE[user_id] = (day, count + 1)
    LAST_CALL[user_id] = now
    return None


def record_activity(user, chat, query: str, hits: int, ms: int, status: str, cmd: str | None = None) -> None:
    uid = user.id if user else 0
    name = (user.full_name if user else "?") or "?"
    where = "DM" if chat is None or chat.type == ChatType.PRIVATE else (chat.title or str(chat.id))
    LOG.append({"ts": time.time(), "uid": uid, "name": name, "where": where,
                "query": query, "hits": hits, "ms": ms, "status": status, "cmd": cmd})
    entry = USER_STATS.setdefault(uid, {"name": name, "count": 0, "last": 0.0})
    entry.update(name=name, last=time.time())
    entry["count"] += 1


# --------------------------------------------------------------------------- #
# Persistence                                                                  #
# --------------------------------------------------------------------------- #


def _atomic_dump(path: str, data: Any, secret: bool = False) -> None:
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        if secret:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        log.exception("could not persist %s", path)


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


def save_groups() -> None:
    _atomic_dump(GROUPS_FILE, {str(k): v for k, v in ALLOWED_GROUPS.items()})


def load_state() -> None:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return
    except Exception:  # noqa: BLE001
        log.exception("could not read %s", STATE_FILE)
        return
    for key, value in (data.get("settings") or {}).items():
        if key in SETTINGS:
            current = SETTINGS[key]
            try:
                SETTINGS[key] = bool(value) if isinstance(current, bool) else type(current)(value)
            except (TypeError, ValueError):
                pass
    BANNED.update(int(x) for x in data.get("banned", []) if str(x).lstrip("-").isdigit())
    for name, conf in (data.get("sources") or {}).items():
        if CMD_RE.match(str(name)) and isinstance(conf, dict) and conf.get("url"):
            merged = new_source(str(name), str(conf["url"]))
            merged.update({k: v for k, v in conf.items() if k in SOURCE_DEFAULTS})
            SOURCES[str(name)] = merged
    log.info("state loaded: %d custom command(s), %d banned", len(SOURCES), len(BANNED))


def save_state() -> None:
    _atomic_dump(STATE_FILE, {"settings": SETTINGS, "banned": sorted(BANNED), "sources": SOURCES}, secret=True)


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
    try:
        member = await bot.get_chat_member(chat_id, bot.id)
    except TelegramError:
        return None
    if member.status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED):
        return None
    return member.status


# --------------------------------------------------------------------------- #
# Auto-delete (privacy)                                                        #
# --------------------------------------------------------------------------- #


async def _delete_later(bot, chat_id: int, message_id: int, delay: float) -> None:
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, message_id)
    except TelegramError:
        pass  # already gone, too old, or no delete rights


async def _forget_later(key: str, delay: float) -> None:
    await asyncio.sleep(delay)
    CACHE.pop(key, None)
    META.pop(key, None)


def autodelete(bot, *messages, delay: float | None = None) -> None:
    delay = SETTINGS["auto_delete"] if delay is None else delay
    if not delay:
        return
    for m in messages:
        if m is not None:
            spawn(_delete_later(bot, m.chat_id, m.message_id, delay))


def delete_note() -> str:
    d = SETTINGS["auto_delete"]
    return f"\n⏳ <i>Self-destructs {fmt_dur(d)} after the lookup</i>" if d else ""


# --------------------------------------------------------------------------- #
# Access gate - runs before EVERY handler                                      #
# --------------------------------------------------------------------------- #


async def _stop(update: Update) -> None:
    if update.callback_query:
        try:
            await update.callback_query.answer()
        except TelegramError:
            pass
    raise ApplicationHandlerStop


async def access_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.my_chat_member or update.chat_member:
        return
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
        await _stop(update)

    if chat.type in GROUP_TYPES:
        if msg and msg.migrate_to_chat_id and chat.id in ALLOWED_GROUPS:
            ALLOWED_GROUPS[msg.migrate_to_chat_id] = ALLOWED_GROUPS.pop(chat.id)
            save_groups()
            raise ApplicationHandlerStop

        if chat.id in ALLOWED_GROUPS:
            if is_admin(user.id):
                return
            if user.id in BANNED:
                await _stop(update)
            if SETTINGS["members_can_search"]:
                return
            await _stop(update)

        text = (msg.text or "") if msg else ""
        if is_admin(user.id) and re.match(r"^/allowgroup(@\w+)?(\s|$)", text):
            return
        await _stop(update)

    raise ApplicationHandlerStop


# --------------------------------------------------------------------------- #
# Rich block primitives                                                        #
# --------------------------------------------------------------------------- #

DIV = "━━━━━━━━━━━━━━━━━━━━"
CARD_SEP = "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈"


def esc(value: Any) -> str:
    return html.escape(str(value), quote=False)


def block_expandable_quote(body: str) -> str:
    return f"<blockquote expandable>{body}</blockquote>"


def block_quote(body: str) -> str:
    return f"<blockquote>{body}</blockquote>"


def block_code(payload: str, language: str = "json") -> str:
    return f'<pre><code class="language-{language}">{esc(payload)}</code></pre>'


def tree(lines: list[str]) -> str:
    """Join pre-built lines with ┣ ┗ connectors."""
    if not lines:
        return ""
    last = len(lines) - 1
    return "\n".join(f"{'┗' if i == last else '┣'} {line}" for i, line in enumerate(lines))


def block_table(pairs: list[tuple[str, str]]) -> str:
    return tree([f"<b>{esc(k)}</b> ▸ <code>{esc(v)}</code>" for k, v in pairs])


def rich_buttons(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([row for row in rows if row])


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


def key_icon(label: str, overrides: dict[str, str] | None = None) -> str:
    if overrides:
        low = label.lower()
        for kw, icon in overrides.items():
            if kw in low:
                return icon
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", label)
    tokens = [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]
    for tok in reversed(tokens):
        for keys, icon in ICON_RULES:
            if tok in keys:
                return icon
    return "▫️"


def fields_block(pairs: list[tuple[str, str]], more: int = 0, icons: dict[str, str] | None = None) -> str:
    lines = [f"{key_icon(k, icons)} <b>{esc(k)}</b> ▸ <code>{esc(v)}</code>" for k, v in pairs]
    if more > 0:
        lines.append(f"➕ <i>{more} more field{'s' if more != 1 else ''} · open the record</i>")
    return tree(lines)


# --------------------------------------------------------------------------- #
# Buttons                                                                      #
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
    except TypeError:
        return InlineKeyboardButton(text, **kw)


def btn(text: str, data: str, style: str | None = "primary", icon: str | None = None) -> InlineKeyboardButton:
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
    if not SETTINGS["mask"]:
        return value
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    tokens = set(re.split(r"[^a-z0-9]+", spaced.lower()))
    if tokens & SENSITIVE_TOKENS and len(value) > 4:
        return value[:2] + "•" * min(10, len(value) - 4) + value[-2:]
    return value


def masked_copy(obj: Any, key: str = "", hide: list[str] | None = None) -> Any:
    hide = hide or []
    if isinstance(obj, dict):
        return {
            k: masked_copy(v, str(k), hide)
            for k, v in obj.items()
            if not any(h in str(k).lower() for h in hide)
        }
    if isinstance(obj, list):
        return [masked_copy(v, key, hide) for v in obj]
    if isinstance(obj, str):
        return mask_if_sensitive(key, obj)
    return obj


def format_scalar(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "✅ Yes" if value else "❌ No"
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
# Result renderers                                                             #
# --------------------------------------------------------------------------- #

FOOTER = "🔐 <i>Sensitive fields masked · tap any value to copy</i>"


def render_card(item: Any, index: int, max_pairs: int, body_limit: int = 150,
                p: dict[str, Any] | None = None) -> str:
    p = p or DEFAULT_PROFILE
    hide, icons = p.get("hide") or [], p.get("icons") or {}
    marker = MARKERS[index % len(MARKERS)]
    title = f"{marker} <b>{esc(item_title(item, index))}</b>"
    if not isinstance(item, dict):
        return title

    used: set[str] = set()
    title_key, _ = pick(item, TITLE_KEYS)
    if title_key:
        used.add(title_key)
    lines: list[str] = []

    body_key, body = pick(item, BODY_KEYS)
    if body_key and isinstance(body, str):
        used.add(body_key)
        if body_limit:
            lines.append(f"💬 <i>{esc(shorten(strip_tags(body), body_limit))}</i>")

    all_pairs = [(k, v) for k, v in flatten({k: v for k, v in item.items() if k not in used})
                 if not hidden(k, hide)]
    shown = [(k, mask_if_sensitive(k, format_scalar(v))) for k, v in all_pairs[:max_pairs]] if max_pairs else []
    more = max(0, len(all_pairs) - len(shown)) if max_pairs else 0
    total_fields = len([1 for k, _ in flatten(item) if not hidden(k, hide)])
    badge = f"  <i>· {total_fields} fields</i>" if total_fields else ""

    out = [title + badge] + lines
    block = fields_block(shown, more, icons)
    if block:
        out.append(block)
    return "\n".join(out)


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


def summary_box(rows: list[str]) -> str:
    return block_quote("\n".join(rows))


def custom_footer(p: dict[str, Any]) -> str:
    return f"\n📝 <i>{esc(p['footer'])}</i>" if p.get("footer") else ""


def render_results(key: str, result: SearchResult, page: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    in_group = bool(meta.get("group"))
    total = len(result.items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    start = page * PAGE_SIZE
    chunk = result.items[start : start + PAGE_SIZE]

    box = [
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 64))}</code>",
        f"📦 <b>Records</b> ▸ <code>{total}</code>   📄 <b>Page</b> ▸ <code>{page + 1}/{pages}</code>",
        f"⚡ <b>Speed</b> ▸ <code>{result.elapsed_ms} ms</code>   🕒 <code>{clock()[:5]} UTC</code>",
    ]
    if meta.get("by"):
        box.append(f"🙋 <b>Requested by</b> ▸ {esc(meta['by'])}")
    extra = [
        f"{humanize_key(k)}: {format_scalar(v)}"
        for k, v in list(result.meta.items())[:3]
        if str(k).lower() not in {"query", "q"}
    ]
    if extra:
        box.append(f"ℹ️ <i>{esc(' · '.join(extra))}</i>")
    header = f"{emoji_html(p)} <b>{esc(str(p['title']).upper())} COMPLETE</b> ✅\n{summary_box(box)}\n"
    footer = f"\n\n{DIV}\n{FOOTER}{custom_footer(p)}{delete_note()}"

    text = header
    for budget in (5, 4, 3, 2, 1, 0):
        body = f"\n\n{CARD_SEP}\n\n".join(
            render_card(it, start + i, budget, 150, p) for i, it in enumerate(chunk)
        )
        text = header + "\n" + (body or "<i>Empty page.</i>") + footer
        if len(text) <= MAX_MESSAGE:
            break

    rows: list[list[InlineKeyboardButton]] = []
    opens = [
        btn(
            f"{MARKERS[(start + i) % len(MARKERS)]} {shorten(item_title(it, start + i), 14)}",
            f"d|{key}|{start + i}", btn_style(p),
        )
        for i, it in enumerate(chunk)
    ]
    for i in range(0, len(opens), 2):
        rows.append(opens[i : i + 2])

    if pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav += [btn("⏮", f"p|{key}|0"), btn("◀️", f"p|{key}|{page - 1}")]
        nav.append(btn(f"📄 {page + 1}/{pages}", "noop", None))
        if page < pages - 1:
            nav += [btn("▶️", f"p|{key}|{page + 1}"), btn("⏭", f"p|{key}|{pages - 1}")]
        rows.append(nav)

    rows.append([btn("📥 Export JSON", f"x|{key}|{page}", "success", CUSTOM_EMOJI["export"])])
    tail = [btn("🗑 Close", f"close|{key}|0", "danger", CUSTOM_EMOJI["close"])]
    if not in_group:
        tail.insert(0, btn("🏠 Menu", "menu|0|0", "primary", CUSTOM_EMOJI["menu"]))
    rows.append(tail)
    return text, rich_buttons(rows)


def render_detail(key: str, result: SearchResult, index: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    hide, icons = p.get("hide") or [], p.get("icons") or {}
    index = max(0, min(index, len(result.items) - 1))
    item = result.items[index]
    page = index // PAGE_SIZE

    pairs_all = [
        (k, mask_if_sensitive(k, format_scalar(v)))
        for k, v in flatten(item if isinstance(item, dict) else {"value": item})
        if not hidden(k, hide)
    ]
    raw_json = json.dumps(masked_copy(item, hide=hide), indent=2, ensure_ascii=False, default=str)

    box = [
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 60))}</code>",
        f"📌 <b>Record</b> ▸ <code>{index + 1}/{len(result.items)}</code>   🧩 <b>Fields</b> ▸ <code>{len(pairs_all)}</code>",
    ]
    brand = f" · {emoji_html(p)} <b>{esc(p['title'])}</b>" if meta.get("src") else ""
    head = (
        f"🗂 <b>RECORD DETAIL</b> ✨{brand}\n{summary_box(box)}\n"
        f"{render_card(item, index, 0, 420, p).split(chr(10))[0]}\n"
    )
    body_key, body = pick(item, BODY_KEYS) if isinstance(item, dict) else (None, None)
    if body_key and isinstance(body, str):
        head += f"💬 <i>{esc(shorten(strip_tags(body), 420))}</i>\n"

    text = head
    for n_pairs, n_json in ((40, 1800), (30, 1200), (20, 700), (12, 400), (6, 0)):
        shown = pairs_all[:n_pairs]
        parts = [
            head,
            f"\n📋 <b>ALL FIELDS</b>\n{fields_block(shown, len(pairs_all) - len(shown), icons) or '<i>-</i>'}",
        ]
        if n_json:
            snippet = raw_json[:n_json] + ("\n…" if len(raw_json) > n_json else "")
            parts.append("\n\n🧾 <b>RAW JSON</b> <i>(tap to expand)</i>\n" + block_expandable_quote(block_code(snippet)))
        parts.append(f"\n\n{DIV}\n{FOOTER}{custom_footer(p)}{delete_note()}")
        text = "".join(parts)
        if len(text) <= MAX_MESSAGE:
            break

    nav: list[InlineKeyboardButton] = []
    if index > 0:
        nav.append(btn("⬅️ Prev", f"d|{key}|{index - 1}"))
    nav.append(btn(f"📌 {index + 1}/{len(result.items)}", "noop", None))
    if index < len(result.items) - 1:
        nav.append(btn("Next ➡️", f"d|{key}|{index + 1}"))

    actions = [btn("💾 Save JSON", f"f|{key}|{index}", "success", CUSTOM_EMOJI["save"])]
    url = item_url(item)
    if url:
        actions.insert(0, link_btn("🔗 Open source", url))
    return text, rich_buttons([nav, actions, [btn("◀️ Back to results", f"p|{key}|{page}")]])


def render_raw(result: SearchResult, requester: str | None, p: dict[str, Any] | None = None) -> str:
    p = p or DEFAULT_PROFILE
    box = [
        f"🎯 <b>Target</b> ▸ <code>{esc(shorten(result.query, 64))}</code>",
        f"📦 <b>Records</b> ▸ <code>{len(result.items)}</code>   ⚡ <code>{result.elapsed_ms} ms</code>",
    ]
    if requester:
        box.append(f"🙋 <b>Requested by</b> ▸ {esc(requester)}")
    header = (
        f"{emoji_html(p)} <b>{esc(str(p['title']).upper())} COMPLETE</b> ✅\n"
        f"{summary_box(box)}\n\n🧾 <b>RAW JSON</b>\n"
    )
    tail = custom_footer(p) + delete_note()
    pretty = json.dumps(masked_copy(result.raw, hide=p.get("hide") or []), indent=2, ensure_ascii=False, default=str)
    room = MAX_MESSAGE - len(header) - len(tail) - 80
    if len(pretty) > room:
        pretty = pretty[: max(0, room)] + "\n…"
    return header + block_code(pretty) + tail


# --------------------------------------------------------------------------- #
# Menu / help                                                                  #
# --------------------------------------------------------------------------- #


def render_menu(user_id: int) -> tuple[str, InlineKeyboardMarkup]:
    recent = list(HISTORY.get(user_id, []))[:4]
    icon = CUSTOM_EMOJI["search"]
    logo = tg_emoji(icon, "🕵️") if icon else "🕵️"
    src = "🟢 Source online" if RUNTIME.get("api_url") else "🔴 No source"
    cmds = [f"<code>/{n}</code>" for n, c in SOURCES.items() if c.get("enabled")]
    cmd_line = f"🧩 <b>Commands</b> ▸ {' '.join(cmds)}\n\n" if cmds else ""
    lock = " · 🔒 Lockdown" if SETTINGS["lockdown"] else ""
    text = (
        f"{logo} <b>{esc(BOT_NAME)}</b>\n"
        "<i>Fast, private, professional intelligence lookups.</i>\n"
        f"{DIV}\n"
        f"{src} · 🧹 Auto-delete {fmt_dur(SETTINGS['auto_delete'])}{lock}\n\n"
        f"{cmd_line}🔎 <b>Send</b> a name, username, email, phone, domain or IP.\n\n"
        "✨ <b>What you get</b>\n"
        "🗂 Clean, readable record cards\n"
        "📑 Paged browsing with a full detail view\n"
        "📥 One-tap JSON export\n"
        "🔐 Auto-masked sensitive fields\n"
        "🧹 Results vanish on their own - nothing lingers\n\n"
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
        btn("❓ Help", "help|0|0", "primary", CUSTOM_EMOJI["help"]),
    ])
    if is_admin(user_id):
        rows.append([btn("🛠 Admin control center", "adm|home|0", "danger")])
    return text, rich_buttons(rows)


def render_help() -> str:
    custom = ""
    enabled = [(n, c) for n, c in SOURCES.items() if c.get("enabled")]
    if enabled:
        custom = "\n\n🧩 <b>Custom commands</b>\n" + "\n".join(
            f"{c.get('emoji') or '▪️'} <code>/{n} &lt;query&gt;</code> ▸ {esc(c.get('title', n))}" for n, c in enabled
        )
    return (
        f"❓ <b>HELP</b>\n{DIV}\n\n"
        "🔎 <b>Searching</b>\n"
        "▪️ Private chat: send a query, or <code>/search &lt;query&gt;</code>\n"
        "▪️ Allowed groups: <code>/num &lt;query&gt;</code>\n\n"
        "📖 <b>Reading results</b>\n"
        "▪️ Name buttons open a record in full\n"
        "▪️ Arrows move between pages and records\n"
        "▪️ 📥 exports what you are viewing as JSON\n"
        f"▪️ 🧹 Results self-destruct after {fmt_dur(SETTINGS['auto_delete'])}\n\n"
        "⌨️ <b>Commands</b>\n"
        "<code>/search</code> <code>/num</code> <code>/recent</code> <code>/usage</code> <code>/menu</code>"
        + custom
        + "\n\n🛠 <b>Admin</b>\n"
        "<code>/admin</code> <code>/groups</code> <code>/allowgroup</code> <code>/denygroup</code>\n"
        "<code>/ban</code> <code>/unban</code> <code>/banned</code> <code>/connect</code> <code>/source</code>\n"
        "<code>/addcmd</code> <code>/cmds</code> <code>/delcmd</code>"
    )


# --------------------------------------------------------------------------- #
# Admin control center renderers                                               #
# --------------------------------------------------------------------------- #

ADMIN_BACK = [btn("⬅️ Control center", "adm|home|0", "primary")]


def render_admin() -> tuple[str, InlineKeyboardMarkup]:
    up = int(time.time() - STATS["started"])
    days, rest = divmod(up, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, _ = divmod(rest, 60)
    uptime = f"{days}d {hours}h {minutes}m" if days else f"{hours}h {minutes}m"
    searches = STATS["searches"]
    hit_rate = f"{round(100 * STATS['hits'] / searches)}%" if searches else "-"
    avg = f"{round(STATS['lat_total'] / STATS['lat_n'])} ms" if STATS["lat_n"] else "-"

    text = (
        f"🛠 <b>CONTROL CENTER</b>\n{DIV}\n\n"
        "📈 <b>PERFORMANCE</b>\n"
        + block_table([
            ("🔎 Lookups", str(searches)),
            ("✅ Hit rate", hit_rate),
            ("⚡ Avg speed", avg),
            ("⚠️ Failures", str(STATS["errors"])),
        ])
        + "\n\n🌐 <b>REACH</b>\n"
        + block_table([
            ("👥 Users", str(len(STATS["users"]))),
            ("🛡 Groups", f"{len(ALLOWED_GROUPS)} allowed · {len(PENDING)} pending"),
            ("🚫 Banned", str(len(BANNED))),
            ("🧩 Custom commands", str(len(SOURCES))),
        ])
        + "\n\n⚙️ <b>STATUS</b>\n"
        + block_table([
            ("🔌 Source", "🟢 connected" if RUNTIME.get("api_url") else "🔴 NOT connected"),
            ("🧹 Auto-delete", fmt_dur(SETTINGS["auto_delete"])),
            ("🔒 Lockdown", "ON" if SETTINGS["lockdown"] else "off"),
            ("🗃 Cached sets", str(len(CACHE))),
            ("⏱ Uptime", uptime),
        ])
        + f"\n\n{DIV}\n<i>Last refreshed {clock()} UTC</i>"
    )
    rows = [
        [btn("⚙️ Settings", "adm|settings|0", "primary"), btn("🛡 Groups", "adm|groups|0", "primary")],
        [btn("🧩 Custom commands", "cx|_.list|0", "success")],
        [btn("📜 Activity log", "adm|activity|0", "primary"), btn("🏆 Top users", "adm|users|0", "primary")],
        [btn("🚫 Ban list", "adm|banned|0", "primary"), btn("🩺 Test source", "adm|ping|0", "success")],
        [btn("🧹 Clear cache", "adm|clear|0", "danger"), btn("📤 Export log", "adm|log|0", "success")],
        [btn("🔄 Refresh", "adm|home|0", "primary"), btn("🏠 Menu", "menu|0|0", "primary")],
    ]
    return text, rich_buttons(rows)


SETTING_KEYS = {
    "ad": "auto_delete", "dq": "delete_queries", "lock": "lockdown", "mem": "members_can_search",
    "raw": "group_raw", "mask": "mask", "cd": "cooldown", "dl": "daily_limit",
}


def _opt_row(code: str, current: float, options: list[tuple[str, float]]) -> list[InlineKeyboardButton]:
    row = []
    for label, value in options:
        selected = float(current) == float(value)
        row.append(btn(f"{'✅ ' if selected else ''}{label}", f"set|{code}|{int(value)}",
                       "success" if selected else "primary"))
    return row


def _toggle(code: str, label: str, on: bool, danger_when_on: bool = False) -> InlineKeyboardButton:
    style = ("danger" if danger_when_on else "success") if on else "primary"
    return btn(f"{'🟢' if on else '⚪'} {label}", f"set|{code}|{0 if on else 1}", style)


def render_settings() -> tuple[str, InlineKeyboardMarkup]:
    s = SETTINGS
    onoff = lambda v: "ON" if v else "off"  # noqa: E731
    text = (
        f"⚙️ <b>SETTINGS</b>\n{DIV}\n"
        + block_table([
            ("🧹 Auto-delete", fmt_dur(s["auto_delete"])),
            ("🗑 Delete queries", onoff(s["delete_queries"])),
            ("🔒 Lockdown", onoff(s["lockdown"])),
            ("👥 Members can search", onoff(s["members_can_search"])),
            ("🧾 Group raw JSON", onoff(s["group_raw"])),
            ("🙈 Field masking", onoff(s["mask"])),
            ("⏱ Cooldown", f"{s['cooldown']:g}s"),
            ("📅 Daily limit", "unlimited" if not s["daily_limit"] else str(s["daily_limit"])),
        ])
        + "\n\n<i>Changes apply instantly and are saved.</i>"
    )
    rows = [
        [btn("🧹 Auto-delete timer", "noop", None)],
        _opt_row("ad", s["auto_delete"], [("Off", 0), ("1m", 60), ("2m", 120), ("5m", 300)]),
        [btn("⏱ Cooldown per user", "noop", None)],
        _opt_row("cd", s["cooldown"], [("1s", 1), ("3s", 3), ("5s", 5), ("10s", 10)]),
        [btn("📅 Daily limit per user", "noop", None)],
        _opt_row("dl", s["daily_limit"], [("∞", 0), ("25", 25), ("50", 50), ("100", 100), ("200", 200)]),
        [_toggle("dq", "Delete queries", s["delete_queries"]), _toggle("mask", "Masking", s["mask"])],
        [_toggle("mem", "Members search", s["members_can_search"]), _toggle("raw", "Group raw JSON", s["group_raw"])],
        [_toggle("lock", "Lockdown mode", s["lockdown"], danger_when_on=True)],
        ADMIN_BACK,
    ]
    return text, rich_buttons(rows)


async def render_groups_view(bot) -> tuple[str, InlineKeyboardMarkup]:
    items = list(ALLOWED_GROUPS.items())[:10]
    statuses = await asyncio.gather(*(bot_status_in(bot, gid) for gid, _ in items))
    lines, rows, ok = [], [], 0
    for (gid, meta), status in zip(items, statuses):
        if status is None:
            mark, note = "❌", "bot not in group"
        else:
            ok += 1
            mark = "✅"
            note = "working · admin" if status == ChatMemberStatus.ADMINISTRATOR else "working"
        lines.append(f"{mark} <b>{esc(meta.get('title', gid))}</b>\n   <code>{gid}</code> · {note}")
        rows.append([btn(f"🚪 Leave · {shorten(meta.get('title', gid), 20)}", f"lg|{gid}|0", "danger")])

    text = (
        f"🛡 <b>GROUP MANAGER</b>\n{DIV}\n"
        f"✅ {ok} working · ❌ {len(items) - ok} inactive · ⏳ {len(PENDING)} pending\n\n"
        + ("\n\n".join(lines) if lines else "<i>No authorized groups yet.</i>")
    )
    if PENDING:
        text += f"\n\n{DIV}\n⏳ <b>WAITING FOR APPROVAL</b>"
        for gid, info in list(PENDING.items())[:8]:
            text += f"\n▪️ <b>{esc(info['title'])}</b> · <code>{gid}</code> · by {esc(info['name'])}"
            rows.insert(0, [
                btn(f"✅ {shorten(info['title'], 16)}", f"ap|{gid}|0", "success"),
                btn("❌ Reject", f"rj|{gid}|0", "danger"),
            ])
    rows.append([btn("🔄 Refresh", "adm|groups|0", "primary")])
    rows.append(ADMIN_BACK)
    return text, rich_buttons(rows)


def render_activity() -> tuple[str, InlineKeyboardMarkup]:
    entries = list(LOG)[-10:][::-1]
    if not entries:
        body = "<i>No lookups yet.</i>"
    else:
        blocks = []
        for e in entries:
            icon = "⚠️" if e["status"] != "ok" else ("✅" if e["hits"] else "🫥")
            blocks.append(
                f"{icon} <code>{clock(e['ts'])}</code> · <b>{esc(shorten(e['name'], 18))}</b> · {esc(shorten(e['where'], 18))}\n"
                f"   🔎 {('<b>/' + esc(e['cmd']) + '</b> ') if e.get('cmd') else ''}<code>{esc(shorten(e['query'], 30))}</code> ▸ {e['hits']} hit(s) · {e['ms']} ms"
            )
        body = "\n\n".join(blocks)
    text = f"📜 <b>ACTIVITY LOG</b> <i>(last {len(entries)})</i>\n{DIV}\n\n{body}"
    return text, rich_buttons([[btn("🔄 Refresh", "adm|activity|0", "primary")], ADMIN_BACK])


def render_top_users() -> tuple[str, InlineKeyboardMarkup]:
    ranked = sorted(USER_STATS.items(), key=lambda kv: kv[1]["count"], reverse=True)[:10]
    medals = ["🥇", "🥈", "🥉"] + ["🔹"] * 7
    if not ranked:
        body = "<i>No activity yet.</i>"
    else:
        body = "\n".join(
            f"{medals[i]} <b>{esc(shorten(info['name'], 22))}</b> · <code>{uid}</code>\n"
            f"   🔎 {info['count']} lookups · last {clock(info['last'])} UTC"
            for i, (uid, info) in enumerate(ranked)
        )
    return f"🏆 <b>TOP USERS</b>\n{DIV}\n\n{body}", rich_buttons([ADMIN_BACK])


def render_banned() -> tuple[str, InlineKeyboardMarkup]:
    ids = sorted(BANNED)[:15]
    if not ids:
        body = "<i>Nobody is banned.</i>\n\nBan someone with <code>/ban &lt;user_id&gt;</code> or by replying to their message with <code>/ban</code>."
    else:
        body = "\n".join(f"🚫 <code>{uid}</code> · {esc(USER_STATS.get(uid, {}).get('name', 'unknown'))}" for uid in ids)
    rows = [[btn(f"✅ Unban {uid}", f"ub|{uid}|0", "success")] for uid in ids]
    rows.append(ADMIN_BACK)
    return f"🚫 <b>BAN LIST</b> <i>({len(BANNED)})</i>\n{DIV}\n\n{body}", rich_buttons(rows)


# --------------------------------------------------------------------------- #
# Search engine                                                                #
# --------------------------------------------------------------------------- #


class ApiError(Exception):
    pass


class NotConfigured(Exception):
    pass


def source_conf(name: str | None) -> tuple[str, dict[str, str]]:
    """Return (url template, headers). Custom sources NEVER receive the default source's headers."""
    if name:
        src = SOURCES.get(name)
        if not src:
            raise NotConfigured
        return src["url"], {str(k): str(v) for k, v in (src.get("headers") or {}).items()}
    return RUNTIME.get("api_url") or "", dict(API_HEADERS)


def build_url(query: str, base: str) -> str:
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
            headers={"Accept": "application/json", "User-Agent": "osint-bot/4.0"},
        )
    return _SESSION


async def run_search(query: str, name: str | None = None) -> SearchResult:
    base, headers = source_conf(name)
    url = build_url(query, base)
    started = time.perf_counter()
    try:
        session = await get_session()
        async with session.get(url, headers=headers) as response:
            body = await response.text()
            if response.status == 404:
                payload: Any = {}
            elif response.status >= 400:
                log.error("source error %s (%s): %s", response.status, name or "default", body[:300])
                raise ApiError("The intelligence source rejected that lookup. Try again shortly.")
            else:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    payload = {"response": shorten(body, 2000)}
    except asyncio.TimeoutError as exc:
        raise ApiError("The source timed out. Please try again in a moment.") from exc
    except aiohttp.ClientError as exc:
        log.error("source unreachable (%s): %s", name or "default", type(exc).__name__)
        raise ApiError("The intelligence source is unreachable right now.") from exc

    elapsed = int((time.perf_counter() - started) * 1000)
    items, meta = extract_items(payload)
    meta.pop("q", None)
    return SearchResult(query=query, items=items, meta=meta, raw=payload, elapsed_ms=elapsed, source=name)


async def search_cached(query: str, name: str | None = None) -> SearchResult:
    key = f"{name or '-'}|{query.strip().lower()}"
    hit = QUERY_CACHE.get(key)
    if hit and time.time() - hit.created_at < QUERY_TTL:
        return hit
    task = INFLIGHT.get(key)
    if task is not None:
        return await asyncio.shield(task)

    task = asyncio.create_task(run_search(query, name))
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


async def ping_source() -> tuple[bool, str]:
    try:
        base, headers = source_conf(None)
        url = build_url("ping-test", base)
    except NotConfigured:
        return False, "🔌 No source connected."
    started = time.perf_counter()
    try:
        session = await get_session()
        async with session.get(url, headers=headers) as response:
            await response.read()
            ms = int((time.perf_counter() - started) * 1000)
            ok = response.status < 400 or response.status == 404
            return ok, f"{'🟢 Healthy' if ok else '🔴 Failing'} · HTTP {response.status} · {ms} ms"
    except asyncio.TimeoutError:
        return False, "🔴 Timed out"
    except aiohttp.ClientError as exc:
        return False, f"🔴 Unreachable ({type(exc).__name__})"


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
        render_help(), reply_markup=rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]])
    )


def usage_numbers(user_id: int) -> tuple[int, str]:
    day, count = USAGE.get(user_id, (today_utc(), 0))
    if day != today_utc():
        count = 0
    limit = int(SETTINGS["daily_limit"])
    left = "unlimited" if not limit or is_admin(user_id) else str(max(0, limit - count))
    return count, left


async def cmd_usage(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    count, left = usage_numbers(uid_of(update))
    await update.effective_message.reply_html(
        f"📊 <b>YOUR USAGE</b>\n{DIV}\n"
        + block_table([
            ("🔎 Lookups today", str(count)),
            ("🎟 Remaining", left),
            ("⏱ Cooldown", f"{SETTINGS['cooldown']:g}s"),
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


async def do_search(update: Update, query: str, force_cards: bool = False,
                    source: str | None = None) -> None:
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    user_id = user.id if user else 0
    group = bool(chat and chat.type in GROUP_TYPES)
    query = (query or "").strip()[:200]
    bot = message.get_bot()
    p = profile(source)
    min_len = int(p.get("min_len") or MIN_QUERY)

    if SETTINGS["lockdown"] and not is_admin(user_id):
        await message.reply_html("🛠 <b>Maintenance</b>\nLookups are paused for a moment. Please try again soon.")
        return
    if len(query) < min_len:
        await message.reply_html(f"🔎 Please provide at least <b>{min_len}</b> characters.")
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
        f"{emoji_html(p)} <b>Scanning…</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n"
        "▰▰▱▱▱ <i>querying source</i>"
    )

    delay = SETTINGS["auto_delete"]
    if delay:
        autodelete(bot, placeholder, delay=delay)
        if SETTINGS["delete_queries"] and update.message is not None:
            autodelete(bot, update.message, delay=delay)

    started = time.perf_counter()
    try:
        result = await search_cached(query, source)
    except NotConfigured:
        record_activity(user, chat, query, 0, 0, "unconfigured", source)
        await placeholder.edit_text(
            "🔌 <b>No source connected yet.</b>\nThe operator has to connect one first.",
            parse_mode=ParseMode.HTML,
        )
        return
    except ApiError as exc:
        STATS["errors"] += 1
        record_activity(user, chat, query, 0, int((time.perf_counter() - started) * 1000), "error", source)
        await placeholder.edit_text(f"⚠️ {esc(exc)}", parse_mode=ParseMode.HTML)
        return
    except Exception:  # noqa: BLE001
        STATS["errors"] += 1
        log.exception("lookup failed")
        record_activity(user, chat, query, 0, 0, "error", source)
        await placeholder.edit_text("💥 Something went wrong on our side. Please try again.")
        return

    STATS["searches"] += 1
    STATS["lat_total"] += result.elapsed_ms
    STATS["lat_n"] += 1
    if source is None:
        remember(user_id, query)
    record_activity(user, chat, query, len(result.items), result.elapsed_ms, "ok", source)

    if not result.items:
        await placeholder.edit_text(
            f"🫥 <b>No records</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n"
            "<i>Try a different spelling, a username, or a full email address.</i>"
            + delete_note(),
            parse_mode=ParseMode.HTML,
            reply_markup=None if group else rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]]),
        )
        return

    STATS["hits"] += 1
    requester = display_name(user) if group else None

    if group and SETTINGS["group_raw"] and not force_cards:
        await placeholder.edit_text(
            render_raw(result, requester, p), parse_mode=ParseMode.HTML, link_preview_options=NO_PREVIEW
        )
        return

    key = cache_put(result, user_id, group, requester, source)
    if delay:
        spawn(_forget_later(key, delay + 5))
    text, markup = render_results(key, result, 0)
    await placeholder.edit_text(
        text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW
    )


async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await do_search(update, " ".join(context.args or []))


async def cmd_num(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = " ".join(context.args or [])
    if not query and update.effective_message.reply_to_message:
        query = update.effective_message.reply_to_message.text or ""
    await do_search(update, query)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if is_admin(uid_of(update)) and await handle_input(update, context):
        return
    await do_search(update, update.effective_message.text or "")


async def on_custom_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Dispatches owner-defined commands such as /tg <query>."""
    msg = update.effective_message
    m = re.match(r"^/(\w+)(?:@(\w+))?(?:\s+(.*))?$", msg.text or "", re.S)
    if not m:
        return
    name, target = m.group(1).lower(), m.group(2)
    if target and context.bot.username and target.lower() != context.bot.username.lower():
        return
    src = SOURCES.get(name)
    if not src or not src.get("enabled"):
        return
    query = (m.group(3) or "").strip()
    if not query and msg.reply_to_message:
        query = msg.reply_to_message.text or ""
    if not query:
        await msg.reply_html(
            f"{emoji_html(src)} <b>{esc(src['title'])}</b>\nUsage: <code>/{name} &lt;query&gt;</code>"
        )
        return
    await do_search(update, query, source=name)


# --------------------------------------------------------------------------- #
# Admin command handlers                                                       #
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
    msg = await update.effective_message.reply_html(
        "🔐 <b>Connected source</b> (admin only)\n" + block_expandable_quote(f"<code>{esc(url)}</code>")
    )
    autodelete(msg.get_bot(), msg, update.effective_message, delay=60)


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
        f"✅ <b>Authorized</b>\n{block_table([('👥 Group', title or str(gid)), ('🆔 ID', str(gid))])}"
    )


async def cmd_denygroup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        gid = int(context.args[0])
    except (IndexError, ValueError):
        await update.effective_message.reply_html("Usage: <code>/denygroup &lt;chat_id&gt;</code>")
        return
    removed = PENDING.pop(gid, None) is not None
    removed = revoke_group(gid) or removed
    try:
        await context.bot.leave_chat(gid)
    except TelegramError:
        pass
    await update.effective_message.reply_html(
        "🗑 Revoked &amp; left." if removed else "That group wasn't authorized (left it anyway if I was in it)."
    )


async def cmd_groups(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = await render_groups_view(context.bot)
    await update.effective_message.reply_html(text, reply_markup=markup)


async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    target = None
    reply = update.effective_message.reply_to_message
    if reply and reply.from_user:
        target = reply.from_user.id
        USER_STATS.setdefault(target, {"name": reply.from_user.full_name, "count": 0, "last": 0.0})
    elif context.args and context.args[0].lstrip("-").isdigit():
        target = int(context.args[0])
    if target is None:
        await update.effective_message.reply_html(
            "Usage: <code>/ban &lt;user_id&gt;</code> or reply to a message with <code>/ban</code>"
        )
        return
    if is_admin(target):
        await update.effective_message.reply_html("🛡 You can't ban an admin.")
        return
    BANNED.add(target)
    save_state()
    await update.effective_message.reply_html(f"🚫 <b>Banned</b> <code>{target}</code>")


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.effective_message.reply_html("Usage: <code>/unban &lt;user_id&gt;</code>")
        return
    target = int(context.args[0])
    BANNED.discard(target)
    save_state()
    await update.effective_message.reply_html(f"✅ <b>Unbanned</b> <code>{target}</code>")


async def cmd_banned(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_banned()
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
# Custom commands - owner-defined APIs, configured entirely inside Telegram    #
# --------------------------------------------------------------------------- #

ADMIN_COMMANDS = [
    BotCommand("start", "Open the main menu"),
    BotCommand("search", "Run an OSINT lookup"),
    BotCommand("recent", "Your recent lookups"),
    BotCommand("usage", "Your usage"),
    BotCommand("admin", "Admin control center"),
    BotCommand("cmds", "Manage custom commands"),
    BotCommand("addcmd", "Add a custom command"),
    BotCommand("delcmd", "Delete a custom command"),
    BotCommand("groups", "Manage groups"),
    BotCommand("allowgroup", "Authorize a group"),
    BotCommand("denygroup", "Revoke a group"),
    BotCommand("ban", "Ban a user"),
    BotCommand("unban", "Unban a user"),
    BotCommand("banned", "Show the ban list"),
    BotCommand("connect", "Connect the default data source"),
    BotCommand("source", "Show the default source"),
    BotCommand("emojiid", "Extract a custom emoji's ID"),
    BotCommand("help", "Help"),
]


async def refresh_commands(bot) -> None:
    """Push the command menus (groups + admins) so /tg etc. show up in Telegram's menu."""
    custom = []
    for name, src in SOURCES.items():
        if src.get("enabled"):
            desc = shorten(f"{src.get('emoji') or ''} {src.get('title') or name}".strip(), 200)
            custom.append(BotCommand(name, desc or name))
    custom = custom[:60]
    try:
        await bot.delete_my_commands()
        group_cmds = [BotCommand("num", "Run an OSINT lookup")] + custom
        await bot.set_my_commands(group_cmds, scope=BotCommandScopeAllGroupChats())
        await bot.set_my_commands(group_cmds, scope=BotCommandScopeAllChatAdministrators())
    except TelegramError as exc:
        log.warning("could not set base commands: %s", exc)
    for admin_id in ADMIN_IDS:
        try:
            await bot.set_my_commands(ADMIN_COMMANDS + custom, scope=BotCommandScopeChat(admin_id))
        except TelegramError as exc:
            log.warning("could not set admin commands for %s: %s", admin_id, exc)


def render_cmd_list() -> tuple[str, InlineKeyboardMarkup]:
    if SOURCES:
        lines = [
            f"{'🟢' if s.get('enabled') else '⚪'} {esc(s.get('emoji') or '')} <b>/{n}</b> ▸ {esc(s.get('title', n))} · <code>{esc(host_of(s['url']))}</code>"
            for n, s in SOURCES.items()
        ]
        body = "\n".join(lines)
    else:
        body = "<i>None yet.</i>\nTap ➕ below, or send <code>/addcmd tg https://api.example.com/x?q={q}</code>"
    text = (
        f"🧩 <b>CUSTOM COMMANDS</b>\n{DIV}\n"
        "<i>Each command is its own API with its own look. Everything is edited right here.</i>\n\n" + body
    )
    rows = [
        [btn(f"{s.get('emoji') or '🧩'} /{n} · {shorten(s.get('title', n), 16)}", f"cx|{n}.view|0",
             "primary" if s.get("enabled") else None)]
        for n, s in SOURCES.items()
    ]
    rows.append([btn("➕ New command", "cx|_.new|0", "success")])
    rows.append(ADMIN_BACK)
    return text, rich_buttons(rows)


def render_cmd_panel(name: str) -> tuple[str, InlineKeyboardMarkup]:
    s = SOURCES[name]
    icons = ", ".join(f"{k}={v}" for k, v in (s.get("icons") or {}).items()) or "defaults"
    hide = ", ".join(s.get("hide") or []) or "none"
    headers = f"{len(s.get('headers') or {})} set" if s.get("headers") else "none"
    style = s.get("style", "primary")
    text = (
        f"{emoji_html(s)} <b>/{name}</b> · <b>{esc(s['title'])}</b>\n{DIV}\n"
        + tree([
            f"😀 <b>Emoji</b> ▸ {emoji_html(s)}{' <i>(premium)</i>' if s.get('emoji_id') else ''}",
            f"🏷 <b>Title</b> ▸ <code>{esc(s['title'])}</code>",
            f"🔗 <b>API</b> ▸ <code>{esc(host_of(s['url']))}</code>",
            f"🎨 <b>Button colour</b> ▸ <code>{esc(style)}</code>",
            f"🧾 <b>Field icons</b> ▸ <code>{esc(shorten(icons, 80))}</code>",
            f"🙈 <b>Hidden fields</b> ▸ <code>{esc(shorten(hide, 80))}</code>",
            f"📝 <b>Footer</b> ▸ <code>{esc(shorten(s.get('footer') or 'none', 60))}</code>",
            f"🔢 <b>Min length</b> ▸ <code>{s.get('min_len')}</code>",
            f"🔑 <b>Headers</b> ▸ <code>{headers}</code>",
            f"📶 <b>Status</b> ▸ {'🟢 enabled' if s.get('enabled') else '⚪ disabled'}",
        ])
        + f"\n\n▶️ Usage: <code>/{name} &lt;query&gt;</code>"
    )
    n = name
    rows = [
        [btn("😀 Emoji", f"cx|{n}.emoji|0"), btn("🏷 Title", f"cx|{n}.title|0")],
        [btn("🔗 Change API", f"cx|{n}.url|0"), btn("👁 Reveal API", f"cx|{n}.reveal|0")],
        [btn("🎨 Button colour", f"cx|{n}.style|0"), btn("🧾 Field icons", f"cx|{n}.icons|0")],
        [btn("🙈 Hide fields", f"cx|{n}.hide|0"), btn("📝 Footer", f"cx|{n}.footer|0")],
        [btn("🔢 Min length", f"cx|{n}.minlen|0"), btn("🔑 Headers", f"cx|{n}.headers|0")],
        [btn("🧪 Test", f"cx|{n}.test|0", "success"),
         btn("⚪ Disable" if s.get("enabled") else "🟢 Enable", f"cx|{n}.toggle|0",
             "primary" if s.get("enabled") else "success")],
        [btn("🗑 Delete", f"cx|{n}.del|0", "danger")],
        [btn("⬅️ Commands", "cx|_.list|0")],
    ]
    return text, rich_buttons(rows)


PROMPTS = {
    "new_name": "➕ <b>New command</b>\nSend the command name, e.g. <code>tg</code> (a-z, 0-9, _ · 2-32 chars).",
    "new_url": "🔗 <b>API URL</b>\nSend the API URL. Put <code>{q}</code> where the query goes, e.g.\n<code>https://api.example.com/tg?id={q}</code>\n<i>Your message is deleted instantly.</i>",
    "title": "🏷 <b>Title</b>\nSend the new title, e.g. <code>Telegram Lookup</code>.",
    "emoji": "😀 <b>Header emoji</b>\nSend one emoji. Premium custom emoji work too (shown if the bot owner has Premium).",
    "url": "🔗 <b>API URL</b>\nSend the new URL with <code>{q}</code> as the query placeholder.\n<i>Your message is deleted instantly.</i>",
    "icons": "🧾 <b>Field icons</b>\nOne per line as <code>keyword=emoji</code>, e.g.\n<code>phone=☎️</code>\n<code>email=💌</code>\nSend <code>clear</code> to reset to defaults.",
    "hide": "🙈 <b>Hide fields</b>\nSend comma-separated keywords, e.g. <code>password, hash, id</code>.\nSend <code>clear</code> to show everything.",
    "footer": "📝 <b>Footer note</b>\nSend the text shown under every result, or <code>clear</code>.",
    "minlen": "🔢 <b>Minimum query length</b>\nSend a number from 1 to 64.",
    "headers": "🔑 <b>Request headers</b>\nSend a JSON object, e.g. <code>{\"x-api-key\": \"abc\"}</code>, or <code>clear</code>.\n<i>Stored privately and never shown. Your message is deleted instantly.</i>",
    "test": "🧪 <b>Test</b>\nSend a sample query and I'll run it through this command.",
}


def prompt_markup(name: str | None) -> InlineKeyboardMarkup:
    return rich_buttons([[btn("✖️ Cancel", f"cx|{name or '_'}.cancel|0", "danger")]])


async def _show(context, st: dict[str, Any], text: str, markup: InlineKeyboardMarkup) -> None:
    try:
        await context.bot.edit_message_text(
            text, chat_id=st["chat"], message_id=st["mid"], parse_mode=ParseMode.HTML,
            reply_markup=markup, link_preview_options=NO_PREVIEW,
        )
    except TelegramError:
        await context.bot.send_message(
            st["chat"], text, parse_mode=ParseMode.HTML, reply_markup=markup,
            link_preview_options=NO_PREVIEW,
        )


def _panel_or_list(name: str | None) -> tuple[str, InlineKeyboardMarkup]:
    return render_cmd_panel(name) if name and name in SOURCES else render_cmd_list()


async def handle_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Consumes the admin's next text message when a prompt is pending. Returns True if handled."""
    msg = update.effective_message
    uid = update.effective_user.id
    st = INPUT.get(uid)
    if not st:
        return False
    if time.time() - st["ts"] > INPUT_TTL:
        INPUT.pop(uid, None)
        return False
    text = (msg.text or "").strip()
    op, name = st["op"], st.get("cmd")

    if op == "test":
        INPUT.pop(uid, None)
        await _show(context, st, *_panel_or_list(name))
        if name in SOURCES:
            await do_search(update, text, source=name)
        return True

    try:
        await msg.delete()  # keep URLs / keys out of the chat history
    except TelegramError:
        pass

    if text.lower() == "cancel":
        INPUT.pop(uid, None)
        await _show(context, st, *_panel_or_list(name))
        return True

    err: str | None = None
    src = SOURCES.get(name) if name else None

    if op == "new_name":
        n = text.lower().lstrip("/")
        if not CMD_RE.match(n):
            err = "Use 2-32 characters: a-z, 0-9, _ (start with a letter)."
        elif n in RESERVED or n in SOURCES:
            err = "That name is reserved or already used."
        else:
            INPUT[uid] = {**st, "op": "new_url", "cmd": n, "ts": time.time()}
            await _show(context, st, f"/{n} ✔️\n\n" + PROMPTS["new_url"], prompt_markup(n))
            return True
    elif op == "new_url":
        if not text.startswith(("http://", "https://")) or len(text) > 2000:
            err = "That is not a valid http(s) URL."
        else:
            SOURCES[name] = new_source(name, text)
            save_state()
            QUERY_CACHE.clear()
            INPUT.pop(uid, None)
            await refresh_commands(context.bot)
            await _show(context, st, f"✅ <b>/{name} created.</b> Customise it below.\n\n" + render_cmd_panel(name)[0],
                        render_cmd_panel(name)[1])
            return True
    elif src is None:
        INPUT.pop(uid, None)
        await _show(context, st, *render_cmd_list())
        return True
    elif op == "title":
        src["title"] = shorten(text, 40) or src["title"]
    elif op == "emoji":
        ents = [e for e in (msg.entities or []) if e.type == "custom_emoji"]
        if ents:
            src["emoji_id"] = ents[0].custom_emoji_id
            src["emoji"] = msg.parse_entity(ents[0]) or "🛰"
        elif text:
            src["emoji"], src["emoji_id"] = text.split()[0][:16], None
        else:
            err = "Send an emoji."
    elif op == "url":
        if not text.startswith(("http://", "https://")) or len(text) > 2000:
            err = "That is not a valid http(s) URL."
        else:
            src["url"] = text
    elif op == "icons":
        if text.lower() == "clear":
            src["icons"] = {}
        else:
            found = {}
            for part in re.split(r"[\n,;]+", text):
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k.strip() and v.strip():
                        found[k.strip().lower()] = v.strip()[:16]
            if found:
                src["icons"] = {**src.get("icons", {}), **found}
            else:
                err = "Use <code>keyword=emoji</code>, one per line."
    elif op == "hide":
        src["hide"] = [] if text.lower() == "clear" else [
            h.strip().lower() for h in re.split(r"[,\n]+", text) if h.strip()
        ][:30]
    elif op == "footer":
        src["footer"] = "" if text.lower() == "clear" else shorten(text, 160)
    elif op == "minlen":
        if text.isdigit() and 1 <= int(text) <= 64:
            src["min_len"] = int(text)
        else:
            err = "Send a number from 1 to 64."
    elif op == "headers":
        if text.lower() == "clear":
            src["headers"] = {}
        else:
            try:
                parsed = json.loads(text)
                if not isinstance(parsed, dict):
                    raise ValueError
                src["headers"] = {str(k): str(v) for k, v in parsed.items()}
            except ValueError:
                err = "Send a valid JSON object."

    if err:
        await _show(context, st, f"⚠️ {err}\n\n" + PROMPTS.get(op, ""), prompt_markup(name))
        return True

    INPUT.pop(uid, None)
    save_state()
    QUERY_CACHE.clear()
    if op in {"title", "emoji"}:
        await refresh_commands(context.bot)
    await _show(context, st, *_panel_or_list(name))
    return True


async def handle_cx(update: Update, context: ContextTypes.DEFAULT_TYPE, key: str) -> None:
    query = update.callback_query
    uid = query.from_user.id
    name, _, op = key.partition(".")

    if op == "list":
        INPUT.pop(uid, None)
        await query.answer()
        await _safe_edit(query, *render_cmd_list())
        return
    if op == "new":
        await query.answer()
        INPUT[uid] = {"op": "new_name", "cmd": None, "chat": query.message.chat_id,
                      "mid": query.message.message_id, "ts": time.time()}
        await _safe_edit(query, PROMPTS["new_name"], prompt_markup(None))
        return
    if op == "cancel":
        INPUT.pop(uid, None)
        await query.answer("Cancelled")
        await _safe_edit(query, *_panel_or_list(name))
        return

    src = SOURCES.get(name)
    if not src:
        await query.answer("That command no longer exists.", show_alert=True)
        await _safe_edit(query, *render_cmd_list())
        return

    if op == "view":
        INPUT.pop(uid, None)
        await query.answer()
        await _safe_edit(query, *render_cmd_panel(name))
    elif op in PROMPTS:
        await query.answer()
        INPUT[uid] = {"op": op, "cmd": name, "chat": query.message.chat_id,
                      "mid": query.message.message_id, "ts": time.time()}
        await _safe_edit(query, PROMPTS[op], prompt_markup(name))
    elif op == "style":
        src["style"] = STYLE_CYCLE[(STYLE_CYCLE.index(src.get("style", "primary")) + 1) % len(STYLE_CYCLE)] \
            if src.get("style") in STYLE_CYCLE else "primary"
        save_state()
        await query.answer(f"Button colour: {src['style']}")
        await _safe_edit(query, *render_cmd_panel(name))
    elif op == "toggle":
        src["enabled"] = not src.get("enabled", True)
        save_state()
        await refresh_commands(context.bot)
        await query.answer("Enabled ✅" if src["enabled"] else "Disabled")
        await _safe_edit(query, *render_cmd_panel(name))
    elif op == "reveal":
        await query.answer("Sent below - auto-deletes in 60s", show_alert=False)
        sent = await context.bot.send_message(
            query.message.chat_id,
            f"🔐 <b>/{esc(name)} API</b> (admin only)\n" + block_expandable_quote(f"<code>{esc(src['url'])}</code>"),
            parse_mode=ParseMode.HTML, link_preview_options=NO_PREVIEW,
        )
        autodelete(context.bot, sent, delay=60)
    elif op == "del":
        await query.answer()
        await _safe_edit(
            query,
            f"🗑 <b>Delete /{esc(name)}?</b>\nThis removes the command and its settings. This cannot be undone.",
            rich_buttons([[btn("🗑 Yes, delete", f"cx|{name}.delok|0", "danger"),
                           btn("↩️ Keep it", f"cx|{name}.view|0", "success")]]),
        )
    elif op == "delok":
        SOURCES.pop(name, None)
        save_state()
        QUERY_CACHE.clear()
        await refresh_commands(context.bot)
        await query.answer("Deleted")
        await _safe_edit(query, *render_cmd_list())
    else:
        await query.answer("Unsupported button.")


async def cmd_addcmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args or []
    if len(args) < 2:
        await update.effective_message.reply_html(
            "Usage: <code>/addcmd &lt;name&gt; &lt;url-with-{q}&gt;</code>\n"
            "Example: <code>/addcmd tg https://api.example.com/tg?id={q}</code>"
        )
        return
    name, url = args[0].lower().lstrip("/"), args[1]
    err = None
    if not CMD_RE.match(name):
        err = "Name must be 2-32 chars: a-z, 0-9, _ (start with a letter)."
    elif name in RESERVED or name in SOURCES:
        err = "That name is reserved or already used."
    elif not url.startswith(("http://", "https://")):
        err = "The URL must start with http:// or https://"
    if err:
        await update.effective_message.reply_html(f"⚠️ {err}")
        return
    SOURCES[name] = new_source(name, url)
    save_state()
    QUERY_CACHE.clear()
    try:
        await update.effective_message.delete()  # hide the URL
    except TelegramError:
        pass
    await refresh_commands(context.bot)
    text, markup = render_cmd_panel(name)
    await context.bot.send_message(
        update.effective_user.id, f"✅ <b>/{name} created.</b> Customise it below.\n\n" + text,
        parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW,
    )


async def cmd_cmds(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_cmd_list()
    await update.effective_message.reply_html(text, reply_markup=markup)


async def cmd_delcmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    name = (context.args[0].lower().lstrip("/") if context.args else "")
    if name not in SOURCES:
        await update.effective_message.reply_html("Usage: <code>/delcmd &lt;name&gt;</code> (see /cmds)")
        return
    SOURCES.pop(name)
    save_state()
    QUERY_CACHE.clear()
    await refresh_commands(context.bot)
    await update.effective_message.reply_html(f"🗑 <b>/{esc(name)}</b> deleted.")


async def cmd_cancel(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    INPUT.pop(uid_of(update), None)
    await update.effective_message.reply_html("✖️ Cancelled.")


# --------------------------------------------------------------------------- #
# Callbacks                                                                    #
# --------------------------------------------------------------------------- #

KEYED_ACTIONS = {"p", "d", "x", "f", "close"}
ADMIN_ACTIONS = {"adm", "set", "ub", "lg", "ap", "rj", "cx"}


async def _safe_edit(query, text: str, markup: InlineKeyboardMarkup | None) -> None:
    try:
        await query.edit_message_text(
            text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW
        )
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            log.warning("edit failed: %s", exc)


async def handle_admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                action: str, key: str, index: int) -> None:
    query = update.callback_query
    user_id = query.from_user.id
    done = InlineKeyboardMarkup([])

    if action == "cx":
        await handle_cx(update, context, key)
        return

    if action == "adm":
        if key == "ping":
            await query.answer("Testing source…")
            _, info = await ping_source()
            await query.answer(info[:190], show_alert=True)
            return
        if key == "clear":
            n = len(CACHE) + len(QUERY_CACHE)
            CACHE.clear(); META.clear(); QUERY_CACHE.clear()  # noqa: E702
            await query.answer(f"🧹 Cleared {n} cached item(s).", show_alert=True)
            key = "home"
        elif key == "log":
            payload = {
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "stats": {k: v for k, v in STATS.items() if k != "users"} | {"unique_users": len(STATS["users"])},
                "settings": SETTINGS,
                "banned": sorted(BANNED),
                "activity": list(LOG),
            }
            blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
            await query.answer("Preparing log…")
            sent = await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=InputFile(io.BytesIO(blob), filename="osint_bot_log.json"),
                caption="📤 <b>ACTIVITY LOG EXPORT</b>\n⏳ <i>Self-destructs in 2 min</i>",
                parse_mode=ParseMode.HTML,
            )
            autodelete(context.bot, sent, delay=120)
            return
        else:
            await query.answer()

        if key == "settings":
            text, markup = render_settings()
        elif key == "groups":
            text, markup = await render_groups_view(context.bot)
        elif key == "activity":
            text, markup = render_activity()
        elif key == "users":
            text, markup = render_top_users()
        elif key == "banned":
            text, markup = render_banned()
        else:
            text, markup = render_admin()
        await _safe_edit(query, text, markup)
        return

    if action == "set":
        name = SETTING_KEYS.get(key)
        if not name:
            await query.answer("Unknown setting.")
            return
        current = SETTINGS[name]
        SETTINGS[name] = bool(index) if isinstance(current, bool) else type(current)(index)
        save_state()
        await query.answer("Saved ✅")
        text, markup = render_settings()
        await _safe_edit(query, text, markup)
        return

    if action == "ub":
        BANNED.discard(int(key))
        save_state()
        await query.answer("Unbanned ✅")
        text, markup = render_banned()
        await _safe_edit(query, text, markup)
        return

    if action == "lg":
        gid = int(key)
        PENDING.pop(gid, None)
        revoke_group(gid)
        try:
            await context.bot.leave_chat(gid)
        except TelegramError:
            pass
        await query.answer("Left & revoked ✅")
        text, markup = await render_groups_view(context.bot)
        await _safe_edit(query, text, markup)
        return

    if action in {"ap", "rj"}:
        try:
            gid = int(key)
        except ValueError:
            await query.answer("Bad request.")
            return
        info = PENDING.get(gid) or ALLOWED_GROUPS.get(gid) or {}
        title = info.get("title") or str(gid)
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
                f"✅ <b>APPROVED</b>\n{DIV}\n" + block_table([("👥 Group", title), ("🆔 ID", str(gid))]),
                done,
            )
            try:
                await context.bot.send_message(
                    gid, "✅ <b>Approved.</b>\nUse <code>/num &lt;query&gt;</code> to run a lookup.",
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
                f"🚫 <b>REJECTED &amp; LEFT</b>\n{DIV}\n" + block_table([("👥 Group", title), ("🆔 ID", str(gid))]),
                done,
            )


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

    if action in ADMIN_ACTIONS:
        if not is_admin(user_id):
            await query.answer("Not available.", show_alert=True)
            return
        try:
            await handle_admin_callback(update, context, action, key, index)
        except (ValueError, TypeError):
            await query.answer("Bad request.")
        return

    chat_type = query.message.chat.type if query.message else None
    in_group = chat_type in GROUP_TYPES

    if action in KEYED_ACTIONS and in_group and not is_admin(user_id):
        meta = META.get(key)
        if meta is None or meta["owner"] != user_id:
            who = meta["by"] if meta and meta.get("by") else "the person who ran the search"
            await query.answer(f"🔒 Only {who} can use these buttons.", show_alert=True)
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
        await _safe_edit(query, render_help(), rich_buttons([[btn("🏠 Menu", "menu|0|0", "primary")]]))
        return

    if action == "usage":
        count, left = usage_numbers(user_id)
        await query.answer(f"Today: {count} lookups · remaining: {left}", show_alert=True)
        return

    if action == "h":
        stored = next((q for q in HISTORY.get(user_id, []) if qtoken(q) == key), None)
        await query.answer("Searching…" if stored else "That query expired.")
        if stored:
            await do_search(update, stored)
        return

    result = CACHE.get(key)
    if not result:
        await query.answer("This result expired - run the lookup again.", show_alert=True)
        return

    if action in {"x", "f"}:
        record = min(index, len(result.items) - 1)
        payload = export_payload(result, None if action == "x" else record)
        blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", result.query)[:40] or "lookup"
        name = f"{safe}_results.json" if action == "x" else f"{safe}_record_{record + 1}.json"
        await query.answer("Preparing file…")
        sent = await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=InputFile(io.BytesIO(blob), filename=name),
            caption=(
                "📥 <b>EXPORT READY</b>\n"
                f"🎯 <code>{esc(shorten(result.query, 50))}</code>\n"
                f"📦 {'Full result set · ' + str(len(result.items)) + ' records' if action == 'x' else 'Record ' + str(record + 1)}"
                + delete_note()
            ),
            parse_mode=ParseMode.HTML,
        )
        autodelete(context.bot, sent)
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
    await refresh_commands(bot)

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
            ("🔌 Source", "connected" if RUNTIME["api_url"] else "NOT connected"),
            ("🛡 Groups", str(len(ALLOWED_GROUPS))),
            ("🧹 Auto-delete", fmt_dur(SETTINGS["auto_delete"])),
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
    load_state()
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

    app.add_handler(TypeHandler(Update, access_gate), group=-1)
    app.add_handler(ChatMemberHandler(on_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER))

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
    app.add_handler(CommandHandler("banned", cmd_banned, filters=private))
    app.add_handler(CommandHandler("num", cmd_num))
    app.add_handler(CommandHandler("allowgroup", cmd_allowgroup))  # admin-checked; works in groups
    app.add_handler(CommandHandler("ban", cmd_ban))                # admin-checked; reply-to-ban in groups
    app.add_handler(CommandHandler("unban", cmd_unban))
    app.add_handler(CommandHandler("addcmd", cmd_addcmd, filters=private))
    app.add_handler(CommandHandler("cmds", cmd_cmds, filters=private))
    app.add_handler(CommandHandler("delcmd", cmd_delcmd, filters=private))
    app.add_handler(CommandHandler("cancel", cmd_cancel, filters=private))
    app.add_handler(MessageHandler(filters.COMMAND, on_custom_command))  # owner-defined commands (/tg ...)

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
