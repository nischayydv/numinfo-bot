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

Storage
-------
Set MONGODB_URI (and optionally MONGODB_DB) and the bot keeps groups, approvals, custom commands,
settings, bans, protected queries and per-user usage counters in MongoDB. Without it (or if the
database is unreachable) it falls back to local JSON files.

Reliability & safety
--------------------
Circuit breaker (auto-pauses a failing API and alerts admins), backup-API failover, timed
maintenance, abuse guard (strikes -> automatic temporary ban), temp bans with reasons, per-user
limit overrides, per-group mute / daily cap / command allow-list, persistent audit log (TTL),
daily digest, /broadcast to groups, /backup export, user opt-out requests (/optout).

Manual values & grants
----------------------
Every limit (cooldown, daily limit, auto-delete, cache, maintenance) has presets AND a '✏️ Custom'
button, per command and globally. /grant gives any person unlimited or a custom daily limit on one
command or all of them (optionally for a limited time); /revoke, /grants and a guided builder in the
Control center manage them.

Per-command control
-------------------
Every custom command has its own cooldown, per-user daily limit, auto-delete timer, no-logging
switch and blocked-query list; anything left on 'global' follows /admin -> Settings.
Protected queries (/block, /unblock or Control center) are refused on EVERY command.

Environment variables
---------------------
BOT_TOKEN, ADMIN_IDS (required)
MONGODB_URI, MONGODB_DB (default osint_bot)
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
from datetime import datetime, timedelta, timezone
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
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB = os.environ.get("MONGODB_DB", "osint_bot").strip() or "osint_bot"
AUDIT_DAYS = int(os.environ.get("AUDIT_DAYS", "30"))
DIGEST_HOUR = int(os.environ.get("DIGEST_HOUR_UTC", "0"))
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
    "no_log": _env_bool("NO_LOG"),  # never keep query text in logs / history
    "abuse_guard": True, "strike_limit": 8, "ban_minutes": 60,   # auto temp-ban after N strikes / 10 min
    "breaker_fails": 5, "breaker_minutes": 5,                    # circuit breaker
    "audit": True, "digest": True,
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
LAST_CALL: dict[tuple[int, str], float] = {}          # (user, command) -> last call
USAGE: dict[tuple[int, str], tuple[str, int]] = {}    # (user, command) -> (day, count)
RUNTIME: dict[str, Any] = {"api_url": SEARCH_API_URL}
STATS: dict[str, Any] = {
    "searches": 0, "hits": 0, "errors": 0, "lat_total": 0, "lat_n": 0,
    "started": time.time(), "users": set(),
}
LOG: deque[dict[str, Any]] = deque(maxlen=100)  # activity / audit log
USER_STATS: dict[int, dict[str, Any]] = {}
BANNED: set[int] = set()
SOURCES: dict[str, dict[str, Any]] = {}  # owner-defined custom commands
BLOCKED: set[str] = set()                # protected queries (normalised) - refused on every command
STORE: Any = None
STORAGE: dict[str, Any] = {"kind": "files", "errors": 0, "note": ""}
BAN_INFO: dict[int, dict[str, Any]] = {}      # uid -> {until, reason, by}   (until 0 = permanent)
USER_LIMITS: dict[int, int] = {}              # uid -> daily limit override for ALL commands (0 = unlimited)
SRC_STATS: dict[str, dict[str, int]] = {}     # command ("-" = default) -> n / hits / err / lat
BREAKER: dict[str, dict[str, Any]] = {}       # command -> {fails, until, alerted}
STRIKES: dict[int, deque] = {}                # uid -> timestamps of recent violations
OPTOUTS: dict[str, dict[str, Any]] = {}       # pending opt-out requests
OPTOUT_COUNT: dict[tuple[int, str], int] = {}
BROADCAST: dict[int, str] = {}
GRANTS: dict[tuple[int, str], dict[str, Any]] = {}   # (user, command | '-' default | '*' all) -> {limit, until, by}
GRANT_DRAFT: dict[int, dict[str, Any]] = {}          # admin id -> grant being built in the UI
DIGEST: dict[str, Any] = {"day": today_utc(), "base": {"searches": 0, "hits": 0, "errors": 0, "users": 0, "src": {}}}
INPUT: dict[int, dict[str, Any]] = {}    # admin id -> pending text-input state
INPUT_TTL = 300

RESERVED = {
    "start", "menu", "help", "search", "recent", "usage", "emojiid", "admin", "connect", "source",
    "groups", "denygroup", "allowgroup", "banned", "ban", "unban", "num", "addcmd", "cmds",
    "delcmd", "cancel", "block", "unblock",
    "setlimit", "limits", "broadcast", "backup", "audit", "optout", "grant", "revoke", "grants",
}
CMD_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
STYLE_CYCLE = ["primary", "success", "danger", "default"]
SOURCE_DEFAULTS: dict[str, Any] = {
    "url": "", "title": "", "emoji": "🛰", "emoji_id": None, "style": "primary",
    "icons": {}, "hide": [], "footer": "", "min_len": MIN_QUERY, "headers": {}, "enabled": True,
    # per-command overrides: None = follow the global setting
    "cooldown": None, "daily_limit": None, "auto_delete": None, "no_log": None, "blocked": [],
    "maintenance": False, "maint_msg": "", "maint_until": 0.0,
    "backup_url": "", "cache_ttl": None,
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


def eff(p: dict[str, Any], key: str) -> Any:
    """Effective setting: the command's own value, or the global one when left on 'global'."""
    v = p.get(key)
    return SETTINGS[key] if v is None else v


def find_grant(uid: int, name: str | None) -> dict[str, Any] | None:
    """The grant that applies to this user on this command: command-specific first, then 'all commands'."""
    now = time.time()
    for key in ((uid, name or "-"), (uid, "*")):
        g = GRANTS.get(key)
        if g and not (g.get("until") and now >= g["until"]):
            return g
    return None


def effective_limit(uid: int, name: str | None) -> int:
    g = find_grant(uid, name)
    if g is not None:
        return int(g["limit"])
    if uid in USER_LIMITS:
        return USER_LIMITS[uid]
    return int(eff(profile(name), "daily_limit"))


def norm_query(q: str) -> str:
    """Canonical form so +91 98765-43210, 919876543210 and 9876543210 are all the same query."""
    q = q.strip().casefold()
    digits = re.sub(r"[\s\-().+]", "", q)
    if digits.isdigit() and len(digits) >= 7:
        return "n:" + (digits[-10:] if len(digits) >= 10 else digits)
    return "t:" + q.lstrip("@")


def mask_norm(n: str) -> str:
    body = n[2:]
    if len(body) <= 4:
        return "••••"
    return body[:2] + "•" * max(2, min(8, len(body) - 4)) + body[-2:]


def qtok(n: str) -> str:
    return hashlib.sha1(n.encode("utf-8")).hexdigest()[:8]


def parse_block_input(text: str) -> list[str]:
    out = []
    for part in re.split(r"[\n,;]+", text):
        part = part.strip()
        if len(part) >= 3:
            out.append(norm_query(part))
    return list(dict.fromkeys(out))


def is_blocked(query: str, name: str | None) -> bool:
    n = norm_query(query)
    if n in BLOCKED:
        return True
    src = SOURCES.get(name) if name else None
    return bool(src) and n in set(src.get("blocked") or [])


def storage_label() -> str:
    base = "🟢 MongoDB" if STORAGE["kind"] == "mongo" else "🟡 Local files"
    if STORAGE["errors"]:
        base += f" · ⚠️ {STORAGE['errors']} write error(s)"
    return base

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


def persist_usage(day: str, uid: int, name: str | None, count: int) -> None:
    if STORE is None or STORE.kind != "mongo":
        return

    async def _write() -> None:
        try:
            await STORE.save_usage(day, uid, name or "-", count)
        except Exception as exc:  # noqa: BLE001
            STORAGE["errors"] += 1
            log.error("usage write failed: %s", type(exc).__name__)

    try:
        spawn(_write())
    except RuntimeError:
        pass


def quota_check(user_id: int, name: str | None = None) -> str | None:
    """Per-user, per-command cooldown and daily limit (command overrides fall back to global)."""
    p = profile(name)
    label = f"/{name}" if name else "/num"
    now = time.time()
    cooldown = float(eff(p, "cooldown"))
    ukey = (user_id, name or "-")
    last = LAST_CALL.get(ukey, 0.0)
    if now - last < cooldown:
        return f"⏳ Easy there - try {label} again in {max(1, round(cooldown - (now - last)))}s."
    limit = effective_limit(user_id, name)
    if limit and not is_admin(user_id):
        today = today_utc()
        day, count = USAGE.get(ukey, (today, 0))
        if day != today:
            day, count = today, 0
        if count >= limit:
            return f"🚦 Daily limit reached for {label} ({limit} lookups per user). Resets at midnight UTC."
        USAGE[ukey] = (day, count + 1)
        persist_usage(today, user_id, name, count + 1)
    LAST_CALL[ukey] = now
    return None


def persist_log(entry: dict[str, Any]) -> None:
    if STORE is None or STORE.kind != "mongo" or not SETTINGS["audit"]:
        return

    async def _write() -> None:
        try:
            await STORE.log_event(entry)
        except Exception as exc:  # noqa: BLE001
            STORAGE["errors"] += 1
            log.error("audit write failed: %s", type(exc).__name__)

    try:
        spawn(_write())
    except RuntimeError:
        pass


def record_activity(user, chat, query: str, hits: int, ms: int, status: str,
                    cmd: str | None = None, hide_query: bool = False) -> None:
    uid = user.id if user else 0
    name = (user.full_name if user else "?") or "?"
    where = "DM" if chat is None or chat.type == ChatType.PRIVATE else (chat.title or str(chat.id))
    entry = {"ts": time.time(), "uid": uid, "name": name, "where": where,
             "query": "(hidden)" if hide_query else query, "hits": hits, "ms": ms,
             "status": status, "cmd": cmd}
    LOG.append(entry)
    persist_log(entry)
    stat = USER_STATS.setdefault(uid, {"name": name, "count": 0, "last": 0.0})
    stat.update(name=name, last=time.time())
    stat["count"] += 1


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


def _sig(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, default=str)


def snapshot() -> dict[str, Any]:
    return {
        "groups": {int(k): dict(v) for k, v in ALLOWED_GROUPS.items()},
        "settings": dict(SETTINGS),
        "banned": [{"uid": u, **(BAN_INFO.get(u) or {})} for u in sorted(BANNED)],
        "sources": json.loads(json.dumps(SOURCES)),
        "blocked": sorted(BLOCKED),
        "limits": {int(k): int(v) for k, v in USER_LIMITS.items()},
        "grants": [{"uid": u, "cmd": c, **g} for (u, c), g in GRANTS.items()],
    }


def apply_loaded(data: dict[str, Any]) -> None:
    ALLOWED_GROUPS.update({int(k): v for k, v in (data.get("groups") or {}).items()})
    for key, value in (data.get("settings") or {}).items():
        if key in SETTINGS:
            current = SETTINGS[key]
            try:
                SETTINGS[key] = bool(value) if isinstance(current, bool) else type(current)(value)
            except (TypeError, ValueError):
                pass
    for item in data.get("banned", []):
        try:
            if isinstance(item, dict):
                uid = int(item["uid"])
                BANNED.add(uid)
                BAN_INFO[uid] = {"until": float(item.get("until") or 0), "reason": str(item.get("reason") or ""),
                                 "by": int(item.get("by") or 0)}
            else:
                BANNED.add(int(item))
        except (KeyError, TypeError, ValueError):
            pass
    for k, v in (data.get("limits") or {}).items():
        try:
            USER_LIMITS[int(k)] = int(v)
        except (TypeError, ValueError):
            pass
    for item in data.get("grants", []):
        try:
            GRANTS[(int(item["uid"]), str(item["cmd"]))] = {
                "limit": int(item.get("limit", 0)), "until": float(item.get("until") or 0), "by": int(item.get("by") or 0)}
        except (KeyError, TypeError, ValueError):
            pass
    BLOCKED.update(str(x) for x in data.get("blocked", []))
    for name, conf in (data.get("sources") or {}).items():
        if CMD_RE.match(str(name)) and isinstance(conf, dict) and conf.get("url"):
            merged = new_source(str(name), str(conf["url"]))
            merged.update({k: v for k, v in conf.items() if k in SOURCE_DEFAULTS})
            SOURCES[str(name)] = merged
    for row in data.get("usage", []):
        try:
            USAGE[(int(row["uid"]), str(row["cmd"]))] = (str(row["day"]), int(row["count"]))
        except (KeyError, TypeError, ValueError):
            pass


class FileStore:
    """Fallback storage: two small JSON files (lost on redeploy unless on a persistent disk)."""

    kind = "files"

    async def connect(self) -> None:
        return None

    async def load(self) -> dict[str, Any]:
        data: dict[str, Any] = {"groups": {}, "settings": {}, "banned": [], "sources": {}, "blocked": [], "limits": {}, "grants": [], "usage": []}
        try:
            with open(GROUPS_FILE, encoding="utf-8") as fh:
                data["groups"] = json.load(fh)
        except FileNotFoundError:
            pass
        except Exception:  # noqa: BLE001
            log.exception("could not read %s", GROUPS_FILE)
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                state = json.load(fh)
            for k in ("settings", "banned", "sources", "blocked", "limits", "grants"):
                data[k] = state.get(k, data[k])
        except FileNotFoundError:
            pass
        except Exception:  # noqa: BLE001
            log.exception("could not read %s", STATE_FILE)
        return data

    def _write(self, snap: dict[str, Any]) -> None:
        _atomic_dump(GROUPS_FILE, {str(k): v for k, v in snap["groups"].items()})
        _atomic_dump(STATE_FILE, {k: snap[k] for k in ("settings", "banned", "sources", "blocked", "limits", "grants")}, secret=True)

    async def save(self, snap: dict[str, Any]) -> None:
        await asyncio.to_thread(self._write, snap)

    async def save_usage(self, *_: Any) -> None:
        return None

    async def log_event(self, entry: dict[str, Any]) -> None:
        return None

    async def load_log(self, n: int = 100) -> list[dict[str, Any]]:
        return []

    async def export_log(self, since: float, limit: int = 5000) -> list[dict[str, Any]]:
        return []

    async def ping(self) -> tuple[bool, str]:
        return True, "🟡 Local files (no database configured)"

    async def close(self) -> None:
        return None


class MongoStore:
    """MongoDB storage (PyMongo async). Only changed documents are written."""

    kind = "mongo"

    def __init__(self, uri: str, dbname: str) -> None:
        self.uri, self.dbname = uri, dbname
        self.client: Any = None
        self.db: Any = None
        self._sig: dict[tuple[str, Any], str] = {}

    async def connect(self) -> None:
        from pymongo import AsyncMongoClient

        self.client = AsyncMongoClient(self.uri, serverSelectionTimeoutMS=8000)
        await self.client.admin.command("ping")
        self.db = self.client[self.dbname]
        for coll in ("usage", "audit"):  # usage counters and audit entries expire on their own
            try:
                await self.db[coll].create_index("exp", expireAfterSeconds=0)
            except Exception:  # noqa: BLE001
                pass
        try:
            await self.db["audit"].create_index("ts")
        except Exception:  # noqa: BLE001
            pass

    async def _all(self, coll: str, flt: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return await self.db[coll].find(flt or {}).to_list(length=None)

    def _prime(self, coll: str, docs: list[dict[str, Any]]) -> None:
        for d in docs:
            self._sig[(coll, d["_id"])] = _sig(d)

    async def load(self) -> dict[str, Any]:
        groups_docs = await self._all("groups")
        source_docs = await self._all("sources")
        ban_docs = await self._all("bans")
        blocked_docs = await self._all("blocked")
        limit_docs = await self._all("limits")
        grant_docs = await self._all("grants")
        settings_doc = await self.db["settings"].find_one({"_id": "global"}) or {}
        usage_docs = await self._all("usage", {"day": today_utc()})
        for coll, docs in (("groups", groups_docs), ("sources", source_docs), ("bans", ban_docs),
                           ("blocked", blocked_docs), ("limits", limit_docs), ("grants", grant_docs),
                           ("settings", [settings_doc] if settings_doc else [])):
            self._prime(coll, docs)
        strip = lambda d: {k: v for k, v in d.items() if k != "_id"}  # noqa: E731
        return {
            "groups": {int(d["_id"]): strip(d) for d in groups_docs},
            "settings": strip(settings_doc),
            "banned": [{"uid": int(d["_id"]), **strip(d)} for d in ban_docs],
            "sources": {str(d["_id"]): strip(d) for d in source_docs},
            "blocked": [str(d["_id"]) for d in blocked_docs],
            "limits": {int(d["_id"]): int(d.get("limit", 0)) for d in limit_docs},
            "grants": [{"uid": d["uid"], "cmd": d["cmd"], "limit": d.get("limit", 0), "until": d.get("until", 0),
                        "by": d.get("by", 0)} for d in grant_docs],
            "usage": [{"uid": d["uid"], "cmd": d["cmd"], "day": d["day"], "count": d["count"]} for d in usage_docs],
        }

    async def _sync(self, coll: str, docs: list[dict[str, Any]]) -> None:
        c = self.db[coll]
        ids = {d["_id"] for d in docs}
        for d in docs:
            sg = _sig(d)
            if self._sig.get((coll, d["_id"])) != sg:
                await c.replace_one({"_id": d["_id"]}, d, upsert=True)
                self._sig[(coll, d["_id"])] = sg
        gone = [k[1] for k in self._sig if k[0] == coll and k[1] not in ids]
        if gone:
            await c.delete_many({"_id": {"$in": gone}})
            for gid in gone:
                self._sig.pop((coll, gid), None)

    async def save(self, snap: dict[str, Any]) -> None:
        await self._sync("groups", [{"_id": gid, **meta} for gid, meta in snap["groups"].items()])
        await self._sync("sources", [{"_id": n, **conf} for n, conf in snap["sources"].items()])
        await self._sync("bans", [{"_id": b["uid"], **{k: v for k, v in b.items() if k != "uid"}} for b in snap["banned"]])
        await self._sync("blocked", [{"_id": n} for n in snap["blocked"]])
        await self._sync("limits", [{"_id": uid, "limit": n} for uid, n in snap["limits"].items()])
        await self._sync("grants", [{"_id": f"{g['uid']}:{g['cmd']}", **g} for g in snap["grants"]])
        await self._sync("settings", [{"_id": "global", **snap["settings"]}])

    async def save_usage(self, day: str, uid: int, cmd: str, count: int) -> None:
        exp = datetime.now(timezone.utc) + timedelta(days=2)
        await self.db["usage"].update_one(
            {"_id": f"{day}:{uid}:{cmd}"},
            {"$set": {"day": day, "uid": uid, "cmd": cmd, "count": count, "exp": exp}},
            upsert=True,
        )

    async def log_event(self, entry: dict[str, Any]) -> None:
        doc = dict(entry)
        doc["exp"] = datetime.now(timezone.utc) + timedelta(days=AUDIT_DAYS)
        await self.db["audit"].insert_one(doc)

    async def load_log(self, n: int = 100) -> list[dict[str, Any]]:
        docs = await self.db["audit"].find({}).sort("ts", -1).limit(n).to_list(length=None)
        out = [{k: v for k, v in d.items() if k not in ("_id", "exp")} for d in docs]
        out.reverse()
        return out

    async def export_log(self, since: float, limit: int = 5000) -> list[dict[str, Any]]:
        docs = await self.db["audit"].find({"ts": {"$gte": since}}).sort("ts", 1).limit(limit).to_list(length=None)
        return [{k: v for k, v in d.items() if k not in ("_id", "exp")} for d in docs]

    async def ping(self) -> tuple[bool, str]:
        started = time.perf_counter()
        try:
            await self.client.admin.command("ping")
        except Exception as exc:  # noqa: BLE001
            return False, f"🔴 MongoDB unreachable ({type(exc).__name__})"
        return True, f"🟢 MongoDB healthy · {int((time.perf_counter() - started) * 1000)} ms"

    async def close(self) -> None:
        try:
            await self.client.close()
        except Exception:  # noqa: BLE001
            pass


_FLUSH_LOCK: asyncio.Lock | None = None


async def _flush() -> None:
    global _FLUSH_LOCK
    if STORE is None:
        return
    if _FLUSH_LOCK is None:
        _FLUSH_LOCK = asyncio.Lock()
    async with _FLUSH_LOCK:  # always writes the LATEST state, so ordering can't regress data
        try:
            await STORE.save(snapshot())
        except Exception as exc:  # noqa: BLE001
            STORAGE["errors"] += 1
            log.error("storage write failed: %s", type(exc).__name__)


def persist() -> None:
    try:
        spawn(_flush())
    except RuntimeError:  # no running loop (tests / startup)
        pass


def save_groups() -> None:
    persist()


def save_state() -> None:
    persist()


async def init_storage() -> None:
    global STORE
    STORE = None
    if MONGODB_URI:
        try:
            candidate = MongoStore(MONGODB_URI, MONGODB_DB)
            await candidate.connect()
            data = await candidate.load()
            STORE = candidate
        except ImportError:
            STORAGE["note"] = "pymongo is not installed - using local files"
        except Exception as exc:  # noqa: BLE001
            STORAGE["note"] = f"MongoDB unreachable ({type(exc).__name__}) - using local files"
            log.error("MongoDB connection failed: %s", type(exc).__name__)  # never log the URI
    if STORE is None:
        STORE = FileStore()
        data = await STORE.load()
    STORAGE["kind"] = STORE.kind
    apply_loaded(data)
    try:
        LOG.extend(await STORE.load_log(100))
    except Exception:  # noqa: BLE001
        pass

    seeded = False
    for gid in re.split(r"[,\s]+", SEED_GROUPS):
        if gid.lstrip("-").isdigit() and int(gid) not in ALLOWED_GROUPS:
            ALLOWED_GROUPS[int(gid)] = {"title": "seeded", "by": 0, "ts": int(time.time())}
            seeded = True
    if seeded or (STORE.kind == "mongo" and not data.get("groups") and ALLOWED_GROUPS):
        persist()
    log.info(
        "storage=%s | %d group(s) | %d custom command(s) | %d banned | %d protected",
        STORE.kind, len(ALLOWED_GROUPS), len(SOURCES), len(BANNED), len(BLOCKED),
    )


def authorize_group(chat_id: int, title: str | None, by: int) -> None:
    ALLOWED_GROUPS[chat_id] = {**ALLOWED_GROUPS.get(chat_id, {}), "title": title or str(chat_id), "by": by,
                               "ts": int(time.time())}  # keeps mute / cap / command settings on re-approval
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


def delete_note(d: float | None = None) -> str:
    d = SETTINGS["auto_delete"] if d is None else d
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
            if is_banned(user.id):
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
    footer = f"\n\n{DIV}\n{FOOTER}{custom_footer(p)}{delete_note(eff(p, 'auto_delete'))}"

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
        parts.append(f"\n\n{DIV}\n{FOOTER}{custom_footer(p)}{delete_note(eff(p, 'auto_delete'))}")
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
    tail = custom_footer(p) + delete_note(eff(p, 'auto_delete'))
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
    cmds = [f"<code>/{n}</code>{' 🛠' if maint_active(c) else ''}" for n, c in SOURCES.items() if c.get("enabled")]
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
        "<code>/search</code> <code>/num</code> <code>/recent</code> <code>/usage</code> <code>/menu</code> <code>/optout</code>"
        + custom
        + "\n\n🛠 <b>Admin</b>\n"
        "<code>/admin</code> <code>/groups</code> <code>/allowgroup</code> <code>/denygroup</code>\n"
        "<code>/ban</code> <code>/unban</code> <code>/banned</code> <code>/connect</code> <code>/source</code>\n"
        "<code>/addcmd</code> <code>/cmds</code> <code>/delcmd</code>\n"
        "<code>/block</code> <code>/unblock</code> <code>/setlimit</code> <code>/limits</code>\n"
        "<code>/broadcast</code> <code>/backup</code> <code>/audit</code>\n"
        "<code>/grant</code> <code>/revoke</code> <code>/grants</code>"
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
        + cmd_stats_block()
        + "\n\n🌐 <b>REACH</b>\n"
        + block_table([
            ("👥 Users", str(len(STATS["users"]))),
            ("🛡 Groups", f"{len(ALLOWED_GROUPS)} allowed · {len(PENDING)} pending"),
            ("🚫 Banned", f"{len(BANNED)} ({sum(1 for u in BANNED if (BAN_INFO.get(u) or {}).get('until'))} temporary)"),
            ("🧩 Custom commands", str(len(SOURCES))),
            ("🛡 Protected queries", str(len(BLOCKED))),
        ])
        + "\n\n⚙️ <b>STATUS</b>\n"
        + block_table([
            ("🔌 Source", "🟢 connected" if RUNTIME.get("api_url") else "🔴 NOT connected"),
            ("🧹 Auto-delete", fmt_dur(SETTINGS["auto_delete"])),
            ("🔒 Lockdown", "ON" if SETTINGS["lockdown"] else "off"),
            ("💾 Storage", storage_label()),
            ("🛠 In maintenance", str(sum(1 for c in SOURCES.values() if maint_active(c))) + " command(s)"),
            ("🧯 Breakers open", str(sum(1 for b in BREAKER.values() if b["until"] > time.time())) + " command(s)"),
            ("🗃 Cached sets", str(len(CACHE))),
            ("⏱ Uptime", uptime),
        ])
        + f"\n\n{DIV}\n<i>Last refreshed {clock()} UTC</i>"
    )
    rows = [
        [btn("⚙️ Settings", "adm|settings|0", "primary"), btn("🔐 Security", "adm|security|0", "primary")],
        [btn("🧩 Custom commands", "cx|_.list|0", "success")],
        [btn(f"🎁 Grants ({len(GRANTS)})", "gr|list|0", "success"), btn("➕ New grant", "gr|new|0", "success")],
        [btn("🛡 Groups", "adm|groups|0", "primary"), btn("🛡 Protected queries", "adm|blocklist|0", "primary")],
        [btn("📜 Activity log", "adm|activity|0", "primary"), btn("🏆 Top users", "adm|users|0", "primary")],
        [btn("🚫 Ban list", "adm|banned|0", "primary"), btn(f"📬 Opt-outs ({len(OPTOUTS)})", "adm|optouts|0", "primary")],
        [btn("🩺 Test source", "adm|ping|0", "success"), btn("💾 Test database", "adm|dbping|0", "success")],
        [btn("📰 Digest now", "adm|digest|0", "primary"), btn("💾 Backup", "adm|backup|0", "primary")],
        [btn("🧹 Clear cache", "adm|clear|0", "danger"), btn("📤 Export log", "adm|log|0", "success")],
        [btn("🔄 Refresh", "adm|home|0", "primary"), btn("🏠 Menu", "menu|0|0", "primary")],
    ]
    return text, rich_buttons(rows)


SETTING_KEYS = {
    "ad": "auto_delete", "dq": "delete_queries", "lock": "lockdown", "mem": "members_can_search",
    "raw": "group_raw", "mask": "mask", "cd": "cooldown", "dl": "daily_limit", "nl": "no_log",
    "ag": "abuse_guard", "au": "audit", "dg": "digest", "sl": "strike_limit", "bm": "ban_minutes",
    "bf": "breaker_fails", "bk": "breaker_minutes",
}
SECURITY_KEYS = {"ag", "au", "dg", "sl", "bm", "bf", "bk"}


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
            ("🕵️ No query logging", onoff(s["no_log"])),
            ("⏱ Cooldown", f"{s['cooldown']:g}s"),
            ("📅 Daily limit", "unlimited" if not s["daily_limit"] else str(s["daily_limit"])),
        ])
        + "\n\n<i>Changes apply instantly and are saved.</i>"
    )
    rows = [
        [btn("🧹 Auto-delete timer", "noop", None), btn("✏️ Custom", "adm|val_ad|0", "success")],
        _opt_row("ad", s["auto_delete"], [("Off", 0), ("1m", 60), ("2m", 120), ("5m", 300)]),
        [btn("⏱ Cooldown per user", "noop", None), btn("✏️ Custom", "adm|val_cd|0", "success")],
        _opt_row("cd", s["cooldown"], [("1s", 1), ("3s", 3), ("5s", 5), ("10s", 10)]),
        [btn("📅 Daily limit per user", "noop", None), btn("✏️ Custom", "adm|val_dl|0", "success")],
        _opt_row("dl", s["daily_limit"], [("∞", 0), ("25", 25), ("50", 50), ("100", 100), ("200", 200)]),
        [_toggle("dq", "Delete queries", s["delete_queries"]), _toggle("mask", "Masking", s["mask"])],
        [_toggle("nl", "Don't log queries", s["no_log"])],
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
        if meta.get("muted"):
            note += " · 🔇 muted"
        if meta.get("cap"):
            note += f" · cap {meta['cap']}/day"
        if meta.get("cmds") is not None:
            note += " · restricted"
        lines.append(f"{mark} <b>{esc(meta.get('title', gid))}</b>\n   <code>{gid}</code> · {note}")
        rows.append([btn(f"⚙️ {shorten(meta.get('title', gid), 16)}", f"adm|gv_{gid}|0", "primary"),
                     btn("🚪 Leave", f"lg|{gid}|0", "danger")])

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
    now = time.time()
    ids = [u for u in sorted(BANNED) if is_banned(u)][:15]
    if not ids:
        body = ("<i>Nobody is banned.</i>\n\nBan with <code>/ban &lt;user_id&gt; [duration] [reason]</code> "
                "or reply to a message with <code>/ban</code>.")
    else:
        lines = []
        for uid in ids:
            info = BAN_INFO.get(uid) or {}
            until = info.get("until") or 0
            when = f"⏱ {fmt_left(until - now)} left" if until else "♾ permanent"
            why = f" · {esc(info['reason'])}" if info.get("reason") else ""
            lines.append(f"🚫 <code>{uid}</code> · {esc(USER_STATS.get(uid, {}).get('name', 'unknown'))}\n   {when}{why}")
        body = "\n".join(lines)
    rows = [[btn(f"✅ Unban {uid}", f"ub|{uid}|0", "success")] for uid in ids]
    rows.append(ADMIN_BACK)
    return f"🚫 <b>BAN LIST</b> <i>({len(ids)})</i>\n{DIV}\n\n{body}", rich_buttons(rows)


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


async def _fetch(url: str, headers: dict[str, str], name: str | None) -> Any:
    try:
        session = await get_session()
        async with session.get(url, headers=headers) as response:
            body = await response.text()
            if response.status == 404:
                return {}
            if response.status >= 400:
                log.error("source error %s (%s): %s", response.status, name or "default", body[:300])
                raise ApiError("The intelligence source rejected that lookup. Try again shortly.")
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"response": shorten(body, 2000)}
    except asyncio.TimeoutError as exc:
        raise ApiError("The source timed out. Please try again in a moment.") from exc
    except aiohttp.ClientError as exc:
        log.error("source unreachable (%s): %s", name or "default", type(exc).__name__)
        raise ApiError("The intelligence source is unreachable right now.") from exc


async def run_search(query: str, name: str | None = None) -> SearchResult:
    base, headers = source_conf(name)
    url = build_url(query, base)
    started = time.perf_counter()
    try:
        payload = await _fetch(url, headers, name)
    except ApiError:
        backup = ((SOURCES.get(name) or {}).get("backup_url") or "") if name else ""
        if not backup:
            raise
        log.warning("primary API failed for /%s - using backup", name)
        payload = await _fetch(build_url(query, backup), headers, name)

    elapsed = int((time.perf_counter() - started) * 1000)
    items, meta = extract_items(payload)
    meta.pop("q", None)
    return SearchResult(query=query, items=items, meta=meta, raw=payload, elapsed_ms=elapsed, source=name)


async def search_cached(query: str, name: str | None = None) -> SearchResult:
    key = f"{name or '-'}|{query.strip().lower()}"
    ttl = profile(name).get("cache_ttl")
    ttl = QUERY_TTL if ttl is None else float(ttl)
    hit = QUERY_CACHE.get(key)
    if ttl > 0 and hit and time.time() - hit.created_at < ttl:
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


def usage_numbers(user_id: int, name: str | None = None) -> tuple[int, str]:
    day, count = USAGE.get((user_id, name or "-"), (today_utc(), 0))
    if day != today_utc():
        count = 0
    limit = effective_limit(user_id, name)
    left = "unlimited" if not limit or is_admin(user_id) else str(max(0, limit - count))
    return count, left


async def cmd_usage(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    uid = uid_of(update)
    names: list[str | None] = [None] + [n for n, c in SOURCES.items() if c.get("enabled")]
    lines = []
    for n in names:
        p = profile(n)
        used, left = usage_numbers(uid, n)
        lines.append(
            f"{emoji_html(p)} <b>{'/num' if n is None else '/' + n}</b> ▸ "
            f"<code>{used}</code> used · <code>{left}</code> left · ⏱ <code>{float(eff(p, 'cooldown')):g}s</code>{' 🎁' if find_grant(uid, n) else ''}"
        )
    await update.effective_message.reply_html(f"📊 <b>YOUR USAGE</b>\n{DIV}\n" + tree(lines))


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
    delay = eff(p, "auto_delete")
    nolog = bool(eff(p, "no_log"))
    admin = is_admin(user_id)
    gmeta = ALLOWED_GROUPS.get(chat.id) if group else None

    def clean(*msgs) -> None:
        if delay:
            autodelete(bot, *msgs, delay=delay)
            if SETTINGS["delete_queries"] and update.message is not None:
                autodelete(bot, update.message, delay=delay)

    if SETTINGS["lockdown"] and not admin:
        await message.reply_html("🛠 <b>Maintenance</b>\nLookups are paused for a moment. Please try again soon.")
        return
    if gmeta is not None and not admin:  # per-group controls
        if gmeta.get("muted"):
            return
        if not group_allows(chat.id, source):
            note = await message.reply_html(
                f"🚫 <b>/{esc(source or 'num')}</b> is disabled in this group." + delete_note(delay)
            )
            clean(note)
            return
    if source and maint_active(p) and not admin:
        note = await message.reply_html(
            f"🛠 <b>/{esc(source)} is under maintenance</b>\n"
            f"{esc(p.get('maint_msg') or 'It will be back shortly.')}" + delete_note(delay)
        )
        clean(note)
        return
    bk = BREAKER.get(source or "-")
    if bk and bk["until"] > time.time() and not admin:  # circuit breaker is open
        note = await message.reply_html(
            "🧯 <b>Temporarily unavailable</b>\nThe data source is being protected after repeated errors. "
            f"Please try again in {fmt_left(bk['until'] - time.time())}." + delete_note(delay)
        )
        clean(note)
        return
    if len(query) < min_len:
        await message.reply_html(f"🔎 Please provide at least <b>{min_len}</b> characters.")
        return
    if is_blocked(query, source):  # protected queries are refused before anything else happens
        note = await message.reply_html(
            "🛡 <b>Protected</b>\nLookups for this query are disabled." + delete_note(delay)
        )
        clean(note)
        record_activity(user, chat, query, 0, 0, "blocked", source, hide_query=True)
        await strike(bot, user, "protected query", 3)
        return

    cap = int((gmeta or {}).get("cap") or 0) if not admin else 0
    gday, gcount = today_utc(), 0
    if cap:
        gday, gcount = USAGE.get((chat.id, "__grp"), (today_utc(), 0))
        if gday != today_utc():
            gday, gcount = today_utc(), 0
        if gcount >= cap:
            note = await message.reply_html(
                f"🚦 This group reached its daily limit ({cap} lookups). Resets at midnight UTC."
            )
            clean(note)
            return
    blocked = quota_check(user_id, source)
    if blocked:
        await message.reply_html(blocked)
        await strike(bot, user, "rate limit", 1)
        return
    if cap:
        USAGE[(chat.id, "__grp")] = (gday, gcount + 1)
        persist_usage(gday, chat.id, "__grp", gcount + 1)

    STATS["users"].add(user_id)
    try:
        await message.chat.send_action(ChatAction.TYPING)
    except TelegramError:
        pass
    placeholder = await message.reply_html(
        f"{emoji_html(p)} <b>Scanning…</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n"
        "▰▰▱▱▱ <i>querying source</i>"
    )
    clean(placeholder)

    started = time.perf_counter()
    try:
        result = await search_cached(query, source)
    except NotConfigured:
        record_activity(user, chat, query, 0, 0, "unconfigured", source, nolog)
        await placeholder.edit_text(
            "🔌 <b>No source connected yet.</b>\nThe operator has to connect one first.",
            parse_mode=ParseMode.HTML,
        )
        return
    except ApiError as exc:
        STATS["errors"] += 1
        src_stat(source, err=True)
        record_activity(user, chat, query, 0, int((time.perf_counter() - started) * 1000), "error", source, nolog)
        await placeholder.edit_text(f"⚠️ {esc(exc)}", parse_mode=ParseMode.HTML)
        await breaker_fail(bot, source)
        return
    except Exception:  # noqa: BLE001
        STATS["errors"] += 1
        src_stat(source, err=True)
        log.exception("lookup failed")
        record_activity(user, chat, query, 0, 0, "error", source, nolog)
        await placeholder.edit_text("💥 Something went wrong on our side. Please try again.")
        return

    BREAKER.pop(source or "-", None)  # a healthy answer closes the breaker
    STATS["searches"] += 1
    STATS["lat_total"] += result.elapsed_ms
    STATS["lat_n"] += 1
    src_stat(source, hits=len(result.items), ms=result.elapsed_ms)
    if source is None and not nolog:
        remember(user_id, query)
    record_activity(user, chat, query, len(result.items), result.elapsed_ms, "ok", source, nolog)

    if not result.items:
        await placeholder.edit_text(
            f"🫥 <b>No records</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n"
            "<i>Try a different spelling, a username, or a full email address.</i>"
            + delete_note(delay),
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
    args = list(context.args or [])
    target = None
    reply = update.effective_message.reply_to_message
    if reply and reply.from_user:
        target = reply.from_user.id
        USER_STATS.setdefault(target, {"name": reply.from_user.full_name, "count": 0, "last": 0.0})
    elif args and args[0].lstrip("-").isdigit():
        target = int(args.pop(0))
    if target is None:
        await update.effective_message.reply_html(
            "Usage: <code>/ban &lt;user_id&gt; [duration] [reason]</code> or reply with <code>/ban [duration] [reason]</code>\n"
            "Durations: <code>30m</code> <code>6h</code> <code>7d</code> <code>2w</code> or <code>perm</code> (default)."
        )
        return
    if is_admin(target):
        await update.effective_message.reply_html("🛡 You can't ban an admin.")
        return
    minutes = 0
    if args:
        parsed = parse_duration(args[0])
        if parsed is not None:
            minutes = parsed
            args.pop(0)
    reason = " ".join(args)
    ban_user(target, minutes, reason, user.id)
    await update.effective_message.reply_html(
        f"🚫 <b>Banned</b> <code>{target}</code> · {fmt_minutes(minutes)}" + (f"\n📝 {esc(reason)}" if reason else "")
    )


async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.effective_message.reply_html("Usage: <code>/unban &lt;user_id&gt;</code>")
        return
    target = int(context.args[0])
    unban_user(target)
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
    BotCommand("block", "Protect a query from lookups"),
    BotCommand("unblock", "Remove a protected query"),
    BotCommand("setlimit", "Set a user's daily limit"),
    BotCommand("limits", "List per-user limit overrides"),
    BotCommand("broadcast", "Announce to all groups"),
    BotCommand("backup", "Export a config backup"),
    BotCommand("audit", "Export the audit log"),
    BotCommand("grant", "Give a user unlimited / custom limits"),
    BotCommand("revoke", "Remove a user's grants"),
    BotCommand("grants", "List all grants"),
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
            desc = shorten(f"{'🛠 ' if maint_active(src) else ''}{src.get('emoji') or ''} {src.get('title') or name}".strip(), 200)
            custom.append(BotCommand(name, desc or name))
    custom = custom[:60]
    try:
        await bot.delete_my_commands()
        group_cmds = [BotCommand("num", "Run an OSINT lookup"),
                      BotCommand("optout", "Ask for a number/username to be protected")] + custom
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
            f"{'🛠' if maint_active(s) else ('🟢' if s.get('enabled') else '⚪')} {esc(s.get('emoji') or '')} <b>/{n}</b> ▸ {esc(s.get('title', n))} · <code>{esc(host_of(s['url']))}</code>"
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


def limits_summary(s: dict[str, Any]) -> str:
    cd, dl = s.get("cooldown"), s.get("daily_limit")
    cd_t = f"{cd:g}s" if cd is not None else f"global {SETTINGS['cooldown']:g}s"
    dl_v = SETTINGS["daily_limit"] if dl is None else dl
    dl_t = ("∞" if not dl_v else str(dl_v)) + ("" if dl is not None else " global")
    return f"{cd_t} cooldown · {dl_t}/user/day"


def _cfg_row(name: str, code: str, current: Any, options: list[tuple[str, str]]) -> list[InlineKeyboardButton]:
    row = []
    for label, tk in options:
        if tk == "g":
            sel = current is None
        elif tk in ("on", "off"):
            sel = current is not None and (tk == "on") == bool(current)
        else:
            sel = current is not None and float(current) == float(tk)
        row.append(btn(f"{'✅ ' if sel else ''}{label}", f"cx|{name}.set_{code}_{tk}|0",
                       "success" if sel else "primary"))
    return row


def _mt_row(name: str) -> list[InlineKeyboardButton]:
    s = SOURCES[name]
    active = maint_active(s)
    indefinite = active and not (s.get("maint_until") or 0)
    row = []
    for label, secs in (("Off", 0), ("30m", 1800), ("1h", 3600), ("6h", 21600), ("∞", -1)):
        sel = (secs == 0 and not active) or (secs == -1 and indefinite)
        row.append(btn(f"{'✅ ' if sel else ''}{label}", f"cx|{name}.set_mt_{secs}|0", "danger" if sel and secs else ("success" if sel else "primary")))
    return row


def render_cmd_cfg(name: str) -> tuple[str, InlineKeyboardMarkup]:
    s = SOURCES[name]

    def show(key: str, fmt) -> str:  # noqa: ANN001
        v = s.get(key)
        return "global" if v is None else fmt(v)

    text = (
        f"⚙️ <b>/{esc(name)} · LIMITS &amp; PRIVACY</b>\n{DIV}\n"
        + tree([
            f"⏱ <b>Cooldown / user</b> ▸ <code>{show('cooldown', lambda v: f'{v:g}s')}</code> <i>(global {SETTINGS['cooldown']:g}s)</i>",
            f"📅 <b>Daily limit / user</b> ▸ <code>{show('daily_limit', lambda v: '∞' if not v else str(v))}</code> <i>(global {SETTINGS['daily_limit'] or '∞'})</i>",
            f"🧹 <b>Auto-delete</b> ▸ <code>{show('auto_delete', fmt_dur)}</code> <i>(global {fmt_dur(SETTINGS['auto_delete'])})</i>",
            f"🕵️ <b>No query logging</b> ▸ <code>{show('no_log', lambda v: 'ON' if v else 'off')}</code> <i>(global {'ON' if SETTINGS['no_log'] else 'off'})</i>",
            f"♻️ <b>Result cache</b> ▸ <code>{show('cache_ttl', lambda v: 'off' if not v else fmt_dur(v))}</code> <i>(global {fmt_dur(QUERY_TTL)})</i>",
            f"🛠 <b>Maintenance</b> ▸ <code>{esc(maint_text(s))}</code>",
        ])
        + "\n\n<i>Limits count per user and per command. “global” follows Settings. Admins skip daily limits.</i>"
    )
    rows = [
        [btn("⏱ Cooldown per user", "noop", None), btn("✏️ Custom", f"cx|{name}.val_cd|0", "success")],
        _cfg_row(name, "cd", s.get("cooldown"), [("Global", "g"), ("1s", "1"), ("3s", "3"), ("5s", "5"), ("10s", "10")]),
        [btn("📅 Daily limit per user", "noop", None), btn("✏️ Custom", f"cx|{name}.val_dl|0", "success")],
        _cfg_row(name, "dl", s.get("daily_limit"), [("Global", "g"), ("∞", "0"), ("10", "10"), ("25", "25"), ("50", "50"), ("100", "100")]),
        [btn("🧹 Auto-delete timer", "noop", None), btn("✏️ Custom", f"cx|{name}.val_ad|0", "success")],
        _cfg_row(name, "ad", s.get("auto_delete"), [("Global", "g"), ("Off", "0"), ("1m", "60"), ("2m", "120"), ("5m", "300")]),
        [btn("🕵️ Don't keep query text in logs", "noop", None)],
        _cfg_row(name, "nl", s.get("no_log"), [("Global", "g"), ("ON", "on"), ("off", "off")]),
        [btn("♻️ Result cache (saves API calls)", "noop", None), btn("✏️ Custom", f"cx|{name}.val_ct|0", "success")],
        _cfg_row(name, "ct", s.get("cache_ttl"), [("Global", "g"), ("Off", "0"), ("30s", "30"), ("5m", "300"), ("1h", "3600")]),
        [btn("🛠 Maintenance for…", "noop", None), btn("✏️ Custom", f"cx|{name}.val_mt|0", "success")],
        _mt_row(name),
        [btn("⬅️ Back", f"cx|{name}.view|0")],
    ]
    return text, rich_buttons(rows)


def render_cmd_blocklist(name: str) -> tuple[str, InlineKeyboardMarkup]:
    entries = SOURCES[name].get("blocked") or []
    body = "\n".join(f"🚫 <code>{esc(mask_norm(n))}</code>" for n in entries[:20]) or "<i>Nothing blocked on this command.</i>"
    text = (
        f"🛡 <b>/{esc(name)} · BLOCKED QUERIES</b> <i>({len(entries)})</i>\n{DIV}\n{body}\n\n"
        "<i>These queries are refused on this command only. Phone numbers match in any format.</i>"
    )
    rows = [[btn(f"🗑 {mask_norm(n)}", f"cx|{name}.unb_{qtok(n)}|0", "danger")] for n in entries[:20]]
    rows.append([btn("➕ Add", f"cx|{name}.blkadd|0", "success"), btn("🧹 Clear all", f"cx|{name}.blkclr|0", "danger")])
    rows.append([btn("⬅️ Back", f"cx|{name}.view|0")])
    return text, rich_buttons(rows)


def render_blocklist() -> tuple[str, InlineKeyboardMarkup]:
    entries = sorted(BLOCKED)
    body = "\n".join(f"🚫 <code>{esc(mask_norm(n))}</code>" for n in entries[:25]) or "<i>No protected queries yet.</i>"
    text = (
        f"🛡 <b>PROTECTED QUERIES</b> <i>({len(entries)})</i>\n{DIV}\n{body}\n\n"
        "<i>Refused on EVERY command (including /num and plain text). Phone numbers match in any format: "
        "+91 98765 43210 = 9876543210.</i>\n"
        "Quick add: <code>/block &lt;query&gt;</code> · remove: <code>/unblock &lt;query&gt;</code>"
    )
    rows = [[btn(f"🗑 {mask_norm(n)}", f"adm|unb_{qtok(n)}|0", "danger")] for n in entries[:25]]
    rows.append([btn("➕ Add", "adm|blkadd|0", "success"), btn("🧹 Clear all", "adm|blkclr|0", "danger")])
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
            f"⏱ <b>Limits</b> ▸ <code>{esc(limits_summary(s))}</code>",
            f"🛡 <b>Blocked</b> ▸ <code>{len(s.get('blocked') or [])}</code>",
            f"📈 <b>Stats</b> ▸ <code>{esc(src_stats_line(name))}</code>",
            f"🛟 <b>Backup API</b> ▸ <code>{esc('set · ' + host_of(s['backup_url'])) if s.get('backup_url') else 'none'}</code>",
            f"🧯 <b>Breaker</b> ▸ <code>{esc(breaker_text(name))}</code>",
            f"📶 <b>Status</b> ▸ {'🟢 enabled' if s.get('enabled') else '⚪ disabled'}",
            f"🛠 <b>Maintenance</b> ▸ <code>{esc(maint_text(s))}</code>",
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
        [btn("⚙️ Limits & privacy", f"cx|{n}.cfg|0"), btn("🛡 Blocked queries", f"cx|{n}.blk|0")],
        [btn("🛠 Maintenance: ON" if maint_active(s) else "🛠 Maintenance: off", f"cx|{n}.maint|0",
             "danger" if maint_active(s) else "primary"),
         btn("💬 Maint. message", f"cx|{n}.maintmsg|0")],
        [btn("🛟 Backup API", f"cx|{n}.backup|0"), btn("🧯 Reset breaker", f"cx|{n}.brk|0")],
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
    "gblock": "🛡 <b>Protect queries</b>\nSend phone numbers, usernames or emails to protect, one per line. Nobody can look them up on ANY command.\n<i>Your message is deleted instantly.</i>",
    "blkadd": "🛡 <b>Block queries (this command only)</b>\nSend queries to block, one per line.\n<i>Your message is deleted instantly.</i>",
    "maintmsg": "💬 <b>Maintenance message</b>\nSend the text users see while this command is in maintenance, or <code>clear</code>.",
    "backup": "🛟 <b>Backup API</b>\nSend a backup URL (with <code>{q}</code>). It is used automatically when the main API fails. Send <code>clear</code> to remove.\n<i>Your message is deleted instantly.</i>",
}


def prompt_markup(name: str | None, back: str = "cancel") -> InlineKeyboardMarkup:
    return rich_buttons([[btn("✖️ Cancel", f"cx|{name or '_'}.{back}|0", "danger")]])


def _prompt_markup_for(st: dict[str, Any]) -> InlineKeyboardMarkup:
    op, name = st.get("op"), st.get("cmd")
    if op == "gblock":
        return prompt_markup(None, "cancelg")
    if op == "blkadd":
        return prompt_markup(name, "blk")
    if op == "val":
        return prompt_markup(name, "cfg") if name else prompt_markup(None, "cancelset")
    if op in GRANT_PROMPTS:
        return rich_buttons([[btn("✖️ Cancel", "gr|build|0", "danger")]])
    return prompt_markup(name)


def prompt_text_for(st: dict[str, Any]) -> str:
    op = st.get("op")
    if op == "val":
        return val_prompt(st["field"], st.get("cmd"))
    if op in GRANT_PROMPTS:
        return GRANT_PROMPTS[op]
    return PROMPTS.get(op, "")


def _back_view(st: dict[str, Any]) -> tuple[str, InlineKeyboardMarkup]:
    op, name = st.get("op"), st.get("cmd")
    if op == "gblock":
        return render_blocklist()
    if op == "blkadd" and name in SOURCES:
        return render_cmd_blocklist(name)
    if op == "val":
        return render_cmd_cfg(name) if name in SOURCES else (render_settings() if name is None else render_cmd_list())
    if op in GRANT_PROMPTS:
        return render_grant_builder(st.get("admin", 0))
    return _panel_or_list(name)


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
        await _show(context, st, *_back_view(st))
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
    elif op == "val":
        field = st["field"]
        if name is not None and src is None:
            INPUT.pop(uid, None)
            await _show(context, st, *render_cmd_list())
            return True
        good, val = parse_maint(text) if field == "maint" else parse_field(field, text)
        if not good:
            err = val
        elif name is None:  # global setting
            if val is None:
                err = "Global settings need a real value, not “global”."
            elif field == "cooldown":
                SETTINGS["cooldown"] = float(val)
            else:
                SETTINGS[field] = int(val)
        elif field == "maint":
            src["maintenance"] = val != 0
            src["maint_until"] = time.time() + val if val > 0 else 0.0
        else:
            src[field] = val
    elif op in GRANT_PROMPTS:
        st["admin"] = uid
        d = GRANT_DRAFT.setdefault(uid, new_draft())
        if op == "grantuid":
            if text.lstrip("-").isdigit():
                d["uid"] = int(text)
            else:
                err = "Send the numeric Telegram user ID."
        elif op == "grantlimit":
            good, val = parse_field("daily_limit", text)
            if not good or val is None:
                err = "Send a number (e.g. <code>37</code>) or <code>unlimited</code>."
            else:
                d["limit"] = val
        else:
            mins = parse_duration(text)
            if mins is None:
                err = "Send a duration like <code>12h</code>, <code>10d</code>, <code>2w</code> or <code>perm</code>."
            else:
                d["secs"] = mins * 60
    elif op == "gblock":
        norms = parse_block_input(text)
        if not norms:
            err = "Send at least one query (3+ characters), one per line."
        else:
            BLOCKED.update(norms)
    elif src is None:
        INPUT.pop(uid, None)
        await _show(context, st, *render_cmd_list())
        return True
    elif op == "blkadd":
        norms = parse_block_input(text)
        if not norms:
            err = "Send at least one query (3+ characters), one per line."
        else:
            src["blocked"] = list(dict.fromkeys((src.get("blocked") or []) + norms))[:500]
    elif op == "maintmsg":
        src["maint_msg"] = "" if text.lower() == "clear" else shorten(text, 200)
    elif op == "backup":
        if text.lower() == "clear":
            src["backup_url"] = ""
        elif text.startswith(("http://", "https://")) and len(text) <= 2000:
            src["backup_url"] = text
        else:
            err = "That is not a valid http(s) URL."
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
        await _show(context, st, f"⚠️ {err}\n\n" + prompt_text_for(st), _prompt_markup_for(st))
        return True

    INPUT.pop(uid, None)
    save_state()
    QUERY_CACHE.clear()
    if op in {"title", "emoji"} or (op == "val" and st.get("field") == "maint"):
        await refresh_commands(context.bot)
    await _show(context, st, *_back_view(st))
    return True


async def handle_cx(update: Update, context: ContextTypes.DEFAULT_TYPE, key: str) -> None:
    query = update.callback_query
    uid = query.from_user.id
    name, _, op = key.partition(".")
    INPUT.pop(uid, None)  # leaving any pending prompt; prompt branches below set it again

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

    if op == "cancelset":
        await query.answer("Cancelled")
        await _safe_edit(query, *render_settings())
        return

    if op == "cancelg":
        await query.answer("Cancelled")
        await _safe_edit(query, *render_blocklist())
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
    elif op == "maint":
        src["maintenance"] = not maint_active(src)
        src["maint_until"] = 0.0
        persist()
        await refresh_commands(context.bot)
        await query.answer("🛠 Maintenance ON" if src["maintenance"] else "✅ Back online")
        await _safe_edit(query, *render_cmd_panel(name))
    elif op.startswith("val_"):
        field = VAL_FIELDS.get(op[4:])
        if not field:
            await query.answer("Unknown setting.")
            return
        await query.answer()
        INPUT[uid] = {"op": "val", "cmd": name, "field": field, "chat": query.message.chat_id,
                      "mid": query.message.message_id, "ts": time.time()}
        await _safe_edit(query, val_prompt(field, name), prompt_markup(name, "cfg"))
    elif op == "brk":
        BREAKER.pop(name, None)
        await query.answer("Breaker reset ✅")
        await _safe_edit(query, *render_cmd_panel(name))
    elif op == "cfg":
        await query.answer()
        await _safe_edit(query, *render_cmd_cfg(name))
    elif op.startswith("set_"):
        _, code, val = op.split("_", 2)
        if code == "mt":  # timed maintenance: seconds, 0 = off, -1 = until switched off
            secs = int(val)
            src["maintenance"] = secs != 0
            src["maint_until"] = time.time() + secs if secs > 0 else 0.0
            persist()
            await refresh_commands(context.bot)
            await query.answer("🛠 Maintenance ON" if secs else "✅ Back online")
            await _safe_edit(query, *render_cmd_cfg(name))
            return
        field = {"cd": "cooldown", "dl": "daily_limit", "ad": "auto_delete", "nl": "no_log", "ct": "cache_ttl"}.get(code)
        if not field:
            await query.answer("Unknown setting.")
            return
        if val == "g":
            src[field] = None
        elif field == "no_log":
            src[field] = val == "on"
        elif field == "cooldown":
            src[field] = float(val)
        else:
            src[field] = int(val)
        persist()
        await query.answer("Saved ✅")
        await _safe_edit(query, *render_cmd_cfg(name))
    elif op == "blk":
        await query.answer()
        await _safe_edit(query, *render_cmd_blocklist(name))
    elif op == "blkclr":
        src["blocked"] = []
        persist()
        await query.answer("Cleared")
        await _safe_edit(query, *render_cmd_blocklist(name))
    elif op.startswith("unb_"):
        tk = op[4:]
        src["blocked"] = [n for n in (src.get("blocked") or []) if qtok(n) != tk]
        persist()
        await query.answer("Unblocked ✅")
        await _safe_edit(query, *render_cmd_blocklist(name))
    elif op in PROMPTS:
        await query.answer()
        INPUT[uid] = {"op": op, "cmd": name, "chat": query.message.chat_id,
                      "mid": query.message.message_id, "ts": time.time()}
        await _safe_edit(query, PROMPTS[op], prompt_markup(name, "blk" if op == "blkadd" else "cancel"))
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


async def cmd_block(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = uid_of(update)
    if not is_admin(uid):
        return
    raw = " ".join(context.args or []).strip()
    norms = parse_block_input(raw)
    if not norms:
        await update.effective_message.reply_html(
            "Usage: <code>/block &lt;phone / username / email&gt;</code>\n"
            "Protected queries are refused on <b>every</b> command."
        )
        return
    BLOCKED.update(norms)
    persist()
    QUERY_CACHE.clear()
    try:
        await update.effective_message.delete()  # keep the protected value out of the chat
    except TelegramError:
        pass
    sent = await context.bot.send_message(
        uid, f"🛡 <b>Protected</b> ▸ <code>{esc(mask_norm(norms[0]))}</code>\n"
        f"<i>{len(BLOCKED)} protected quer{'y' if len(BLOCKED) == 1 else 'ies'} in total.</i>",
        parse_mode=ParseMode.HTML,
    )
    autodelete(context.bot, sent, delay=60)


async def cmd_unblock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = uid_of(update)
    if not is_admin(uid):
        return
    norms = parse_block_input(" ".join(context.args or []))
    if not norms:
        await update.effective_message.reply_html("Usage: <code>/unblock &lt;query&gt;</code>")
        return
    removed = sum(1 for n in norms if n in BLOCKED)
    BLOCKED.difference_update(norms)
    persist()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    sent = await context.bot.send_message(
        uid, "✅ <b>Unprotected.</b>" if removed else "That query wasn't protected.", parse_mode=ParseMode.HTML
    )
    autodelete(context.bot, sent, delay=60)


# --------------------------------------------------------------------------- #
# Reliability, safety and operations                                           #
# --------------------------------------------------------------------------- #


def fmt_left(seconds: float) -> str:
    sec = int(max(0, seconds))
    if sec < 90:
        return f"{sec}s"
    mins = sec // 60
    if mins < 120:
        return f"{mins}m"
    hours = mins // 60
    if hours < 48:
        return f"{hours}h {mins % 60}m"
    return f"{hours // 24}d {hours % 24}h"


def fmt_minutes(m: int) -> str:
    if m <= 0:
        return "permanent"
    if m % 1440 == 0:
        return f"{m // 1440}d"
    if m % 60 == 0:
        return f"{m // 60}h"
    return f"{m}m"


def parse_duration(tok: str) -> int | None:
    """'30m' / '6h' / '7d' / '2w' / 'perm' -> minutes (0 = permanent); None when not a duration."""
    t = tok.strip().lower()
    if t in {"perm", "permanent", "forever"}:
        return 0
    m = re.fullmatch(r"(\d+)([mhdw]?)", t)
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "m": 1, "h": 60, "d": 1440, "w": 10080}[m.group(2)]


def is_banned(uid: int) -> bool:
    if uid not in BANNED:
        return False
    until = (BAN_INFO.get(uid) or {}).get("until") or 0
    if until and time.time() >= until:  # temporary ban ran out
        BANNED.discard(uid)
        BAN_INFO.pop(uid, None)
        persist()
        return False
    return True


def ban_user(uid: int, minutes: int = 0, reason: str = "", by: int = 0) -> None:
    BANNED.add(uid)
    BAN_INFO[uid] = {"until": time.time() + minutes * 60 if minutes else 0.0, "reason": reason[:120], "by": by}
    persist()


def unban_user(uid: int) -> None:
    BANNED.discard(uid)
    BAN_INFO.pop(uid, None)
    STRIKES.pop(uid, None)
    persist()


def maint_active(src: dict[str, Any]) -> bool:
    if not src.get("maintenance"):
        return False
    until = src.get("maint_until") or 0
    return not (until and time.time() >= until)


def maint_text(src: dict[str, Any]) -> str:
    if not maint_active(src):
        return "off"
    until = src.get("maint_until") or 0
    return f"ON · ends in {fmt_left(until - time.time())}" if until else "ON · until switched off"


def breaker_text(name: str | None) -> str:
    bk = BREAKER.get(name or "-")
    if not bk:
        return "ok"
    if bk["until"] > time.time():
        return f"🔴 open · {fmt_left(bk['until'] - time.time())}"
    return f"🟡 {bk['fails']} recent failure(s)"


def group_allows(gid: int, cmd: str | None) -> bool:
    cmds = (ALLOWED_GROUPS.get(gid) or {}).get("cmds")
    return cmds is None or (cmd or "num") in cmds


def src_stat(name: str | None, hits: int = 0, ms: int = 0, err: bool = False) -> None:
    st = SRC_STATS.setdefault(name or "-", {"n": 0, "hits": 0, "err": 0, "lat": 0})
    st["n"] += 1
    if err:
        st["err"] += 1
        return
    st["lat"] += ms
    if hits:
        st["hits"] += 1


def src_stats_line(name: str | None) -> str:
    st = SRC_STATS.get(name or "-")
    if not st or not st["n"]:
        return "no lookups yet"
    ok = st["n"] - st["err"]
    hit = round(100 * st["hits"] / ok) if ok else 0
    avg = round(st["lat"] / ok) if ok else 0
    return f"{st['n']} lookups · {hit}% hits · {avg}ms · {st['err']} errors"


def cmd_stats_block() -> str:
    if not SRC_STATS:
        return ""
    rows = []
    for name, st in sorted(SRC_STATS.items(), key=lambda kv: -kv[1]["n"])[:6]:
        ok = st["n"] - st["err"]
        hit = round(100 * st["hits"] / ok) if ok else 0
        avg = round(st["lat"] / ok) if ok else 0
        label = "/num" if name == "-" else f"/{name}"
        rows.append(f"<b>{esc(label)}</b> ▸ <code>{st['n']}</code> · ✅ {hit}% · ⚡ {avg}ms · ⚠️ {st['err']}")
    return "\n\n📊 <b>BY COMMAND</b>\n" + tree(rows)


async def strike(bot, user, why: str, weight: int = 1) -> bool:
    """Abuse guard: too many violations in 10 minutes -> automatic temporary ban + admin alert."""
    if user is None or not SETTINGS["abuse_guard"] or is_admin(user.id):
        return False
    now = time.time()
    dq = STRIKES.setdefault(user.id, deque(maxlen=200))
    for _ in range(weight):
        dq.append(now)
    while dq and now - dq[0] > 600:
        dq.popleft()
    if len(dq) < int(SETTINGS["strike_limit"]):
        return False
    STRIKES.pop(user.id, None)
    minutes = int(SETTINGS["ban_minutes"])
    ban_user(user.id, minutes, f"auto: {why}", 0)
    await notify_admins(
        bot,
        f"🚨 <b>AUTO-BAN</b>\n{DIV}\n"
        + block_table([
            ("👤 User", f"{user.full_name} ({user.id})"),
            ("⏱ Duration", fmt_minutes(minutes)),
            ("📝 Reason", why),
        ]),
        rich_buttons([[btn("✅ Unban", f"ub|{user.id}|0", "success")]]),
    )
    return True


async def breaker_fail(bot, name: str | None) -> None:
    """Circuit breaker: repeated API failures pause the command and alert the admins once."""
    key = name or "-"
    bk = BREAKER.setdefault(key, {"fails": 0, "until": 0.0, "alerted": False})
    bk["fails"] += 1
    if bk["fails"] < int(SETTINGS["breaker_fails"]):
        return
    minutes = int(SETTINGS["breaker_minutes"])
    bk["until"] = time.time() + minutes * 60
    if not bk["alerted"]:
        bk["alerted"] = True
        await notify_admins(
            bot,
            f"🧯 <b>CIRCUIT BREAKER TRIPPED</b>\n{DIV}\n"
            + block_table([
                ("🔌 Command", "/num" if key == "-" else f"/{key}"),
                ("❌ Failures in a row", str(bk["fails"])),
                ("⏸ Paused for", f"{minutes}m"),
            ])
            + "\n<i>Users get a friendly notice, admins can still test, and it re-tests itself automatically.</i>",
            rich_buttons([[btn("🧯 Reset now", f"brk|{key}|0", "success")]]),
        )


def render_security() -> tuple[str, InlineKeyboardMarkup]:
    s = SETTINGS
    onoff = lambda v: "ON" if v else "off"  # noqa: E731
    text = (
        f"🔐 <b>SECURITY &amp; RELIABILITY</b>\n{DIV}\n"
        + block_table([
            ("🚨 Abuse guard", onoff(s["abuse_guard"])),
            ("⚡ Strikes before auto-ban", f"{s['strike_limit']} / 10 min"),
            ("⏱ Auto-ban length", fmt_minutes(int(s["ban_minutes"]))),
            ("🧯 Breaker trips after", f"{s['breaker_fails']} failures"),
            ("⏸ Breaker pause", f"{s['breaker_minutes']}m"),
            ("📜 Audit log", f"{onoff(s['audit'])} · {AUDIT_DAYS} days (MongoDB)"),
            ("📰 Daily digest", f"{onoff(s['digest'])} · {DIGEST_HOUR:02d}:00 UTC"),
        ])
        + "\n\n<i>Strikes: rate-limit hits and protected-query attempts. Admins are never struck.</i>"
    )
    rows = [
        [_toggle("ag", "Abuse guard", s["abuse_guard"]), _toggle("au", "Audit log", s["audit"])],
        [_toggle("dg", "Daily digest", s["digest"])],
        [btn("🚨 Strikes before auto-ban", "noop", None)],
        _opt_row("sl", s["strike_limit"], [("5", 5), ("8", 8), ("15", 15), ("30", 30)]),
        [btn("⏱ Auto-ban length", "noop", None)],
        _opt_row("bm", s["ban_minutes"], [("15m", 15), ("1h", 60), ("6h", 360), ("24h", 1440)]),
        [btn("🧯 Breaker: failures to trip", "noop", None)],
        _opt_row("bf", s["breaker_fails"], [("3", 3), ("5", 5), ("10", 10)]),
        [btn("⏸ Breaker: pause length", "noop", None)],
        _opt_row("bk", s["breaker_minutes"], [("2m", 2), ("5m", 5), ("15m", 15)]),
        ADMIN_BACK,
    ]
    return text, rich_buttons(rows)


def render_group_view(gid: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = ALLOWED_GROUPS.get(gid)
    if meta is None:
        return "⚪ That group is no longer authorized.", rich_buttons([[btn("⬅️ Groups", "adm|groups|0")]])
    cmds = meta.get("cmds")
    names = ["num"] + list(SOURCES)
    allowed = names if cmds is None else [n for n in names if n in cmds]
    cap = int(meta.get("cap") or 0)
    muted = bool(meta.get("muted"))
    text = (
        f"⚙️ <b>{esc(meta.get('title', gid))}</b>\n{DIV}\n"
        + tree([
            f"🆔 <b>ID</b> ▸ <code>{gid}</code>",
            f"🔇 <b>Muted</b> ▸ <code>{'YES - the bot stays silent' if muted else 'no'}</code>",
            f"📅 <b>Group daily cap</b> ▸ <code>{'∞' if not cap else cap}</code> <i>(all members together)</i>",
            f"🧩 <b>Commands here</b> ▸ <code>{'all' if cmds is None else (', '.join('/' + n for n in allowed) or 'none')}</code>",
        ])
        + "\n\n<i>Admins are never limited by these settings.</i>"
    )
    rows: list[list[InlineKeyboardButton]] = [
        [btn("🔊 Unmute group" if muted else "🔇 Mute group", f"adm|gmute_{gid}|0", "success" if muted else "danger")],
        [btn("📅 Group daily cap", "noop", None)],
        [btn(f"{'✅ ' if cap == v else ''}{label}", f"adm|gcap_{gid}_{v}|0", "success" if cap == v else "primary")
         for label, v in (("∞", 0), ("50", 50), ("100", 100), ("300", 300), ("1000", 1000))],
        [btn("🧩 Commands allowed here", "noop", None)],
    ]
    toggles = [
        btn(f"{'✅' if n in allowed else '⛔'} /{n}", f"adm|gcmd_{gid}_{n}|0", "success" if n in allowed else "danger")
        for n in names
    ]
    for i in range(0, len(toggles), 2):
        rows.append(toggles[i : i + 2])
    rows.append([btn("🚪 Leave", f"lg|{gid}|0", "danger"), btn("⬅️ Groups", "adm|groups|0")])
    return text, rich_buttons(rows)


def render_optouts() -> tuple[str, InlineKeyboardMarkup]:
    items = list(OPTOUTS.items())[:10]
    body = "\n".join(
        f"🛡 <code>{esc(mask_norm(q['norm']))}</code> · {esc(q['name'])} · {esc(q['where'])}" for _, q in items
    ) or "<i>No pending requests.</i>"
    text = (
        f"📬 <b>OPT-OUT REQUESTS</b> <i>({len(OPTOUTS)})</i>\n{DIV}\n{body}\n\n"
        "<i>Members send <code>/optout &lt;number/username&gt;</code>. Approving adds it to Protected queries.</i>"
    )
    rows = []
    for rid, q in items:
        rows.append([btn(f"✅ Protect {mask_norm(q['norm'])}", f"oo|{rid}|1", "success"),
                     btn("❌ Decline", f"oo|{rid}|0", "danger")])
    rows.append(ADMIN_BACK)
    return text, rich_buttons(rows)


async def cmd_setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    args = list(context.args or [])
    reply = update.effective_message.reply_to_message
    target = None
    if reply and reply.from_user:
        target = reply.from_user.id
    elif args and args[0].lstrip("-").isdigit():
        target = int(args.pop(0))
    val = args[0].lower() if args else ""
    if target is None or not val:
        await update.effective_message.reply_html(
            "Usage: <code>/setlimit &lt;user_id&gt; &lt;number|unlimited|off&gt;</code> (or reply with <code>/setlimit 100</code>)\n"
            "Overrides the daily limit on <b>every</b> command for that user. <code>off</code> removes the override."
        )
        return
    if val in {"off", "reset", "default"}:
        USER_LIMITS.pop(target, None)
        note = "override removed"
    elif val in {"unlimited", "inf", "∞", "0"}:
        USER_LIMITS[target] = 0
        note = "unlimited"
    elif val.isdigit():
        USER_LIMITS[target] = int(val)
        note = f"{int(val)} lookups/day"
    else:
        await update.effective_message.reply_html("⚠️ Send a number, <code>unlimited</code> or <code>off</code>.")
        return
    persist()
    await update.effective_message.reply_html(f"✅ <code>{target}</code> ▸ <b>{note}</b>")


async def cmd_limits(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if not USER_LIMITS:
        await update.effective_message.reply_html("📅 No per-user limit overrides.\nSet one with <code>/setlimit &lt;user_id&gt; &lt;n&gt;</code>.")
        return
    lines = [
        f"<code>{uid}</code> · {esc(USER_STATS.get(uid, {}).get('name', 'unknown'))} ▸ <b>{'unlimited' if not n else n}</b>"
        for uid, n in sorted(USER_LIMITS.items())
    ]
    await update.effective_message.reply_html(f"📅 <b>PER-USER LIMITS</b>\n{DIV}\n" + tree(lines[:40]))


async def cmd_optout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Anyone in an allowed group can ask for their own number / username to be protected."""
    user, chat, msg = update.effective_user, update.effective_chat, update.effective_message
    if user is None or chat is None:
        return
    norms = parse_block_input(" ".join(context.args or []))
    try:
        await msg.delete()  # never leave the number in the chat
    except TelegramError:
        pass

    async def say(text: str) -> None:
        sent = await context.bot.send_message(chat.id, text, parse_mode=ParseMode.HTML)
        autodelete(context.bot, sent, delay=30)

    if not norms:
        await say("🛡 <b>Opt-out</b>\nUsage: <code>/optout &lt;your number / username / email&gt;</code>\n"
                  "Your message is deleted instantly and an admin reviews the request.")
        return
    ck = (user.id, today_utc())
    if OPTOUT_COUNT.get(ck, 0) >= 3 and not is_admin(user.id):
        await say("⏳ You've reached today's request limit.")
        return
    n = norms[0]
    if n in BLOCKED:
        await say("✅ That query is already protected.")
        return
    OPTOUT_COUNT[ck] = OPTOUT_COUNT.get(ck, 0) + 1
    if is_admin(user.id):
        BLOCKED.add(n)
        persist()
        QUERY_CACHE.clear()
        await say("🛡 Protected.")
        return
    rid = secrets.token_hex(4)
    OPTOUTS[rid] = {"norm": n, "uid": user.id, "name": display_name(user),
                    "where": "DM" if chat.type == ChatType.PRIVATE else (chat.title or str(chat.id)), "ts": time.time()}
    await notify_admins(
        context.bot,
        f"📬 <b>OPT-OUT REQUEST</b>\n{DIV}\n"
        + block_table([("🛡 Query", mask_norm(n)), ("👤 From", f"{display_name(user)} ({user.id})"),
                       ("📍 Where", OPTOUTS[rid]["where"])]),
        rich_buttons([[btn("✅ Protect", f"oo|{rid}|1", "success"), btn("❌ Decline", f"oo|{rid}|0", "danger")]]),
    )
    await say("🛡 <b>Request received.</b> An admin will review it shortly.")


async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = uid_of(update)
    text = (update.effective_message.text or "").partition(" ")[2].strip()
    if not text:
        await update.effective_message.reply_html("Usage: <code>/broadcast &lt;message&gt;</code>\nYou'll get a preview before anything is sent.")
        return
    BROADCAST[uid] = text[:3000]
    await update.effective_message.reply_html(
        f"📣 <b>PREVIEW</b>\n{DIV}\n{esc(text[:3000])}\n{DIV}\nSend to <b>{len(ALLOWED_GROUPS)}</b> group(s)?",
        reply_markup=rich_buttons([[btn("📣 Send", "bc|go|1", "success"), btn("✖️ Cancel", "bc|no|0", "danger")]]),
    )


async def send_backup(bot, chat_id: int) -> None:
    snap = snapshot()
    payload = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": 2,
        **{**snap, "groups": {str(k): v for k, v in snap["groups"].items()},
           "limits": {str(k): v for k, v in snap["limits"].items()}},
    }
    blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")
    sent = await bot.send_document(
        chat_id=chat_id,
        document=InputFile(io.BytesIO(blob), filename="osint_bot_backup.json"),
        caption="💾 <b>CONFIG BACKUP</b>\n⚠️ <i>Contains API URLs and keys - keep it private.</i>\n⏳ <i>Self-destructs in 60s</i>",
        parse_mode=ParseMode.HTML,
    )
    autodelete(bot, sent, delay=60)


async def cmd_backup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await send_backup(context.bot, update.effective_chat.id)


async def cmd_audit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    hours = int(context.args[0]) if context.args and context.args[0].isdigit() else 24
    hours = max(1, min(hours, 24 * AUDIT_DAYS))
    since = time.time() - hours * 3600
    rows: list[dict[str, Any]] = []
    try:
        rows = await STORE.export_log(since) if STORE else []
    except Exception:  # noqa: BLE001
        pass
    if not rows:
        rows = [e for e in LOG if e["ts"] >= since]
    blob = json.dumps({"since_hours": hours, "count": len(rows), "entries": rows}, indent=2,
                      ensure_ascii=False, default=str).encode("utf-8")
    sent = await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=InputFile(io.BytesIO(blob), filename=f"audit_{hours}h.json"),
        caption=f"📜 <b>AUDIT LOG</b> · last {hours}h · {len(rows)} entries\n⏳ <i>Self-destructs in 2 min</i>",
        parse_mode=ParseMode.HTML,
    )
    autodelete(context.bot, sent, delay=120)


async def maybe_digest(bot, force: bool = False, chat_id: int | None = None) -> None:
    now = datetime.now(timezone.utc)
    if not force and (not SETTINGS["digest"] or now.hour != DIGEST_HOUR or DIGEST["day"] == today_utc()):
        return
    base = DIGEST["base"]
    d_n = STATS["searches"] - base["searches"]
    d_h = STATS["hits"] - base["hits"]
    d_e = STATS["errors"] - base["errors"]
    d_u = len(STATS["users"]) - base["users"]
    top = sorted(((SRC_STATS[n]["n"] - base["src"].get(n, 0), n) for n in SRC_STATS), reverse=True)[:5]
    top_lines = [f"<b>{'/num' if n == '-' else '/' + esc(n)}</b> ▸ <code>{c}</code>" for c, n in top if c > 0]
    text = (
        f"📰 <b>DAILY DIGEST</b>\n{DIV}\n"
        + block_table([
            ("🔎 Lookups", str(d_n)),
            ("✅ Hit rate", f"{round(100 * d_h / d_n)}%" if d_n else "-"),
            ("⚠️ Errors", str(d_e)),
            ("👥 New users", str(max(0, d_u))),
            ("🚫 Active bans", str(sum(1 for u in BANNED if is_banned(u)))),
            ("🧯 Breakers open", str(sum(1 for b in BREAKER.values() if b["until"] > time.time()))),
            ("🛠 In maintenance", str(sum(1 for c in SOURCES.values() if maint_active(c)))),
            ("📬 Opt-outs pending", str(len(OPTOUTS))),
        ])
        + (("\n\n🏆 <b>TOP COMMANDS</b>\n" + tree(top_lines)) if top_lines else "")
    )
    if chat_id is not None:
        await bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)
    else:
        await notify_admins(bot, text)
    if not force:
        DIGEST["day"] = today_utc()
        DIGEST["base"] = {"searches": STATS["searches"], "hits": STATS["hits"], "errors": STATS["errors"],
                          "users": len(STATS["users"]), "src": {n: SRC_STATS[n]["n"] for n in SRC_STATS}}


async def housekeeping_tick(bot) -> None:
    now = time.time()
    changed = False
    for src in SOURCES.values():
        if src.get("maintenance") and src.get("maint_until") and now >= src["maint_until"]:
            src["maintenance"], src["maint_until"] = False, 0.0
            changed = True
    for uid in [u for u, i in BAN_INFO.items() if i.get("until") and now >= i["until"]]:
        BANNED.discard(uid)
        BAN_INFO.pop(uid, None)
        changed = True
    for key in [k for k, g in GRANTS.items() if g.get("until") and now >= g["until"]]:
        GRANTS.pop(key, None)  # timed grants end by themselves
        changed = True
    for uid, dq in list(STRIKES.items()):
        while dq and now - dq[0] > 600:
            dq.popleft()
        if not dq:
            STRIKES.pop(uid, None)
    for rid in [r for r, q in OPTOUTS.items() if now - q["ts"] > 7 * 86400]:
        OPTOUTS.pop(rid, None)
    today = today_utc()
    for k in [k for k in OPTOUT_COUNT if k[1] != today]:
        OPTOUT_COUNT.pop(k, None)
    if changed:
        persist()
        await refresh_commands(bot)
    await maybe_digest(bot)


async def housekeeping(bot) -> None:
    """Every minute: end timed maintenance, expire temp bans, prune stale state, send the digest."""
    while True:
        await asyncio.sleep(60)
        try:
            await housekeeping_tick(bot)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")


# --------------------------------------------------------------------------- #
# Manual values and per-user grants                                            #
# --------------------------------------------------------------------------- #

UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
VAL_FIELDS = {"cd": "cooldown", "dl": "daily_limit", "ad": "auto_delete", "ct": "cache_ttl", "mt": "maint"}
GRANT_PROMPTS = {
    "grantuid": "🔢 <b>User ID</b>\nSend the person's numeric Telegram user ID.\n<i>Tip: “Pick recent user” lists people the bot has already seen.</i>",
    "grantlimit": "🔢 <b>Daily lookups</b>\nSend a number such as <code>37</code>, or <code>unlimited</code>.",
    "grantdur": "⏳ <b>How long?</b>\nSend a duration such as <code>90m</code>, <code>12h</code>, <code>10d</code>, <code>2w</code> - or <code>perm</code> for no end.",
}


def _secs(t: str) -> float | None:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", t)
    return float(m.group(1)) * UNIT_SECONDS[m.group(2) or "s"] if m else None


def parse_field(field: str, text: str) -> tuple[bool, Any]:
    """Parse a manually typed value. (True, None) means 'follow the global setting'."""
    t = text.strip().lower()
    if t in {"g", "global", "default", "reset"}:
        return True, None
    if field == "daily_limit":
        if t in {"unlimited", "inf", "∞", "none"}:
            return True, 0
        if t.isdigit() and int(t) <= 1_000_000:
            return True, int(t)
        return False, "Send a whole number (e.g. <code>37</code>), <code>unlimited</code> or <code>global</code>."
    v = 0.0 if t in {"off", "never", "none"} else _secs(t)
    if field == "cooldown":
        if v is None or v > 3600:
            return False, "Send seconds or a duration up to 1h, e.g. <code>7</code>, <code>45s</code>, <code>2m</code>."
        return True, float(v)
    if v is None or v > 7 * 86400:
        return False, "Send a duration up to 7d, e.g. <code>90s</code>, <code>10m</code>, <code>2h</code> or <code>off</code>."
    return True, int(v)


def parse_maint(text: str) -> tuple[bool, Any]:
    t = text.strip().lower()
    if t in {"off", "0", "stop", "end"}:
        return True, 0
    if t in {"perm", "permanent", "forever", "indefinite"}:
        return True, -1
    mins = parse_duration(t)
    if mins is None or mins <= 0 or mins > 90 * 1440:
        return False, "Send a duration such as <code>45m</code>, <code>3h</code>, <code>2d</code>, <code>perm</code> or <code>off</code>."
    return True, mins * 60


def val_prompt(field: str, name: str | None) -> str:
    scope = f"/{esc(name)}" if name else "all commands"
    what = {
        "cooldown": ("⏱ <b>Cooldown per user</b>", "seconds or a duration (max 1h): <code>7</code>, <code>45s</code>, <code>2m</code>"),
        "daily_limit": ("📅 <b>Daily limit per user</b>", "a number: <code>37</code> - or <code>unlimited</code>"),
        "auto_delete": ("🧹 <b>Auto-delete timer</b>", "how long results stay: <code>90s</code>, <code>3m</code>, <code>1h</code> - or <code>off</code>"),
        "cache_ttl": ("♻️ <b>Result cache</b>", "how long identical lookups are reused: <code>45s</code>, <code>10m</code>, <code>2h</code> - or <code>off</code>"),
        "maint": ("🛠 <b>Maintenance length</b>", "how long it lasts: <code>45m</code>, <code>3h</code>, <code>2d</code>, <code>perm</code> - or <code>off</code>"),
    }[field]
    tail = "" if (name is None or field == "maint") else "\nSend <code>global</code> to follow the global setting again."
    return f"✏️ {what[0]} · <i>{scope}</i>\nSend {what[1]}.{tail}"


def new_draft() -> dict[str, Any]:
    return {"uid": None, "cmd": "*", "limit": 0, "secs": 0}


def grant_label(cmd: str) -> str:
    return "all commands" if cmd == "*" else ("/num" if cmd == "-" else f"/{cmd}")


def grant_scope_key(tok: str) -> str | None:
    t = tok.strip().lower().lstrip("/")
    if t in {"all", "*", "everything"}:
        return "*"
    if t in {"num", "default", "-", "search"}:
        return "-"
    return t if t in SOURCES else None


def set_grant(uid: int, cmd: str, limit: int, secs: int, by: int) -> None:
    GRANTS[(uid, cmd)] = {"limit": int(limit), "until": time.time() + secs if secs else 0.0, "by": by}
    persist()


def grant_line(uid: int, cmd: str, g: dict[str, Any]) -> str:
    name = USER_STATS.get(uid, {}).get("name", "unknown")
    amount = "unlimited" if not g["limit"] else f"{g['limit']}/day"
    ends = f"ends in {fmt_left(g['until'] - time.time())}" if g.get("until") else "no end"
    return f"{'♾' if not g['limit'] else '🔢'} <code>{uid}</code> · {esc(shorten(name, 18))} ▸ {esc(grant_label(cmd))} ▸ <b>{amount}</b> · {ends}"


def render_grants() -> tuple[str, InlineKeyboardMarkup]:
    now = time.time()
    live = [(k, g) for k, g in sorted(GRANTS.items()) if not (g.get("until") and now >= g["until"])][:15]
    body = "\n".join(grant_line(u, c, g) for (u, c), g in live) or "<i>No grants yet.</i>"
    text = (
        f"🎁 <b>GRANTS</b> <i>({len(live)})</i>\n{DIV}\n{body}\n\n"
        "<i>A grant replaces the normal daily limit for one person - on one command or all. "
        "Cooldowns still apply. Quick add: <code>/grant &lt;user_id&gt; &lt;command|all&gt; &lt;unlimited|N&gt; [duration]</code></i>"
    )
    rows = [[btn(f"🗑 {u} · {shorten(grant_label(c), 14)}", f"gr|x_{u}_{c}|0", "danger")] for (u, c), _ in live]
    rows.append([btn("➕ New grant", "gr|new|0", "success")])
    rows.append(ADMIN_BACK)
    return text, rich_buttons(rows)


def render_grant_users() -> tuple[str, InlineKeyboardMarkup]:
    people = sorted(((u, i) for u, i in USER_STATS.items() if not is_admin(u)), key=lambda kv: -kv[1]["last"])[:12]
    text = (
        f"👤 <b>PICK A USER</b>\n{DIV}\n"
        + ("People the bot has seen recently - newest first." if people else "<i>No users seen yet. Use “Enter user ID”.</i>")
    )
    btns = [btn(shorten(i["name"], 18) or str(u), f"gr|u_{u}|0", "primary") for u, i in people]
    rows = [btns[i : i + 2] for i in range(0, len(btns), 2)]
    rows.append([btn("🔢 Enter user ID", "gr|uidp|0", "success"), btn("⬅️ Back", "gr|build|0")])
    return text, rich_buttons(rows)


def render_grant_builder(admin_id: int) -> tuple[str, InlineKeyboardMarkup]:
    d = GRANT_DRAFT.setdefault(admin_id, new_draft())
    who = "- not chosen -" if d["uid"] is None else f"{USER_STATS.get(d['uid'], {}).get('name', 'user')} ({d['uid']})"
    text = (
        f"🎁 <b>NEW GRANT</b>\n{DIV}\n"
        + tree([
            f"👤 <b>User</b> ▸ <code>{esc(who)}</code>",
            f"🧩 <b>Applies to</b> ▸ <code>{esc(grant_label(d['cmd']))}</code>",
            f"🔢 <b>Daily lookups</b> ▸ <code>{'unlimited ♾' if not d['limit'] else d['limit']}</code>",
            f"⏳ <b>Lasts</b> ▸ <code>{'until you remove it' if not d['secs'] else fmt_left(d['secs'])}</code>",
        ])
        + "\n\n<i>Choose below, then tap “Create grant”. Unlimited or any number you type.</i>"
    )
    scopes = [("*", "All commands"), ("-", "/num")] + [(n, f"/{n}") for n in SOURCES]
    scope_btns = [btn(f"{'✅ ' if d['cmd'] == k else ''}{label}", f"gr|c_{k}|0", "success" if d["cmd"] == k else "primary")
                  for k, label in scopes]
    rows: list[list[InlineKeyboardButton]] = [
        [btn("👤 Pick recent user", "gr|pick|0", "primary"), btn("🔢 Enter user ID", "gr|uidp|0", "primary")],
        [btn("🧩 Applies to", "noop", None)],
    ]
    rows += [scope_btns[i : i + 3] for i in range(0, len(scope_btns), 3)]
    rows.append([btn("🔢 Daily lookups", "noop", None), btn("✏️ Custom", "gr|limp|0", "success")])
    rows.append([btn(f"{'✅ ' if d['limit'] == v else ''}{label}", f"gr|l_{v}|0", "success" if d["limit"] == v else "primary")
                 for label, v in (("∞", 0), ("10", 10), ("25", 25), ("50", 50), ("100", 100), ("500", 500))])
    rows.append([btn("⏳ Lasts", "noop", None), btn("✏️ Custom", "gr|durp|0", "success")])
    rows.append([btn(f"{'✅ ' if d['secs'] == v else ''}{label}", f"gr|d_{v}|0", "success" if d["secs"] == v else "primary")
                 for label, v in (("1h", 3600), ("1d", 86400), ("7d", 604800), ("30d", 2592000), ("♾", 0))])
    rows.append([btn("✅ Create grant", "gr|go|0", "success")])
    rows.append([btn("🎁 All grants", "gr|list|0"), ADMIN_BACK[0]])
    return text, rich_buttons(rows)


def _grant_target(update: Update, args: list[str]) -> int | None:
    reply = update.effective_message.reply_to_message
    if reply and reply.from_user:
        USER_STATS.setdefault(reply.from_user.id, {"name": reply.from_user.full_name, "count": 0, "last": 0.0})
        return reply.from_user.id
    if args and args[0].lstrip("-").isdigit():
        return int(args.pop(0))
    return None


async def cmd_grant(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    args = list(context.args or [])
    target = _grant_target(update, args)
    if target is None or len(args) < 2:
        await update.effective_message.reply_html(
            "Usage: <code>/grant &lt;user_id&gt; &lt;command|all|num&gt; &lt;unlimited|N&gt; [duration]</code>\n"
            "Examples:\n<code>/grant 123456 tg unlimited 7d</code>\n<code>/grant 123456 all 200</code>\n"
            "Reply to someone's message with <code>/grant tg unlimited</code> to skip the ID."
        )
        return
    scope = grant_scope_key(args[0])
    if scope is None:
        await update.effective_message.reply_html(
            f"⚠️ Unknown command <code>{esc(args[0])}</code>. Use <code>all</code>, <code>num</code>"
            + (" or one of: " + ", ".join(f"<code>{esc(n)}</code>" for n in SOURCES) if SOURCES else ".")
        )
        return
    good, limit = parse_field("daily_limit", args[1])
    if not good or limit is None:
        await update.effective_message.reply_html("⚠️ Send a number or <code>unlimited</code>.")
        return
    secs = 0
    if len(args) > 2:
        mins = parse_duration(args[2])
        if mins is None:
            await update.effective_message.reply_html("⚠️ Duration like <code>12h</code>, <code>7d</code>, <code>2w</code> or <code>perm</code>.")
            return
        secs = mins * 60
    if is_admin(target):
        await update.effective_message.reply_html("🛡 Admins are already unlimited.")
        return
    set_grant(target, scope, limit, secs, user.id)
    await update.effective_message.reply_html(
        f"🎁 <b>Granted</b> <code>{target}</code>\n"
        + block_table([("🧩 Applies to", grant_label(scope)),
                       ("🔢 Daily lookups", "unlimited" if not limit else str(limit)),
                       ("⏳ Lasts", fmt_left(secs) if secs else "until removed")])
    )


async def cmd_revoke(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    if not user or not is_admin(user.id):
        return
    args = list(context.args or [])
    target = _grant_target(update, args)
    if target is None:
        await update.effective_message.reply_html("Usage: <code>/revoke &lt;user_id&gt; [command|all]</code> (no command = remove every grant)")
        return
    if args:
        scope = grant_scope_key(args[0])
        removed = 1 if scope is not None and GRANTS.pop((target, scope), None) is not None else 0
    else:
        keys = [k for k in GRANTS if k[0] == target]
        for k in keys:
            GRANTS.pop(k, None)
        removed = len(keys)
    persist()
    await update.effective_message.reply_html(
        f"🗑 Removed <b>{removed}</b> grant(s) from <code>{target}</code>." if removed else "That user had no matching grant."
    )


async def cmd_grants(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_grants()
    await update.effective_message.reply_html(text, reply_markup=markup)


# --------------------------------------------------------------------------- #
# Callbacks                                                                    #
# --------------------------------------------------------------------------- #

KEYED_ACTIONS = {"p", "d", "x", "f", "close"}
ADMIN_ACTIONS = {"adm", "set", "ub", "lg", "ap", "rj", "cx", "oo", "bc", "brk", "gr"}


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
        elif key == "security":
            await query.answer()
        elif key == "optouts":
            await query.answer()
        elif key == "digest":
            await query.answer("Sending digest…")
            await maybe_digest(context.bot, force=True, chat_id=query.message.chat_id)
            return
        elif key == "backup":
            await query.answer("Preparing backup…")
            await send_backup(context.bot, query.message.chat_id)
            return
        elif key.startswith("gv_"):
            await query.answer()
        elif key.startswith("gmute_"):
            meta = ALLOWED_GROUPS.get(int(key[6:]))
            if meta is not None:
                meta["muted"] = not meta.get("muted", False)
                persist()
            await query.answer("Saved ✅")
            key = "gv_" + key[6:]
        elif key.startswith("gcap_"):
            _, g, n = key.split("_", 2)
            meta = ALLOWED_GROUPS.get(int(g))
            if meta is not None:
                meta["cap"] = int(n)
                persist()
            await query.answer("Saved ✅")
            key = f"gv_{g}"
        elif key.startswith("gcmd_"):
            _, g, cname = key.split("_", 2)
            meta = ALLOWED_GROUPS.get(int(g))
            if meta is not None:
                names = ["num"] + list(SOURCES)
                current = set(names if meta.get("cmds") is None else meta["cmds"])
                current ^= {cname}
                meta["cmds"] = None if current >= set(names) else sorted(current)
                persist()
            await query.answer("Saved ✅")
            key = f"gv_{g}"
        elif key.startswith("val_"):
            field = VAL_FIELDS.get(key[4:])
            if not field or field in {"cache_ttl", "maint"}:
                await query.answer("Unknown setting.")
                return
            await query.answer()
            INPUT[user_id] = {"op": "val", "cmd": None, "field": field, "chat": query.message.chat_id,
                              "mid": query.message.message_id, "ts": time.time()}
            await _safe_edit(query, val_prompt(field, None), prompt_markup(None, "cancelset"))
            return
        elif key == "dbping":
            _, info = await STORE.ping() if STORE else (False, "No storage initialised")
            await query.answer(info[:190], show_alert=True)
            return
        elif key == "blkadd":
            await query.answer()
            INPUT[user_id] = {"op": "gblock", "cmd": None, "chat": query.message.chat_id,
                              "mid": query.message.message_id, "ts": time.time()}
            await _safe_edit(query, PROMPTS["gblock"], prompt_markup(None, "cancelg"))
            return
        elif key == "blkclr":
            BLOCKED.clear()
            persist()
            await query.answer("Cleared")
            key = "blocklist"
        elif key.startswith("unb_"):
            tk = key[4:]
            for n in [n for n in BLOCKED if qtok(n) == tk]:
                BLOCKED.discard(n)
            persist()
            await query.answer("Unblocked ✅")
            key = "blocklist"
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
        elif key == "blocklist":
            text, markup = render_blocklist()
        elif key == "security":
            text, markup = render_security()
        elif key == "optouts":
            text, markup = render_optouts()
        elif key.startswith("gv_"):
            text, markup = render_group_view(int(key[3:]))
        else:
            text, markup = render_admin()
        await _safe_edit(query, text, markup)
        return

    if action == "gr":  # grants: list, guided builder, removal
        d = GRANT_DRAFT.setdefault(user_id, new_draft())
        view, note = "builder", None
        if key == "new":
            GRANT_DRAFT[user_id] = new_draft()
        elif key == "list":
            view = "list"
        elif key == "pick":
            view = "users"
        elif key == "build":
            INPUT.pop(user_id, None)
        elif key.startswith("u_"):
            d["uid"] = int(key[2:])
        elif key.startswith("c_"):
            d["cmd"] = key[2:]
        elif key.startswith("l_"):
            d["limit"] = int(key[2:])
        elif key.startswith("d_"):
            d["secs"] = int(key[2:])
        elif key in {"uidp", "limp", "durp"}:
            await query.answer()
            op = {"uidp": "grantuid", "limp": "grantlimit", "durp": "grantdur"}[key]
            INPUT[user_id] = {"op": op, "cmd": None, "admin": user_id, "chat": query.message.chat_id,
                              "mid": query.message.message_id, "ts": time.time()}
            await _safe_edit(query, GRANT_PROMPTS[op], rich_buttons([[btn("✖️ Cancel", "gr|build|0", "danger")]]))
            return
        elif key == "go":
            if d["uid"] is None:
                await query.answer("Pick a user first.", show_alert=True)
                return
            if is_admin(d["uid"]):
                await query.answer("Admins are already unlimited.", show_alert=True)
                return
            set_grant(d["uid"], d["cmd"], d["limit"], d["secs"], user_id)
            note, view = "Grant created 🎁", "list"
        elif key.startswith("x_"):
            uid_s, _, cmd = key[2:].partition("_")
            GRANTS.pop((int(uid_s), cmd), None)
            persist()
            note, view = "Grant removed", "list"
        await query.answer(note)
        if view == "list":
            text, markup = render_grants()
        elif view == "users":
            text, markup = render_grant_users()
        else:
            text, markup = render_grant_builder(user_id)
        await _safe_edit(query, text, markup)
        return

    if action == "oo":  # opt-out request decision
        req = OPTOUTS.pop(key, None)
        if req is None:
            await query.answer("Already handled.")
            await _safe_edit(query, "ℹ️ That request was already handled.", done)
            return
        if index == 1:
            BLOCKED.add(req["norm"])
            persist()
            QUERY_CACHE.clear()
            await query.answer("Protected ✅")
            await _safe_edit(query, f"🛡 <b>PROTECTED</b> ▸ <code>{esc(mask_norm(req['norm']))}</code>\nRequested by {esc(req['name'])}", done)
        else:
            await query.answer("Declined")
            await _safe_edit(query, f"❌ <b>DECLINED</b> ▸ <code>{esc(mask_norm(req['norm']))}</code>", done)
        return

    if action == "bc":  # broadcast confirmation
        text = BROADCAST.pop(user_id, None)
        if index == 0 or not text:
            await query.answer("Cancelled")
            await _safe_edit(query, "✖️ Broadcast cancelled.", done)
            return
        await query.answer("Sending…")
        ok = fail = 0
        for gid in list(ALLOWED_GROUPS):
            try:
                await context.bot.send_message(
                    gid, f"📣 <b>Announcement</b>\n{DIV}\n{esc(text)}", parse_mode=ParseMode.HTML
                )
                ok += 1
            except TelegramError:
                fail += 1
            await asyncio.sleep(0.05)
        await _safe_edit(query, f"📣 <b>BROADCAST DONE</b>\n{DIV}\n✅ Sent: {ok}\n❌ Failed: {fail}", done)
        return

    if action == "brk":  # reset a circuit breaker
        BREAKER.pop(key, None)
        await query.answer("Breaker reset ✅")
        await _safe_edit(query, f"🧯 <b>Breaker reset</b> for <code>{esc('/num' if key == '-' else '/' + key)}</code>.", done)
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
        text, markup = render_security() if key in SECURITY_KEYS else render_settings()
        await _safe_edit(query, text, markup)
        return

    if action == "ub":
        unban_user(int(key))
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
        pp = profile(META.get(key, {}).get("src"))
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
                + delete_note(eff(pp, 'auto_delete'))
            ),
            parse_mode=ParseMode.HTML,
        )
        autodelete(context.bot, sent, delay=eff(pp, 'auto_delete'))
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
    await init_storage()
    await refresh_commands(bot)

    app.bot_data["sweeper"] = asyncio.create_task(pending_sweeper(bot))
    app.bot_data["housekeeping"] = asyncio.create_task(housekeeping(bot))
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
            ("🧩 Custom commands", str(len(SOURCES))),
            ("💾 Storage", storage_label()),
            ("🧹 Auto-delete", fmt_dur(SETTINGS["auto_delete"])),
        ])
        + (f"\n\n⚠️ <b>{esc(STORAGE['note'])}</b>\n<i>Groups and commands will NOT survive a redeploy until this is fixed.</i>" if STORAGE["note"] else ""),
    )


async def post_shutdown(app: Application) -> None:
    for key in ("sweeper", "housekeeping"):
        task = app.bot_data.get(key)
        if task:
            task.cancel()
    if STORE is not None:
        await STORE.close()
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
    app.add_handler(CommandHandler("block", cmd_block, filters=private))
    app.add_handler(CommandHandler("unblock", cmd_unblock, filters=private))
    app.add_handler(CommandHandler("setlimit", cmd_setlimit))   # admin-checked; reply-to-set in groups
    app.add_handler(CommandHandler("limits", cmd_limits, filters=private))
    app.add_handler(CommandHandler("grant", cmd_grant))      # admin-checked; reply-to-grant works in groups
    app.add_handler(CommandHandler("revoke", cmd_revoke))
    app.add_handler(CommandHandler("grants", cmd_grants, filters=private))
    app.add_handler(CommandHandler("broadcast", cmd_broadcast, filters=private))
    app.add_handler(CommandHandler("backup", cmd_backup, filters=private))
    app.add_handler(CommandHandler("audit", cmd_audit, filters=private))
    app.add_handler(CommandHandler("optout", cmd_optout))        # members of allowed groups + admins
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
