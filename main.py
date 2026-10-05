#!/usr/bin/env python3
"""
Lookup Bot v5 - single file, production ready.

ACCESS
  Private chat : admins only (ADMIN_IDS).
  Groups       : only allow-listed groups. Added by an admin -> auto-approved.
                 Added by anyone else -> silent "pending" + Approve/Reject buttons for admins.
  Buttons      : in groups only the person who ran the search (or an admin) can press them.

LOG CHANNEL
  Add the bot as ADMIN to a channel (an admin must do it) -> it becomes the log channel automatically,
  or use /setlog <chat_id>, or LOG_CHANNEL_ID env. Every user, search, warn, ban, join and admin action is
  posted there AND stored in the bot's own event store (file or MongoDB). Telegram bots cannot read channel
  history, so /userinfo and /exportlog build the JSON / TXT files from that event store.

RESPONSE MAPPING (per command, no redeploy)
  /cmds -> open a command -> "Response map". JSON like:
  {
    "rows_path": "data.result",                 # where the list of records lives (optional)
    "remove_keys": ["credit", "developer"],     # removed at ANY depth, case-insensitive
    "rename": {"fname": "Father Name"},         # rename keys
    "replace": {"@OldBrand": "@MyBrand"},       # text replace in every value ("" = delete the text)
    "regex": {"(?i)powered by .*": ""}          # regex replace in every value
  }
  "Strip branding" button adds common branding keys in one tap. Every command also has a Raw JSON row view
  (button on each result, and "Raw JSON by default" per command).

MODERATION
  Abuse guard -> strike -> automatic WARNING (reply to the user, every time) -> after WARN_LIMIT warnings an
  automatic temporary BAN (reply + DM, every time). Banned users get a notice whenever they try to use the bot.
  Manual: /warn /unwarn /ban /unban /banned (reply or user id).

ENV
  BOT_TOKEN, ADMIN_IDS (required) | SEARCH_API_URL, API_HEADERS(JSON) | LOG_CHANNEL_ID
  MONGODB_URI, MONGODB_DB (optional; otherwise STATE_FILE + EVENTS_FILE) | EVENT_DAYS (0 = keep forever)
  WEBHOOK_URL (or RENDER_EXTERNAL_URL), WEBHOOK_SECRET, PORT | BOT_NAME | EMOJI_SEARCH | MIN_QUERY | PAGE_SIZE
  AUTO_DELETE_SECONDS, COOLDOWN_SECONDS, DAILY_LIMIT, PENDING_TTL_HOURS, REQUEST_TIMEOUT, QUERY_CACHE_TTL

Requirements: python-telegram-bot[rate-limiter,webhooks]>=22.7  aiohttp  (pymongo>=4.9 only if MONGODB_URI)
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
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlparse

import aiohttp
from telegram import (
    BotCommand, BotCommandScopeAllChatAdministrators, BotCommandScopeAllGroupChats, BotCommandScopeChat,
    InlineKeyboardButton, InlineKeyboardMarkup, InputFile, LinkPreviewOptions, ReplyParameters, Update,
)
from telegram.constants import ChatMemberStatus, ChatType, ParseMode
from telegram.error import BadRequest, RetryAfter, TelegramError
from telegram.ext import (
    AIORateLimiter, Application, ApplicationBuilder, ApplicationHandlerStop, CallbackQueryHandler,
    ChatMemberHandler, CommandHandler, ContextTypes, MessageHandler, TypeHandler, filters,
)

# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #


def env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


BOT_TOKEN = os.environ.get("BOT_TOKEN", "8748100209:AAGZptgEMNrkMT5ZZ89VQYQfHHKd0zk3mto").strip()
BOT_NAME = os.environ.get("BOT_NAME", "OSINT Lookup")
ADMIN_IDS: set[int] = {int(x) for x in re.split(r"[,\s]+", os.environ.get("ADMIN_IDS", "6846112069, 7910994767")) if x.strip().isdigit()}
SEARCH_API_URL = os.environ.get("SEARCH_API_URL", "https://icmr-and-hitek-7fdc.vercel.app/search?q={q}").strip()
LOG_CHANNEL_ID = int(os.environ.get("LOG_CHANNEL_ID", "0") or 0)
EMOJI_SEARCH = os.environ.get("EMOJI_SEARCH") or None
PAGE_SIZE = max(1, min(8, int(os.environ.get("PAGE_SIZE", "4"))))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "25"))
MIN_QUERY = int(os.environ.get("MIN_QUERY", "3"))
QUERY_TTL = float(os.environ.get("QUERY_CACHE_TTL", "90"))
PENDING_TTL = float(os.environ.get("PENDING_TTL_HOURS", "24")) * 3600
EVENT_DAYS = int(os.environ.get("EVENT_DAYS", "0"))
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB = os.environ.get("MONGODB_DB", "osint_bot").strip() or "osint_bot"
STATE_FILE = os.environ.get("STATE_FILE", "bot_state.json")
EVENTS_FILE = os.environ.get("EVENTS_FILE", "bot_events.jsonl")
WEBHOOK_URL = (os.environ.get("WEBHOOK_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "https://numinfo-bot-eeek.onrender.com").strip().rstrip("/")
PORT = int(os.environ.get("PORT", "10000"))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip() or secrets.token_urlsafe(24)

logging.basicConfig(format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s", level=logging.INFO)
for _n in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(_n).setLevel(logging.WARNING)
log = logging.getLogger("lookup-bot")

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN is required")
if not ADMIN_IDS:
    raise SystemExit("ADMIN_IDS is required")

try:
    API_HEADERS = {str(k): str(v) for k, v in json.loads(os.environ.get("API_HEADERS", "") or "{}").items()}
except Exception:  # noqa: BLE001
    API_HEADERS = {}

GROUP_TYPES = (ChatType.GROUP, ChatType.SUPERGROUP)
MAX_MESSAGE = 3900
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

DEFAULTS: dict[str, Any] = {
    "auto_delete": int(os.environ.get("AUTO_DELETE_SECONDS", "120")),
    "delete_queries": True, "lockdown": False, "members_can_search": True, "mask": True,
    "cooldown": float(os.environ.get("COOLDOWN_SECONDS", "3")),
    "daily_limit": int(os.environ.get("DAILY_LIMIT", "50")),
    "welcome": True, "welcome_delete": 180, "welcome_text": "",
    "abuse_guard": True, "strike_limit": 6, "warn_limit": 3, "ban_minutes": 60,
    "log_queries": True, "log_files": False,
    "breaker_fails": 5, "breaker_minutes": 5,
}
S: dict[str, Any] = dict(DEFAULTS)  # live settings
STATE: dict[str, Any] = {}          # persisted state (see fresh_state)

# runtime-only
CACHE: dict[str, "Result"] = {}
META: dict[str, dict[str, Any]] = {}
QCACHE: dict[str, "Result"] = {}
INFLIGHT: dict[str, asyncio.Task] = {}
LAST: dict[tuple[int, str], float] = {}
USAGE: dict[tuple[int, str], tuple[str, int]] = {}
STRIKES: dict[int, deque] = {}
BREAKER: dict[str, dict[str, Any]] = {}
PENDING: dict[int, dict[str, Any]] = {}
OPTOUTS: dict[str, dict[str, Any]] = {}
INPUT: dict[int, dict[str, Any]] = {}
NOTICE: dict[tuple[str, int], float] = {}
STATS: dict[str, Any] = {"searches": 0, "hits": 0, "errors": 0, "lat": 0, "started": time.time()}
STORE: Any = None
_BG: set[asyncio.Task] = set()
LOGQ: asyncio.Queue = asyncio.Queue(maxsize=3000)
DIRTY = False
_SESSION: aiohttp.ClientSession | None = None


def fresh_state() -> dict[str, Any]:
    return {"settings": {}, "groups": {}, "bans": {}, "warns": {}, "sources": {}, "blocked": [],
            "users": {}, "limits": {}, "log_chat": LOG_CHANNEL_ID}


SRC_DEFAULT: dict[str, Any] = {
    "url": "", "title": "", "emoji": "🛰", "emoji_id": None, "style": "primary", "hide": [], "icons": {},
    "footer": "", "min_len": MIN_QUERY, "headers": {}, "enabled": True, "cooldown": None,
    "daily_limit": None, "auto_delete": None, "no_log": False, "raw_default": False,
    "maintenance": False, "maint_msg": "", "transform": {}, "backup_url": "",
}
BRAND_KEYS = ["credit", "credits", "developer", "dev", "owner", "powered_by", "poweredby", "made_by", "by",
              "channel", "telegram", "join", "support", "api_by", "author", "copyright", "contact", "promo",
              "advert", "ad", "watermark", "note_from_dev"]
RESERVED = {"start", "menu", "help", "admin", "cmds", "addcmd", "delcmd", "setmap", "connect", "groups",
            "allowgroup", "denygroup", "ban", "unban", "warn", "unwarn", "banned", "block", "unblock",
            "setlimit", "setlog", "userinfo", "exportlog", "broadcast", "setwelcome", "optout", "cancel"}
CMD_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")


def new_source(name: str, url: str) -> dict[str, Any]:
    s = json.loads(json.dumps(SRC_DEFAULT))
    s["url"], s["title"] = url, f"{name.upper()} Lookup"
    return s


SOURCES: dict[str, dict[str, Any]] = {}

# --------------------------------------------------------------------------- #
# Small helpers                                                                #
# --------------------------------------------------------------------------- #


def is_admin(uid: int | None) -> bool:
    return bool(uid) and uid in ADMIN_IDS


def esc(v: Any) -> str:
    return html.escape(str(v), quote=False)


def shorten(t: Any, n: int) -> str:
    t = re.sub(r"\s+", " ", str(t)).strip()
    return t if len(t) <= n else t[: n - 1].rstrip() + "…"


def today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def stamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + " UTC"


def clock(ts: float | None = None) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def fmt_dur(s: float) -> str:
    s = int(s)
    if s <= 0:
        return "off"
    if s % 3600 == 0:
        return f"{s // 3600}h"
    if s % 60 == 0:
        return f"{s // 60}m"
    return f"{s}s"


def fmt_left(sec: float) -> str:
    sec = int(max(0, sec))
    if sec < 90:
        return f"{sec}s"
    m = sec // 60
    if m < 120:
        return f"{m}m"
    h = m // 60
    return f"{h}h {m % 60}m" if h < 48 else f"{h // 24}d {h % 24}h"


def fmt_minutes(m: int) -> str:
    if m <= 0:
        return "permanent"
    if m % 1440 == 0:
        return f"{m // 1440}d"
    if m % 60 == 0:
        return f"{m // 60}h"
    return f"{m}m"


def parse_secs(t: str) -> float | None:
    t = t.strip().lower()
    if t in {"off", "never", "none"}:
        return 0.0
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", t)
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] if m else None


def parse_minutes(t: str) -> int | None:
    t = t.strip().lower()
    if t in {"perm", "permanent", "forever"}:
        return 0
    m = re.fullmatch(r"(\d+)([mhdw]?)", t)
    return int(m.group(1)) * {"": 1, "m": 1, "h": 60, "d": 1440, "w": 10080}[m.group(2)] if m else None


def mention(uid: int, name: str) -> str:
    return f'<a href="tg://user?id={uid}">{esc(shorten(name, 40))}</a>'


def utag(uid: int, name: str, username: str = "") -> str:
    return f"{mention(uid, name)} · <code>{uid}</code>" + (f" · @{esc(username)}" if username else "")


def norm_query(q: str) -> str:
    q = q.strip().casefold()
    d = re.sub(r"[\s\-().+]", "", q)
    if d.isdigit() and len(d) >= 7:
        return "n:" + (d[-10:] if len(d) >= 10 else d)
    return "t:" + q.lstrip("@")


def mask_norm(n: str) -> str:
    b = n[2:]
    return "••••" if len(b) <= 4 else b[:2] + "•" * max(2, min(8, len(b) - 4)) + b[-2:]


def tok(n: str) -> str:
    return hashlib.sha1(n.encode()).hexdigest()[:8]


def spawn(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _BG.add(t)
    t.add_done_callback(_BG.discard)
    return t


def persist() -> None:
    global DIRTY
    DIRTY = True


def eff(src: dict[str, Any], key: str) -> Any:
    v = src.get(key)
    return S[key] if v is None else v


# --------------------------------------------------------------------------- #
# Storage (JSON files or MongoDB) - state + append-only event store            #
# --------------------------------------------------------------------------- #


class JsonStore:
    kind = "files"

    async def connect(self) -> None: ...

    async def load(self) -> dict[str, Any]:
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return {}
        except Exception:  # noqa: BLE001
            log.exception("cannot read %s", STATE_FILE)
            return {}

    def _save(self, st: dict[str, Any]) -> None:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(st, fh, ensure_ascii=False, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, STATE_FILE)

    async def save_state(self, st: dict[str, Any]) -> None:
        await asyncio.to_thread(self._save, st)

    def _add(self, ev: dict[str, Any]) -> None:
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")

    async def add_event(self, ev: dict[str, Any]) -> None:
        await asyncio.to_thread(self._add, ev)

    def _read(self, uid: int | None, since: float, limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with open(EVENTS_FILE, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if e.get("ts", 0) >= since and (uid is None or e.get("uid") == uid):
                        out.append(e)
        except FileNotFoundError:
            pass
        return out[-limit:]

    async def events(self, uid: int | None = None, since: float = 0.0, limit: int = 20000) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._read, uid, since, limit)

    async def ping(self) -> str:
        return "🟡 Local files (set MONGODB_URI for durable storage)"

    async def close(self) -> None: ...


class MongoStore:
    kind = "mongo"

    def __init__(self) -> None:
        self.client: Any = None
        self.db: Any = None

    async def connect(self) -> None:
        from pymongo import AsyncMongoClient

        self.client = AsyncMongoClient(MONGODB_URI, serverSelectionTimeoutMS=8000)
        await self.client.admin.command("ping")
        self.db = self.client[MONGODB_DB]
        await self.db.events.create_index([("uid", 1), ("ts", -1)])
        if EVENT_DAYS:
            await self.db.events.create_index("exp", expireAfterSeconds=0)

    async def load(self) -> dict[str, Any]:
        d = await self.db.state.find_one({"_id": "state"})
        return json.loads(d["json"]) if d else {}

    async def save_state(self, st: dict[str, Any]) -> None:
        await self.db.state.replace_one({"_id": "state"}, {"_id": "state", "json": json.dumps(st, default=str)}, upsert=True)

    async def add_event(self, ev: dict[str, Any]) -> None:
        doc = dict(ev)
        if EVENT_DAYS:
            doc["exp"] = datetime.now(timezone.utc) + timedelta(days=EVENT_DAYS)
        await self.db.events.insert_one(doc)

    async def events(self, uid: int | None = None, since: float = 0.0, limit: int = 20000) -> list[dict[str, Any]]:
        flt: dict[str, Any] = {"ts": {"$gte": since}}
        if uid is not None:
            flt["uid"] = uid
        docs = await self.db.events.find(flt).sort("ts", -1).limit(limit).to_list(length=None)
        docs.reverse()
        return [{k: v for k, v in d.items() if k not in ("_id", "exp")} for d in docs]

    async def ping(self) -> str:
        t = time.perf_counter()
        try:
            await self.client.admin.command("ping")
        except Exception as exc:  # noqa: BLE001
            return f"🔴 MongoDB unreachable ({type(exc).__name__})"
        return f"🟢 MongoDB · {int((time.perf_counter() - t) * 1000)} ms"

    async def close(self) -> None:
        try:
            await self.client.close()
        except Exception:  # noqa: BLE001
            pass


async def init_storage() -> None:
    global STORE, STATE
    note = ""
    if MONGODB_URI:
        try:
            cand = MongoStore()
            await cand.connect()
            STORE = cand
        except Exception as exc:  # noqa: BLE001
            note = f"MongoDB unavailable ({type(exc).__name__}) - using local files"
            log.error(note)
    if STORE is None:
        STORE = JsonStore()
    data = await STORE.load()
    STATE = fresh_state()
    STATE.update({k: v for k, v in data.items() if k in STATE})
    for k, v in (STATE.get("settings") or {}).items():
        if k in DEFAULTS:
            try:
                S[k] = bool(v) if isinstance(DEFAULTS[k], bool) else type(DEFAULTS[k])(v)
            except (TypeError, ValueError):
                pass
    STATE["settings"] = S
    if LOG_CHANNEL_ID and not STATE.get("log_chat"):
        STATE["log_chat"] = LOG_CHANNEL_ID
    SOURCES.clear()
    for n, c in (STATE.get("sources") or {}).items():
        if isinstance(c, dict) and c.get("url") is not None:
            m = new_source(n, c.get("url", ""))
            m.update({k: v for k, v in c.items() if k in SRC_DEFAULT})
            SOURCES[n] = m
    if "num" not in SOURCES:
        SOURCES["num"] = new_source("num", SEARCH_API_URL)
        SOURCES["num"]["title"] = "Lookup"
        if SEARCH_API_URL:
            SOURCES["num"]["headers"] = dict(API_HEADERS)
    STATE["sources"] = SOURCES
    persist()
    if note:
        STATE["_note"] = note
    log.info("storage=%s | %d sources | %d groups | %d users", STORE.kind, len(SOURCES), len(STATE["groups"]), len(STATE["users"]))


async def flusher() -> None:
    global DIRTY
    while True:
        await asyncio.sleep(4)
        if DIRTY and STORE is not None:
            DIRTY = False
            try:
                await STORE.save_state({k: v for k, v in STATE.items() if not k.startswith("_")})
            except Exception as exc:  # noqa: BLE001
                DIRTY = True
                log.error("state write failed: %s", type(exc).__name__)


# --------------------------------------------------------------------------- #
# Events + log channel                                                         #
# --------------------------------------------------------------------------- #


def tolog(text: str | None = None, doc: tuple[bytes, str] | None = None) -> None:
    if not STATE.get("log_chat"):
        return
    try:
        LOGQ.put_nowait((text, doc))
    except asyncio.QueueFull:
        pass


async def log_worker(bot) -> None:
    while True:
        text, doc = await LOGQ.get()
        chat = STATE.get("log_chat")
        if not chat:
            continue
        try:
            if doc:
                await bot.send_document(chat, InputFile(io.BytesIO(doc[0]), filename=doc[1]),
                                        caption=(text or "")[:1000] or None, parse_mode=ParseMode.HTML)
            else:
                await bot.send_message(chat, (text or "")[:4000], parse_mode=ParseMode.HTML,
                                       link_preview_options=NO_PREVIEW)
        except RetryAfter as exc:
            await asyncio.sleep(exc.retry_after + 1)
            LOGQ.put_nowait((text, doc))
        except TelegramError as exc:
            log.warning("log channel send failed: %s", exc)
        await asyncio.sleep(0.4)


def emit(ev_type: str, user=None, chat=None, card: str | None = None, doc: tuple[bytes, str] | None = None, **fields: Any) -> None:
    """Persist an event AND post a card in the log channel."""
    ev: dict[str, Any] = {"ts": time.time(), "type": ev_type, "uid": getattr(user, "id", fields.pop("uid", 0)),
                          "name": getattr(user, "full_name", fields.pop("name", "")) or "",
                          "username": getattr(user, "username", "") or ""}
    if chat is not None:
        ev["chat"] = chat.id
        ev["chat_title"] = "DM" if chat.type == ChatType.PRIVATE else (chat.title or str(chat.id))
    ev.update(fields)

    async def _w() -> None:
        try:
            await STORE.add_event(ev)
        except Exception as exc:  # noqa: BLE001
            log.error("event write failed: %s", type(exc).__name__)

    try:
        spawn(_w())
    except RuntimeError:
        pass
    if card:
        tolog(card, doc)


def where(chat) -> str:
    if chat is None:
        return "?"
    return "DM" if chat.type == ChatType.PRIVATE else f"{chat.title or ''} ({chat.id})"


def touch_user(user, chat) -> bool:
    """Create/update the user's profile. Returns True the first time we ever see them."""
    key = str(user.id)
    u = STATE["users"].get(key)
    new = u is None
    if new:
        u = {"first": time.time(), "count": 0, "hits": 0, "cmds": {}, "chats": {}}
    u.update(name=user.full_name or "", username=user.username or "", last=time.time(),
             lang=getattr(user, "language_code", "") or "", premium=bool(getattr(user, "is_premium", False)))
    if chat is not None and len(u["chats"]) < 30:
        u["chats"][str(chat.id)] = "DM" if chat.type == ChatType.PRIVATE else (chat.title or str(chat.id))
    STATE["users"][key] = u
    persist()
    return new


# --------------------------------------------------------------------------- #
# Telegram plumbing                                                            #
# --------------------------------------------------------------------------- #


async def _del(bot, chat_id: int, mid: int, delay: float) -> None:
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id, mid)
    except TelegramError:
        pass


def autodelete(bot, *msgs, delay: float | None = None) -> None:
    delay = S["auto_delete"] if delay is None else delay
    if not delay:
        return
    for m in msgs:
        if m is not None:
            spawn(_del(bot, m.chat_id, m.message_id, delay))


async def _forget(key: str, delay: float) -> None:
    await asyncio.sleep(delay)
    CACHE.pop(key, None)
    META.pop(key, None)


def delete_note(d: float | None = None) -> str:
    d = S["auto_delete"] if d is None else d
    return f"\n⏳ <i>Self-destructs in {fmt_dur(d)}</i>" if d else ""


async def notify_admins(bot, text: str, markup: InlineKeyboardMarkup | None = None) -> None:
    for a in ADMIN_IDS:
        try:
            await bot.send_message(a, text, parse_mode=ParseMode.HTML, reply_markup=markup,
                                   link_preview_options=NO_PREVIEW)
        except TelegramError:
            pass


async def bot_status_in(bot, chat_id: int) -> str | None:
    try:
        m = await bot.get_chat_member(chat_id, bot.id)
    except TelegramError:
        return None
    return None if m.status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED) else m.status


VALID_STYLES = {"primary", "success", "danger"}


def btn(text: str, data: str, style: str | None = "primary", icon: str | None = None) -> InlineKeyboardButton:
    extra: dict[str, Any] = {}
    if style in VALID_STYLES:
        extra["style"] = style
    if icon:
        extra["icon_custom_emoji_id"] = icon
    try:
        return InlineKeyboardButton(text, callback_data=data, **extra)
    except TypeError:
        return InlineKeyboardButton(text, callback_data=data)


def link_btn(text: str, url: str, style: str | None = "primary") -> InlineKeyboardButton:
    try:
        return InlineKeyboardButton(text, url=url, **({"style": style} if style in VALID_STYLES else {}))
    except TypeError:
        return InlineKeyboardButton(text, url=url)


def kb(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([r for r in rows if r])


async def reply_to(bot, chat_id: int, text: str, mid: int | None = None, markup=None, delete_after: float = 0):
    try:
        kw: dict[str, Any] = {}
        if mid:
            kw["reply_parameters"] = ReplyParameters(message_id=mid, allow_sending_without_reply=True)
        sent = await bot.send_message(chat_id, text, parse_mode=ParseMode.HTML, reply_markup=markup,
                                      link_preview_options=NO_PREVIEW, **kw)
        if delete_after:
            autodelete(bot, sent, delay=delete_after)
        return sent
    except TelegramError:
        return None


# --------------------------------------------------------------------------- #
# Moderation: warn / ban with a reply to the user EVERY time                   #
# --------------------------------------------------------------------------- #

DIV = "━━━━━━━━━━━━━━━━━━━━"


def is_banned(uid: int) -> bool:
    b = STATE["bans"].get(str(uid))
    if not b:
        return False
    if b.get("until") and time.time() >= b["until"]:
        STATE["bans"].pop(str(uid), None)
        persist()
        return False
    return True


def ban_notice(uid: int) -> str:
    b = STATE["bans"].get(str(uid)) or {}
    when = f"⏱ {fmt_left(b['until'] - time.time())} remaining" if b.get("until") else "♾ permanent"
    return (f"🚫 <b>YOU ARE BANNED</b>\n{DIV}\n<blockquote>📝 <b>Reason</b> ▸ {esc(b.get('reason') or 'policy violation')}\n"
            f"{when}</blockquote>\n<i>You cannot use this bot until the ban ends. Contact an admin to appeal.</i>")


async def apply_ban(bot, uid: int, name: str, chat_id: int | None, reply_id: int | None, minutes: int,
                    reason: str, by: int = 0, username: str = "") -> None:
    STATE["bans"][str(uid)] = {"until": time.time() + minutes * 60 if minutes else 0.0, "reason": reason[:150],
                               "by": by, "ts": time.time(), "name": name}
    STRIKES.pop(uid, None)
    persist()
    text = ban_notice(uid)
    if chat_id:
        await reply_to(bot, chat_id, f"{mention(uid, name)}\n{text}", reply_id, delete_after=90)
    try:  # also DM (works if the user started the bot before)
        await bot.send_message(uid, text, parse_mode=ParseMode.HTML)
    except TelegramError:
        pass
    emit("ban", uid=uid, name=name, username=username, reason=reason, minutes=minutes, by=by,
         card=f"🚫 <b>BANNED</b>\n<blockquote>👤 {utag(uid, name, username)}\n⏱ {fmt_minutes(minutes)}\n📝 {esc(reason)}\n"
              f"{'🤖 automatic' if not by else '👮 by ' + str(by)}</blockquote>")


async def warn_user(bot, user, chat, msg, reason: str, by: int = 0) -> None:
    uid = user.id
    if is_admin(uid):
        return
    w = STATE["warns"].setdefault(str(uid), {"count": 0, "reasons": []})
    w["count"] += 1
    w["reasons"] = (w["reasons"] + [f"{stamp()} · {reason}"])[-10:]
    limit = int(S["warn_limit"])
    if w["count"] >= limit:
        w["count"] = 0
        await apply_ban(bot, uid, user.full_name, chat.id if chat else None, msg.message_id if msg else None,
                        int(S["ban_minutes"]), f"{limit} warnings · last: {reason}", by, user.username or "")
        return
    persist()
    left = limit - w["count"]
    text = (f"{mention(uid, user.full_name)}\n⚠️ <b>WARNING {w['count']}/{limit}</b>\n{DIV}\n"
            f"<blockquote>📝 <b>Reason</b> ▸ {esc(reason)}\n🚨 {left} more warning(s) = "
            f"{fmt_minutes(int(S['ban_minutes']))} ban</blockquote>")
    if chat:
        await reply_to(bot, chat.id, text, msg.message_id if msg else None, delete_after=90)
    try:
        await bot.send_message(uid, text, parse_mode=ParseMode.HTML)
    except TelegramError:
        pass
    emit("warn", user, chat, reason=reason, count=w["count"], by=by,
         card=f"⚠️ <b>WARNING {w['count']}/{limit}</b>\n<blockquote>👤 {utag(uid, user.full_name, user.username or '')}\n"
              f"📍 {esc(where(chat))}\n📝 {esc(reason)}\n{'🤖 automatic' if not by else '👮 by ' + str(by)}</blockquote>")


async def strike(bot, user, chat, msg, why: str, weight: int = 1) -> None:
    if user is None or not S["abuse_guard"] or is_admin(user.id):
        return
    dq = STRIKES.setdefault(user.id, deque(maxlen=200))
    now = time.time()
    for _ in range(weight):
        dq.append(now)
    while dq and now - dq[0] > 600:
        dq.popleft()
    if len(dq) >= int(S["strike_limit"]):
        dq.clear()
        await warn_user(bot, user, chat, msg, why)


# --------------------------------------------------------------------------- #
# Access gate                                                                  #
# --------------------------------------------------------------------------- #


async def _stop(update: Update) -> None:
    if update.callback_query:
        try:
            await update.callback_query.answer()
        except TelegramError:
            pass
    raise ApplicationHandlerStop


def throttle(kind: str, uid: int, secs: float) -> bool:
    now = time.time()
    if now - NOTICE.get((kind, uid), 0) < secs:
        return False
    NOTICE[(kind, uid)] = now
    return True


async def access_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.my_chat_member or update.chat_member:
        return
    chat, user, msg = update.effective_chat, update.effective_user, update.effective_message
    if chat is None or user is None:
        raise ApplicationHandlerStop
    bot = context.bot

    if chat.type == ChatType.PRIVATE:
        if is_admin(user.id):
            return
        new = touch_user(user, chat)
        if throttle("deny", user.id, 60):
            emit("dm_denied", user, chat, text=(msg.text or "")[:100] if msg else "",
                 card=f"🔒 <b>{'NEW ' if new else ''}STRANGER IN DM</b> (denied)\n<blockquote>👤 {utag(user.id, user.full_name, user.username or '')}\n"
                      f"💬 {esc(shorten((msg.text or '') if msg else '', 80))}</blockquote>")
            if msg:
                try:
                    await msg.reply_text("🔒 This is a private bot.")
                except TelegramError:
                    pass
        await _stop(update)

    if chat.type in GROUP_TYPES:
        if msg and msg.migrate_to_chat_id and str(chat.id) in STATE["groups"]:
            STATE["groups"][str(msg.migrate_to_chat_id)] = STATE["groups"].pop(str(chat.id))
            persist()
            raise ApplicationHandlerStop
        if str(chat.id) in STATE["groups"]:
            if is_admin(user.id):
                return
            if is_banned(user.id):
                if msg and (msg.text or "").startswith("/") and throttle("ban", user.id, 20):
                    await reply_to(bot, chat.id, f"{mention(user.id, user.full_name)}\n{ban_notice(user.id)}",
                                   msg.message_id, delete_after=30)
                await _stop(update)
            if msg and msg.new_chat_members:
                return
            if not S["members_can_search"]:
                await _stop(update)
            if touch_user(user, chat):
                emit("new_user", user, chat,
                     card=f"🆕 <b>NEW USER</b>\n<blockquote>👤 {utag(user.id, user.full_name, user.username or '')}\n"
                          f"📍 {esc(where(chat))}\n🌐 lang {esc(getattr(user, 'language_code', '') or '?')}</blockquote>")
            return
        text = (msg.text or "") if msg else ""
        if is_admin(user.id) and re.match(r"^/allowgroup(@\w+)?(\s|$)", text):
            return
        await _stop(update)
    raise ApplicationHandlerStop


# --------------------------------------------------------------------------- #
# Formatting primitives                                                        #
# --------------------------------------------------------------------------- #

CARD_SEP = "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈"
MARKERS = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")
ICON_RULES = [
    ({"name", "fullname", "full", "user", "username", "owner", "person"}, "👤"),
    ({"phone", "mobile", "number", "mob", "msisdn", "contact", "alt", "alternate"}, "📱"),
    ({"email", "mail"}, "📧"),
    ({"address", "addr", "location", "city", "state", "country", "pincode", "zip", "district", "area", "region"}, "📍"),
    ({"father", "mother", "spouse", "parent", "relative"}, "👪"),
    ({"id", "uid", "aadhaar", "aadhar", "pan"}, "🆔"),
    ({"ip", "domain", "host", "url", "link", "site", "website"}, "🌐"),
    ({"date", "dob", "time", "created", "updated", "age", "year"}, "🗓"),
    ({"circle", "operator", "carrier", "sim", "network", "provider", "type"}, "📡"),
    ({"gender", "sex"}, "⚧"),
    ({"bank", "ifsc", "account", "card", "upi"}, "🏦"),
    ({"status", "active", "verified", "valid"}, "✅"),
]
TITLE_KEYS = ("title", "name", "full_name", "display_name", "username", "handle", "email", "phone", "number",
              "mobile", "domain", "ip", "address", "label", "subject")
BODY_KEYS = ("description", "summary", "snippet", "text", "content", "body", "about", "bio", "notes", "detail")
URL_KEYS = ("url", "link", "href", "permalink", "profile_url", "web_url", "source_url")
ARRAY_KEYS = ("results", "result", "items", "data", "hits", "records", "list", "entries", "rows", "matches",
              "accounts", "profiles", "leaks", "values", "response", "payload")
SENSITIVE = {"password", "passwd", "pass", "hash", "token", "secret", "otp", "pin", "cvv"}
NOISE = {"_id", "__typename", "_index", "_score", "_type"}


def key_icon(label: str, overrides: dict[str, str] | None = None) -> str:
    low = label.lower()
    for kw, icon in (overrides or {}).items():
        if kw in low:
            return icon
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", label)
    for t in reversed([x for x in re.split(r"[^a-z0-9]+", spaced.lower()) if x]):
        for keys, icon in ICON_RULES:
            if t in keys:
                return icon
    return "▫️"


def humanize(key: Any) -> str:
    k = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    k = re.sub(r"[_\-.]+", " ", k).strip()
    return k[:1].upper() + k[1:]


def scalar(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool)) or v is None


def fmt_scalar(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "✅ Yes" if v else "❌ No"
    return shorten(re.sub(r"<[^>]+>", "", str(v)), 220)


def mask_val(key: str, value: str) -> str:
    if not S["mask"]:
        return value
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", str(key))
    if set(re.split(r"[^a-z0-9]+", spaced.lower())) & SENSITIVE and len(value) > 4:
        return value[:2] + "•" * min(10, len(value) - 4) + value[-2:]
    return value


def masked_copy(o: Any, key: str = "", hide: list[str] | None = None) -> Any:
    hide = hide or []
    if isinstance(o, dict):
        return {k: masked_copy(v, str(k), hide) for k, v in o.items() if not any(h in str(k).lower() for h in hide)}
    if isinstance(o, list):
        return [masked_copy(v, key, hide) for v in o]
    return mask_val(key, o) if isinstance(o, str) else o


def hidden(label: str, hide: list[str]) -> bool:
    return any(h in label.lower() for h in hide)


def flatten(o: Any, prefix: str = "", out: list | None = None, depth: int = 0) -> list[tuple[str, Any]]:
    out = [] if out is None else out
    if depth > 3:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            if str(k).lower() in NOISE:
                continue
            label = f"{prefix}{humanize(k)}"
            if scalar(v):
                if v not in (None, ""):
                    out.append((label, v))
            elif isinstance(v, list) and all(scalar(x) for x in v):
                if v:
                    out.append((label, ", ".join(fmt_scalar(x) for x in v[:8])))
            else:
                flatten(v, f"{label} › ", out, depth + 1)
    elif isinstance(o, list):
        for i, v in enumerate(o[:8]):
            flatten(v, f"{prefix}{i + 1} › ", out, depth + 1)
    elif o not in (None, ""):
        out.append((prefix.rstrip(" ›") or "Value", o))
    return out


def pick(obj: dict[str, Any], keys) -> tuple[str | None, Any]:
    low = {str(k).lower(): k for k in obj}
    for c in keys:
        r = low.get(c)
        if r is not None and obj[r] not in (None, "", [], {}):
            return r, obj[r]
    return None, None


def item_title(item: Any, i: int) -> str:
    if not isinstance(item, dict):
        return shorten(item, 60) or f"Record {i + 1}"
    _, v = pick(item, TITLE_KEYS)
    if v is not None and scalar(v):
        return shorten(v, 60)
    for k, v in item.items():
        if isinstance(v, str) and 1 < len(v) < 120 and str(k).lower() not in NOISE:
            return shorten(v, 60)
    return f"Record {i + 1}"


def item_url(item: Any) -> str | None:
    if isinstance(item, dict):
        _, v = pick(item, URL_KEYS)
        if isinstance(v, str) and v.startswith(("http://", "https://")):
            return v
    return None


def tree(lines: list[str]) -> str:
    return "\n".join(f"{'┗' if i == len(lines) - 1 else '┣'} {l}" for i, l in enumerate(lines))


def table(pairs: list[tuple[str, str]]) -> str:
    return tree([f"<b>{esc(k)}</b> ▸ <code>{esc(v)}</code>" for k, v in pairs])


def fields_block(pairs: list[tuple[str, str]], more: int = 0, icons: dict[str, str] | None = None) -> str:
    lines = [f"{key_icon(k, icons)} <b>{esc(k)}</b> ▸ <code>{esc(v)}</code>" for k, v in pairs]
    if more > 0:
        lines.append(f"➕ <i>{more} more field{'s' if more != 1 else ''} · open the record</i>")
    return tree(lines)


def quote_box(rows: list[str]) -> str:
    return "<blockquote>" + "\n".join(rows) + "</blockquote>"


def json_block(obj: Any, limit: int = 1800, hide: list[str] | None = None) -> str:
    s = json.dumps(masked_copy(obj, hide=hide), indent=2, ensure_ascii=False, default=str)
    if len(s) > limit:
        s = s[:limit] + "\n…"
    return f'<pre><code class="language-json">{esc(s)}</code></pre>'


def emoji_html(p: dict[str, Any]) -> str:
    if p.get("emoji_id"):
        return f'<tg-emoji emoji-id="{esc(p["emoji_id"])}">{esc(p.get("emoji") or "🛰")}</tg-emoji>'
    return esc(p.get("emoji") or "🛰")


def style_of(p: dict[str, Any]) -> str | None:
    s = p.get("style", "primary")
    return None if s == "default" else s


# --------------------------------------------------------------------------- #
# API layer + response mapping                                                 #
# --------------------------------------------------------------------------- #


class ApiError(Exception): ...
class NotConfigured(Exception): ...


@dataclass
class Result:
    query: str
    items: list[Any]
    meta: dict[str, Any]
    raw: Any
    ms: int
    src: str
    born: float = field(default_factory=time.time)


def build_url(query: str, base: str) -> str:
    if not base:
        raise NotConfigured
    q = quote(query, safe="")
    if "{q}" in base:
        return base.replace("{q}", q)
    if base.endswith(("q=", "query=", "search=", "term=", "s=", "number=", "num=")):
        return base + q
    return f"{base}{'&' if '?' in base else '?'}q={q}"


async def get_session() -> aiohttp.ClientSession:
    global _SESSION
    if _SESSION is None or _SESSION.closed:
        _SESSION = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=8),
            connector=aiohttp.TCPConnector(limit=100, limit_per_host=30, ttl_dns_cache=300),
            headers={"Accept": "application/json", "User-Agent": "lookup-bot/5.0"})
    return _SESSION


async def fetch_json(url: str, headers: dict[str, str], name: str) -> Any:
    try:
        s = await get_session()
        async with s.get(url, headers=headers) as r:
            body = await r.text()
            if r.status == 404:
                return {}
            if r.status >= 400:
                log.error("source %s -> HTTP %s: %s", name, r.status, body[:200])
                raise ApiError("The data source rejected that lookup. Try again shortly.")
            try:
                return json.loads(body)
            except ValueError:
                return {"response": shorten(body, 2000)}
    except asyncio.TimeoutError as exc:
        raise ApiError("The source timed out. Please try again.") from exc
    except aiohttp.ClientError as exc:
        log.error("source %s unreachable: %s", name, type(exc).__name__)
        raise ApiError("The data source is unreachable right now.") from exc


def apply_transform(payload: Any, tf: dict[str, Any]) -> Any:
    """Remove branding / rename keys / replace text anywhere in the API response."""
    if not tf:
        return payload
    remove = {str(k).lower() for k in tf.get("remove_keys", [])}
    rename = {str(k).lower(): str(v) for k, v in (tf.get("rename") or {}).items()}
    repl = [(str(a), str(b)) for a, b in (tf.get("replace") or {}).items()]
    rx = []
    for a, b in (tf.get("regex") or {}).items():
        try:
            rx.append((re.compile(a), str(b)))
        except re.error:
            pass

    def clean(s: str) -> str:
        for a, b in repl:
            s = re.sub(re.escape(a), b.replace("\\", "\\\\"), s, flags=re.I)
        for pat, b in rx:
            s = pat.sub(b, s)
        return s.strip()

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                lk = str(k).lower()
                if lk in remove:
                    continue
                out[rename.get(lk, k)] = walk(v)
            return out
        if isinstance(o, list):
            return [walk(x) for x in o]
        return clean(o) if isinstance(o, str) else o

    return walk(payload)


def get_path(o: Any, path: str) -> Any:
    for part in [p for p in path.split(".") if p]:
        if isinstance(o, dict):
            o = next((v for k, v in o.items() if str(k).lower() == part.lower()), None)
        elif isinstance(o, list) and part.isdigit() and int(part) < len(o):
            o = o[int(part)]
        else:
            return None
    return o


def extract_items(payload: Any, depth: int = 0) -> tuple[list[Any], dict[str, Any]]:
    if isinstance(payload, list):
        return payload, {}
    if not isinstance(payload, dict) or depth > 3:
        return ([payload] if payload not in (None, "") else []), {}
    meta = {k: v for k, v in payload.items() if scalar(v) and v not in (None, "")}
    for cand in ARRAY_KEYS:
        for rk in payload:
            if str(rk).lower() == cand:
                v = payload[rk]
                if isinstance(v, list):
                    return v, meta
                if isinstance(v, dict):
                    n, nm = extract_items(v, depth + 1)
                    if n:
                        return n, {**meta, **nm}
    for v in payload.values():
        if isinstance(v, list) and v:
            return v, meta
    for v in payload.values():
        if isinstance(v, dict):
            n, nm = extract_items(v, depth + 1)
            if n:
                return n, {**meta, **nm}
    return ([payload] if payload else []), meta


async def run_search(query: str, name: str) -> Result:
    src = SOURCES.get(name)
    if not src or not src.get("url"):
        raise NotConfigured
    headers = {str(k): str(v) for k, v in (src.get("headers") or {}).items()}
    t0 = time.perf_counter()
    try:
        payload = await fetch_json(build_url(query, src["url"]), headers, name)
    except ApiError:
        if not src.get("backup_url"):
            raise
        log.warning("primary failed for /%s - using backup", name)
        payload = await fetch_json(build_url(query, src["backup_url"]), headers, name)
    ms = int((time.perf_counter() - t0) * 1000)
    tf = src.get("transform") or {}
    payload = apply_transform(payload, tf)
    items, meta = None, {}
    if tf.get("rows_path"):
        sel = get_path(payload, str(tf["rows_path"]))
        if isinstance(sel, list):
            items = sel
        elif isinstance(sel, dict):
            items = [sel]
    if items is None:
        items, meta = extract_items(payload)
    meta.pop("q", None)
    return Result(query=query, items=items, meta=meta, raw=payload, ms=ms, src=name)


async def search_cached(query: str, name: str) -> Result:
    key = f"{name}|{norm_query(query)}"
    hit = QCACHE.get(key)
    if QUERY_TTL > 0 and hit and time.time() - hit.born < QUERY_TTL:
        return hit
    task = INFLIGHT.get(key)
    if task is not None:
        return await asyncio.shield(task)
    task = asyncio.create_task(run_search(query, name))
    INFLIGHT[key] = task
    try:
        res = await task
    finally:
        INFLIGHT.pop(key, None)
    QCACHE[key] = res
    if len(QCACHE) > 500:
        for k in sorted(QCACHE, key=lambda x: QCACHE[x].born)[:100]:
            QCACHE.pop(k, None)
    return res


# --------------------------------------------------------------------------- #
# Result renderers                                                             #
# --------------------------------------------------------------------------- #


def profile(name: str | None) -> dict[str, Any]:
    return SOURCES.get(name or "") or SRC_DEFAULT


def render_card(item: Any, index: int, max_pairs: int, body_limit: int, p: dict[str, Any]) -> str:
    hide, icons = p.get("hide") or [], p.get("icons") or {}
    head = f"{MARKERS[index % len(MARKERS)]} <b>{esc(item_title(item, index))}</b>"
    if not isinstance(item, dict):
        return head
    used: set[str] = set()
    tk, _ = pick(item, TITLE_KEYS)
    if tk:
        used.add(tk)
    out = []
    bk, body = pick(item, BODY_KEYS)
    if bk and isinstance(body, str):
        used.add(bk)
        if body_limit:
            out.append(f"💬 <i>{esc(shorten(body, body_limit))}</i>")
    pairs = [(k, v) for k, v in flatten({k: v for k, v in item.items() if k not in used}) if not hidden(k, hide)]
    shown = [(k, mask_val(k, fmt_scalar(v))) for k, v in pairs[:max_pairs]] if max_pairs else []
    more = max(0, len(pairs) - len(shown)) if max_pairs else 0
    total = len([1 for k, _ in flatten(item) if not hidden(k, hide)])
    blk = fields_block(shown, more, icons)
    return "\n".join([head + (f"  <i>· {total} fields</i>" if total else "")] + out + ([blk] if blk else []))


def header_for(key: str, res: Result, page: int, pages: int, title_suffix: str = "COMPLETE") -> str:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    box = [f"🎯 <b>Target</b> ▸ <code>{esc(shorten(res.query, 64))}</code>",
           f"📦 <b>Records</b> ▸ <code>{len(res.items)}</code>   📄 <b>Page</b> ▸ <code>{page + 1}/{pages}</code>",
           f"⚡ <b>Speed</b> ▸ <code>{res.ms} ms</code>   🕒 <code>{clock()[:5]} UTC</code>"]
    if meta.get("by"):
        box.append(f"🙋 <b>Requested by</b> ▸ {esc(meta['by'])}")
    return f"{emoji_html(p)} <b>{esc(str(p['title']).upper())} {title_suffix}</b> ✅\n{quote_box(box)}\n"


def footer_for(p: dict[str, Any]) -> str:
    note = f"\n📝 <i>{esc(p['footer'])}</i>" if p.get("footer") else ""
    return f"\n\n{DIV}\n🔐 <i>Sensitive fields masked · tap any value to copy</i>{note}{delete_note(eff(p, 'auto_delete'))}"


def nav_row(code: str, key: str, page: int, pages: int) -> list[InlineKeyboardButton]:
    if pages <= 1:
        return []
    row = []
    if page > 0:
        row += [btn("⏮", f"{code}|{key}|0"), btn("◀️", f"{code}|{key}|{page - 1}")]
    row.append(btn(f"📄 {page + 1}/{pages}", "noop", None))
    if page < pages - 1:
        row += [btn("▶️", f"{code}|{key}|{page + 1}"), btn("⏭", f"{code}|{key}|{pages - 1}")]
    return row


def render_results(key: str, res: Result, page: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    total = len(res.items)
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    start = page * PAGE_SIZE
    chunk = res.items[start: start + PAGE_SIZE]
    head = header_for(key, res, page, pages)
    text = head
    for budget in (5, 4, 3, 2, 1, 0):
        body = f"\n\n{CARD_SEP}\n\n".join(render_card(it, start + i, budget, 150, p) for i, it in enumerate(chunk))
        text = head + "\n" + (body or "<i>Empty page.</i>") + footer_for(p)
        if len(text) <= MAX_MESSAGE:
            break
    opens = [btn(f"{MARKERS[(start + i) % len(MARKERS)]} {shorten(item_title(it, start + i), 14)}",
                 f"d|{key}|{start + i}", style_of(p)) for i, it in enumerate(chunk)]
    rows = [opens[i: i + 2] for i in range(0, len(opens), 2)]
    rows.append(nav_row("p", key, page, pages))
    rows.append([btn("🧾 Raw JSON", f"j|{key}|{page}", "primary"), btn("📥 Export", f"x|{key}|0", "success")])
    tail = [btn("🗑 Close", f"close|{key}|0", "danger")]
    if not meta.get("group"):
        tail.insert(0, btn("🏠 Menu", "menu|0|0"))
    rows.append(tail)
    return text, kb(rows)


def render_raw_page(key: str, res: Result, page: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    pages = max(1, (len(res.items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    rows_data = res.items[page * PAGE_SIZE: (page + 1) * PAGE_SIZE]
    head = header_for(key, res, page, pages, "· RAW JSON")
    tail = footer_for(p)
    room = MAX_MESSAGE - len(head) - len(tail) - 120
    body = "<blockquote expandable>" + json_block(rows_data, max(300, room - 80), p.get("hide")) + "</blockquote>"
    rows = [nav_row("j", key, page, pages),
            [btn("🗂 Cards view", f"p|{key}|{page}", "primary"), btn("📥 Export", f"x|{key}|0", "success")],
            [btn("🗑 Close", f"close|{key}|0", "danger")]]
    return head + body + tail, kb(rows)


def render_detail(key: str, res: Result, index: int) -> tuple[str, InlineKeyboardMarkup]:
    meta = META.get(key, {})
    p = profile(meta.get("src"))
    hide, icons = p.get("hide") or [], p.get("icons") or {}
    index = max(0, min(index, len(res.items) - 1))
    item = res.items[index]
    pairs = [(k, mask_val(k, fmt_scalar(v))) for k, v in flatten(item if isinstance(item, dict) else {"value": item})
             if not hidden(k, hide)]
    head = (f"🗂 <b>RECORD DETAIL</b> ✨ · {emoji_html(p)} <b>{esc(p['title'])}</b>\n"
            + quote_box([f"🎯 <b>Target</b> ▸ <code>{esc(shorten(res.query, 60))}</code>",
                         f"📌 <b>Record</b> ▸ <code>{index + 1}/{len(res.items)}</code>   🧩 <b>Fields</b> ▸ <code>{len(pairs)}</code>"])
            + f"\n{MARKERS[index % len(MARKERS)]} <b>{esc(item_title(item, index))}</b>\n")
    text = head
    for n_pairs, n_json in ((40, 1800), (30, 1200), (20, 700), (12, 400), (6, 0)):
        shown = pairs[:n_pairs]
        parts = [head, f"\n📋 <b>ALL FIELDS</b>\n{fields_block(shown, len(pairs) - len(shown), icons) or '<i>-</i>'}"]
        if n_json:
            parts.append("\n\n🧾 <b>RAW JSON ROW</b> <i>(tap to expand)</i>\n<blockquote expandable>"
                         + json_block(item, n_json, hide) + "</blockquote>")
        parts.append(footer_for(p))
        text = "".join(parts)
        if len(text) <= MAX_MESSAGE:
            break
    page = index // PAGE_SIZE
    nav = []
    if index > 0:
        nav.append(btn("⬅️ Prev", f"d|{key}|{index - 1}"))
    nav.append(btn(f"📌 {index + 1}/{len(res.items)}", "noop", None))
    if index < len(res.items) - 1:
        nav.append(btn("Next ➡️", f"d|{key}|{index + 1}"))
    acts = [btn("💾 Save JSON", f"f|{key}|{index}", "success")]
    if item_url(item):
        acts.insert(0, link_btn("🔗 Open source", item_url(item)))
    return text, kb([nav, acts, [btn("◀️ Back to results", f"p|{key}|{page}")]])


# --------------------------------------------------------------------------- #
# Welcome / help / menu                                                        #
# --------------------------------------------------------------------------- #


def command_lines(for_group: bool = True) -> str:
    rows = []
    for n, s in SOURCES.items():
        if s.get("enabled") and s.get("url"):
            rows.append(f"{emoji_html(s)} <code>/{n} &lt;query&gt;</code> ▸ {esc(s.get('title') or n)}"
                        + (" 🛠" if s.get("maintenance") else ""))
    return tree(rows) if rows else "<i>No commands configured yet.</i>"


def build_welcome(names: str, chat, bot_username: str) -> str:
    custom = (S.get("welcome_text") or "").strip()
    cmds = command_lines()
    if custom:
        return (custom.replace("{name}", names).replace("{group}", esc(chat.title or "")).replace("{bot}", f"@{bot_username}")
                .replace("{commands}", cmds))
    return (
        f"👋 <b>Welcome, {names}!</b>\n"
        + quote_box([f"🛰 <b>{esc(BOT_NAME)}</b> is active in <b>{esc(chat.title or 'this group')}</b>",
                     "Fast, private, professional lookups - right here."])
        + f"\n\n⌨️ <b>COMMANDS</b>\n{cmds}\n\n"
        "📖 <b>HOW TO USE</b>\n"
        + tree(["1️⃣ Send a command followed by your query",
                "2️⃣ Tap a record button for the full detail view",
                "3️⃣ Use 🧾 Raw JSON or 📥 Export when you need data"])
        + f"\n\n🧹 <i>Results self-destruct after {fmt_dur(S['auto_delete'])}.</i>\n"
        + "<blockquote expandable><b>Rules</b>\n• Research, verification and security work only\n"
          "• No harassment, stalking or anything unlawful\n• Spam = warning, repeated spam = ban\n"
          "• Activity is logged by the operator for abuse prevention\n"
          "• Want your own number/username protected? Use /optout</blockquote>")


def welcome_markup(bot_username: str) -> InlineKeyboardMarkup:
    return kb([[link_btn("🤖 Open bot", f"https://t.me/{bot_username}", "primary"), btn("📖 Full help", "help|0|0", "success")]])


async def on_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg, chat = update.effective_message, update.effective_chat
    if not msg or str(chat.id) not in STATE["groups"]:
        return
    members = [m for m in (msg.new_chat_members or []) if not m.is_bot]
    for m in members:
        touch_user(m, chat)
        emit("join", m, chat, card=f"➕ <b>MEMBER JOINED</b>\n<blockquote>👤 {utag(m.id, m.full_name, m.username or '')}\n"
                                    f"📍 {esc(where(chat))}</blockquote>")
    if not S["welcome"] or not members:
        return
    names = ", ".join(mention(m.id, m.full_name) for m in members[:5]) + (f" +{len(members) - 5}" if len(members) > 5 else "")
    try:
        text = build_welcome(names, chat, context.bot.username)
        sent = await msg.reply_html(text, reply_markup=welcome_markup(context.bot.username), link_preview_options=NO_PREVIEW)
    except TelegramError:
        S_text = S["welcome_text"]
        S["welcome_text"] = ""
        try:
            sent = await msg.reply_html(build_welcome(names, chat, context.bot.username),
                                        reply_markup=welcome_markup(context.bot.username), link_preview_options=NO_PREVIEW)
        finally:
            S["welcome_text"] = S_text
    autodelete(context.bot, sent, delay=S["welcome_delete"])


def render_help(admin: bool) -> str:
    text = (f"❓ <b>HELP</b>\n{DIV}\n\n🔎 <b>Searching</b>\n"
            + tree(["Groups: <code>/command &lt;query&gt;</code> or reply to a message with a command",
                    "Private (admins): just send the query"])
            + f"\n\n🧩 <b>Commands</b>\n{command_lines()}\n\n📖 <b>Reading results</b>\n"
            + tree(["Name buttons open a record in full", "🧾 shows the raw JSON rows", "📥 exports a JSON file",
                    f"🧹 results vanish after {fmt_dur(S['auto_delete'])}"])
            + "\n\n🛡 <code>/optout &lt;number/username&gt;</code> asks for your data to be protected.")
    if admin:
        text += ("\n\n🛠 <b>Admin</b>\n<code>/admin /cmds /addcmd /delcmd /setmap /connect /groups /allowgroup /denygroup</code>\n"
                 "<code>/ban /unban /warn /unwarn /banned /block /unblock /setlimit /userinfo /exportlog</code>\n"
                 "<code>/setlog /setwelcome /broadcast</code>")
    return text


def render_menu(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    logo = f'<tg-emoji emoji-id="{EMOJI_SEARCH}">🕵️</tg-emoji>' if EMOJI_SEARCH else "🕵️"
    text = (f"{logo} <b>{esc(BOT_NAME)}</b>\n<i>Fast, private, professional lookups.</i>\n{DIV}\n"
            f"🧩 <b>Commands</b>\n{command_lines()}\n\n"
            f"🧹 Auto-delete {fmt_dur(S['auto_delete'])}" + (" · 🔒 Lockdown" if S["lockdown"] else "") + "\n"
            "🔎 Send a query to start.")
    rows = [[btn("❓ Help", "help|0|0"), btn("📊 My usage", "usage|0|0")]]
    if is_admin(uid):
        rows.append([btn("🛠 Admin control center", "adm|home|0", "danger")])
    return text, kb(rows)


# --------------------------------------------------------------------------- #
# Core: lookup                                                                 #
# --------------------------------------------------------------------------- #


def user_limit(uid: int, src: dict[str, Any]) -> int:
    if str(uid) in STATE["limits"]:
        return int(STATE["limits"][str(uid)])
    return int(eff(src, "daily_limit"))


def quota(uid: int, name: str, src: dict[str, Any]) -> tuple[str, str] | None:
    now = time.time()
    cd = float(eff(src, "cooldown"))
    last = LAST.get((uid, name), 0.0)
    if now - last < cd and not is_admin(uid):
        return "cool", f"⏳ Easy there - try /{name} again in {max(1, round(cd - (now - last)))}s."
    lim = user_limit(uid, src)
    if lim and not is_admin(uid):
        day, cnt = USAGE.get((uid, name), (today(), 0))
        if day != today():
            day, cnt = today(), 0
        if cnt >= lim:
            return "limit", f"🚦 Daily limit reached for /{name} ({lim} lookups). Resets at midnight UTC."
        USAGE[(uid, name)] = (day, cnt + 1)
    LAST[(uid, name)] = now
    return None


def is_blocked(query: str, src: dict[str, Any]) -> bool:
    return norm_query(query) in set(STATE["blocked"])


def search_card(user, chat, name: str, query: str, res: Result | None, status: str, ms: int, hide: bool) -> str:
    q = "(hidden)" if hide or not S["log_queries"] else query
    head = {"ok": "🔎 <b>SEARCH</b> ✅", "empty": "🔎 <b>SEARCH</b> 🫥 no records", "error": "🔎 <b>SEARCH</b> ⚠️ error",
            "blocked": "🛡 <b>PROTECTED QUERY ATTEMPT</b>"}.get(status, "🔎 <b>SEARCH</b>")
    rows = [f"👤 {utag(user.id, user.full_name, user.username or '')}", f"📍 {esc(where(chat))}",
            f"🧩 <b>/{esc(name)}</b>", f"🎯 <code>{esc(shorten(q, 80))}</code>",
            f"📦 {len(res.items) if res else 0} record(s) · ⚡ {ms} ms"]
    text = f"{head}\n{quote_box(rows)}"
    if res and res.items and not hide and S["log_queries"]:
        top = [f"{MARKERS[i]} {esc(item_title(it, i))}" for i, it in enumerate(res.items[:3])]
        text += "\n" + tree(top)
    return text


async def lookup(update: Update, context: ContextTypes.DEFAULT_TYPE, name: str, query: str) -> None:
    msg, user, chat, bot = update.effective_message, update.effective_user, update.effective_chat, context.bot
    src = SOURCES.get(name)
    if src is None or not src.get("enabled", True) or user is None:
        return
    group = chat.type in GROUP_TYPES
    admin = is_admin(user.id)
    delay = eff(src, "auto_delete")
    query = (query or "").strip()[:200]
    hide_log = bool(src.get("no_log"))
    gmeta = STATE["groups"].get(str(chat.id)) if group else None

    def clean(*ms) -> None:
        if delay:
            autodelete(bot, *ms, delay=delay)
            if S["delete_queries"] and update.message is not None and not INPUT.get(user.id):
                autodelete(bot, update.message, delay=delay)

    async def say(text: str, markup=None):
        note = await msg.reply_html(text + delete_note(delay), reply_markup=markup, link_preview_options=NO_PREVIEW)
        clean(note)
        return note

    if S["lockdown"] and not admin:
        await say("🛠 <b>Maintenance</b>\nLookups are paused for a moment. Please try again soon.")
        return
    if gmeta and gmeta.get("muted") and not admin:
        return
    if src.get("maintenance") and not admin:
        await say(f"🛠 <b>/{esc(name)} is under maintenance</b>\n{esc(src.get('maint_msg') or 'It will be back shortly.')}")
        return
    bk = BREAKER.get(name)
    if bk and bk["until"] > time.time() and not admin:
        await say(f"🧯 <b>Temporarily unavailable</b>\nThe source is paused after repeated errors. Try again in {fmt_left(bk['until'] - time.time())}.")
        return
    if len(query) < int(src.get("min_len") or MIN_QUERY):
        await msg.reply_html(f"🔎 Please provide at least <b>{int(src.get('min_len') or MIN_QUERY)}</b> characters.")
        return
    if is_blocked(query, src):
        await say("🛡 <b>Protected</b>\nLookups for this query are disabled.")
        emit("blocked", user, chat, cmd=name, card=search_card(user, chat, name, query, None, "blocked", 0, True))
        await strike(bot, user, chat, msg, "tried to look up a protected query", int(S["strike_limit"]))
        return
    q = quota(user.id, name, src)
    if q:
        await msg.reply_html(q[1])
        if q[0] == "cool":
            await strike(bot, user, chat, msg, "spamming commands (cooldown ignored)")
        return

    placeholder = await msg.reply_html(f"{emoji_html(src)} <b>Scanning…</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n"
                                       "▰▰▱▱▱ <i>querying source</i>")
    clean(placeholder)
    t0 = time.perf_counter()
    try:
        res = await search_cached(query, name)
    except NotConfigured:
        await placeholder.edit_text("🔌 <b>No source connected.</b> The operator must set one first.", parse_mode=ParseMode.HTML)
        return
    except ApiError as exc:
        STATS["errors"] += 1
        await placeholder.edit_text(f"⚠️ {esc(exc)}", parse_mode=ParseMode.HTML)
        emit("search", user, chat, cmd=name, query="(hidden)" if hide_log or not S["log_queries"] else query, hits=0, status="error",
             card=search_card(user, chat, name, query, None, "error", int((time.perf_counter() - t0) * 1000), hide_log))
        await breaker_fail(bot, name)
        return
    except Exception:  # noqa: BLE001
        STATS["errors"] += 1
        log.exception("lookup failed")
        await placeholder.edit_text("💥 Something went wrong on our side. Please try again.")
        return

    BREAKER.pop(name, None)
    STATS["searches"] += 1
    STATS["lat"] += res.ms
    u = STATE["users"].get(str(user.id))
    if u is not None:
        u["count"] = u.get("count", 0) + 1
        u["hits"] = u.get("hits", 0) + (1 if res.items else 0)
        u["cmds"][name] = u["cmds"].get(name, 0) + 1
        u["last_query_at"] = time.time()
        persist()
    hit = bool(res.items)
    if hit:
        STATS["hits"] += 1

    # persist the full event (query + result) and post the log card
    result_json = ""
    if not hide_log and S["log_queries"]:
        rows = list(res.items[:25])
        result_json = json.dumps(rows, ensure_ascii=False, default=str)
        while len(result_json) > 60000 and rows:
            rows = rows[: max(1, len(rows) // 2)]
            result_json = json.dumps(rows, ensure_ascii=False, default=str)
            if len(rows) == 1:
                break
    doc = None
    if hit and S["log_files"] and not hide_log and S["log_queries"]:
        doc = (json.dumps({"query": query, "user": user.id, "cmd": name, "results": res.items}, indent=2,
                          ensure_ascii=False, default=str).encode(), f"{user.id}_{int(time.time())}.json")
    emit("search", user, chat, cmd=name, query="(hidden)" if hide_log or not S["log_queries"] else query,
         hits=len(res.items), ms=res.ms, status="ok" if hit else "empty", result_json=result_json,
         card=search_card(user, chat, name, query, res, "ok" if hit else "empty", res.ms, hide_log), doc=doc)

    if not hit:
        await placeholder.edit_text(
            f"🫥 <b>No records</b>\n🎯 <code>{esc(shorten(query, 60))}</code>\n<i>Try another spelling or a full value.</i>"
            + delete_note(delay), parse_mode=ParseMode.HTML)
        return

    requester = user.full_name if group else None
    key = secrets.token_hex(5)
    CACHE[key] = res
    META[key] = {"owner": user.id, "group": group, "by": requester, "src": name, "born": time.time()}
    if delay:
        spawn(_forget(key, delay + 5))
    else:
        spawn(_forget(key, 3600))
    text, markup = render_raw_page(key, res, 0) if src.get("raw_default") else render_results(key, res, 0)
    await placeholder.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW)


async def breaker_fail(bot, name: str) -> None:
    bk = BREAKER.setdefault(name, {"fails": 0, "until": 0.0, "alerted": False})
    bk["fails"] += 1
    if bk["fails"] < int(S["breaker_fails"]):
        return
    bk["until"] = time.time() + int(S["breaker_minutes"]) * 60
    if not bk["alerted"]:
        bk["alerted"] = True
        msg = (f"🧯 <b>CIRCUIT BREAKER</b>\n{DIV}\n"
               + table([("Command", f"/{name}"), ("Failures", str(bk["fails"])), ("Paused", f"{S['breaker_minutes']}m")]))
        await notify_admins(bot, msg, kb([[btn("🧯 Reset now", f"brk|{name}|0", "success")]]))
        tolog(msg)


async def on_source_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
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
        query = msg.reply_to_message.text or msg.reply_to_message.caption or ""
    if not query:
        sent = await msg.reply_html(f"{emoji_html(src)} <b>{esc(src['title'])}</b>\nUsage: <code>/{name} &lt;query&gt;</code>")
        autodelete(context.bot, sent, msg, delay=30)
        return
    await lookup(update, context, name, query)


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if is_admin(update.effective_user.id) and await handle_input(update, context):
        return
    await lookup(update, context, "num", update.effective_message.text or "")


# --------------------------------------------------------------------------- #
# User info / dossier                                                          #
# --------------------------------------------------------------------------- #


def find_user(arg: str) -> int | None:
    arg = arg.strip().lstrip("@")
    if arg.lstrip("-").isdigit():
        return int(arg)
    for uid, u in STATE["users"].items():
        if (u.get("username") or "").lower() == arg.lower():
            return int(uid)
    return None


async def build_dossier(uid: int) -> dict[str, Any]:
    u = STATE["users"].get(str(uid))
    events = await STORE.events(uid=uid, limit=20000)
    for e in events:
        if e.get("result_json"):
            try:
                e["result"] = json.loads(e.pop("result_json"))
            except ValueError:
                e["result"] = e.pop("result_json")
    searches = [e for e in events if e.get("type") == "search"]
    ban = STATE["bans"].get(str(uid))
    return {
        "user_id": uid, "has_used_bot": bool(u or events),
        "profile": ({**u, "first_seen": stamp(u.get("first")), "last_seen": stamp(u.get("last"))} if u else None),
        "ban": ban if ban and is_banned(uid) else None,
        "warnings": STATE["warns"].get(str(uid)),
        "daily_limit_override": STATE["limits"].get(str(uid)),
        "summary": {"events": len(events), "searches": len(searches),
                    "with_records": sum(1 for s in searches if s.get("hits")),
                    "warns": sum(1 for e in events if e.get("type") == "warn"),
                    "bans": sum(1 for e in events if e.get("type") == "ban")},
        "events": events,
    }


def dossier_txt(d: dict[str, Any]) -> str:
    out = [f"USER REPORT · {d['user_id']}", "=" * 60, f"Has used the bot : {'YES' if d['has_used_bot'] else 'NO'}"]
    p = d.get("profile")
    if p:
        out += [f"Name             : {p.get('name')}", f"Username         : @{p.get('username') or '-'}",
                f"First seen       : {p.get('first_seen')}", f"Last seen        : {p.get('last_seen')}",
                f"Language/Premium : {p.get('lang') or '-'} / {p.get('premium')}",
                f"Chats            : {', '.join(p.get('chats', {}).values())}"]
    out += [f"Ban              : {d['ban']}", f"Warnings         : {d['warnings']}", f"Summary          : {d['summary']}", "", "EVENTS", "-" * 60]
    for e in d["events"]:
        line = f"[{stamp(e.get('ts'))}] {e.get('type', '').upper():9} {e.get('chat_title', '')}"
        if e.get("type") == "search":
            line += f" | /{e.get('cmd')} | q={e.get('query')} | hits={e.get('hits')} | {e.get('ms')}ms | {e.get('status')}"
        elif e.get("reason"):
            line += f" | {e['reason']}"
        out.append(line)
        if e.get("result"):
            out.append("    RESULT: " + json.dumps(e["result"], ensure_ascii=False, default=str))
    return "\n".join(out)


async def render_userinfo(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    d = await build_dossier(uid)
    if not d["has_used_bot"]:
        return (f"🕵️ <b>USER REPORT</b>\n{DIV}\n❌ <code>{uid}</code> has <b>never used</b> this bot.",
                kb([[btn("🚫 Ban anyway", f"ui|{uid}|ban", "danger")], [btn("⬅️ Control center", "adm|home|0")]]))
    p = d["profile"] or {}
    ev = d["events"]
    s = d["summary"]
    last = [e for e in ev if e.get("type") == "search"][-6:][::-1]
    lines = [f"{'✅' if e.get('hits') else '🫥'} <code>{clock(e['ts'])}</code> /{esc(e.get('cmd'))} ▸ "
             f"<code>{esc(shorten(e.get('query'), 30))}</code> ▸ {e.get('hits', 0)}" for e in last]
    cmds = ", ".join(f"/{k}×{v}" for k, v in sorted((p.get("cmds") or {}).items(), key=lambda kv: -kv[1])[:5]) or "-"
    ban = d["ban"]
    w = d["warnings"] or {}
    text = (f"🕵️ <b>USER REPORT</b>\n{DIV}\n" + quote_box([f"👤 {utag(uid, p.get('name', '?'), p.get('username', ''))}", "✅ <b>Has used this bot</b>"])
            + "\n" + tree([f"🗓 <b>First seen</b> ▸ <code>{esc(p.get('first_seen', '-'))}</code>",
                           f"🕒 <b>Last seen</b> ▸ <code>{esc(p.get('last_seen', '-'))}</code>",
                           f"🔎 <b>Lookups</b> ▸ <code>{s['searches']}</code> ({s['with_records']} with records)",
                           f"🧩 <b>Commands</b> ▸ <code>{esc(cmds)}</code>",
                           f"📍 <b>Chats</b> ▸ <code>{esc(shorten(', '.join((p.get('chats') or {}).values()), 80))}</code>",
                           f"⚠️ <b>Warnings</b> ▸ <code>{w.get('count', 0)}/{S['warn_limit']}</code> · past warns {s['warns']}",
                           f"🚫 <b>Ban</b> ▸ <code>{esc((str(ban.get('reason')) + ' · ' + (fmt_left(ban['until'] - time.time()) + ' left' if ban.get('until') else 'permanent')) if ban else 'no')}</code>"])
            + (("\n\n🕘 <b>LAST LOOKUPS</b>\n<blockquote expandable>" + "\n".join(lines) + "</blockquote>") if lines else ""))
    rows = [[btn("📄 JSON file", f"ui|{uid}|json", "success"), btn("📝 TXT file", f"ui|{uid}|txt", "success")],
            [btn("✅ Unban", f"ui|{uid}|unban", "success") if ban else btn("🚫 Ban", f"ui|{uid}|ban", "danger"),
             btn("⚠️ Warn", f"ui|{uid}|warn", "primary")],
            [btn("⬅️ Control center", "adm|home|0")]]
    return text, kb(rows)


async def send_file(bot, chat_id: int, blob: bytes, fname: str, caption: str, delete_after: float = 300) -> None:
    sent = await bot.send_document(chat_id, InputFile(io.BytesIO(blob), filename=fname), caption=caption[:1000],
                                   parse_mode=ParseMode.HTML)
    autodelete(bot, sent, delay=delete_after)


async def cmd_userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    target = None
    if msg.reply_to_message and msg.reply_to_message.from_user:
        target = msg.reply_to_message.from_user.id
    elif context.args:
        target = find_user(context.args[0])
    if target is None:
        await msg.reply_html("Usage: <code>/userinfo &lt;user_id | @username&gt;</code> or reply to a message.\n"
                             "Shows whether the person used the bot + all their lookups, and exports JSON/TXT.")
        return
    text, markup = await render_userinfo(target)
    await msg.reply_html(text, reply_markup=markup, link_preview_options=NO_PREVIEW)


async def cmd_exportlog(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = [a.lower() for a in (context.args or [])]
    fmt = "txt" if "txt" in args else "json"
    hours = next((int(a) for a in args if a.isdigit()), 24)
    events = await STORE.events(since=time.time() - hours * 3600, limit=50000)
    for e in events:
        if e.get("result_json"):
            try:
                e["result"] = json.loads(e.pop("result_json"))
            except ValueError:
                pass
    if fmt == "txt":
        lines = [f"[{stamp(e.get('ts'))}] {e.get('type', '').upper()} uid={e.get('uid')} {e.get('name')} (@{e.get('username') or '-'}) "
                 f"{e.get('chat_title', '')} q={e.get('query', '')} hits={e.get('hits', '')}" for e in events]
        blob = "\n".join(lines).encode()
    else:
        blob = json.dumps({"hours": hours, "count": len(events), "events": events}, indent=2, ensure_ascii=False, default=str).encode()
    await send_file(context.bot, update.effective_chat.id, blob, f"events_{hours}h.{fmt}",
                    f"📜 <b>EVENT EXPORT</b> · last {hours}h · {len(events)} events\n⏳ <i>Self-destructs in 5 min</i>")


# --------------------------------------------------------------------------- #
# Admin: panels                                                                #
# --------------------------------------------------------------------------- #

BACK = [btn("⬅️ Control center", "adm|home|0")]
SPECS = [("auto_delete", "🧹 Auto-delete", "dur", [0, 60, 120, 300]), ("cooldown", "⏱ Cooldown", "dur", [1, 3, 5, 10]),
         ("daily_limit", "📅 Daily limit / user", "int", [0, 25, 50, 100, 200]),
         ("warn_limit", "⚠️ Warnings before ban", "int", [2, 3, 5]),
         ("strike_limit", "🚨 Strikes per warning", "int", [4, 6, 10]),
         ("ban_minutes", "⏳ Auto-ban minutes", "int", [15, 60, 360, 1440]),
         ("welcome_delete", "👋 Welcome auto-delete", "dur", [0, 60, 180, 600])]
TOGGLES = [("delete_queries", "🗑 Delete queries"), ("mask", "🙈 Mask sensitive"), ("members_can_search", "👥 Members search"),
           ("welcome", "👋 Welcome msg"), ("abuse_guard", "🚨 Abuse guard"), ("log_queries", "📝 Log queries"),
           ("log_files", "📎 Result files → log"), ("lockdown", "🔒 Lockdown")]


def render_admin() -> tuple[str, InlineKeyboardMarkup]:
    up = int(time.time() - STATS["started"])
    s = STATS["searches"]
    bans = sum(1 for u in list(STATE["bans"]) if is_banned(int(u)))
    text = (f"🛠 <b>CONTROL CENTER</b>\n{DIV}\n\n📈 <b>PERFORMANCE</b>\n"
            + table([("🔎 Lookups", str(s)), ("✅ Hit rate", f"{round(100 * STATS['hits'] / s)}%" if s else "-"),
                     ("⚡ Avg speed", f"{round(STATS['lat'] / s)} ms" if s else "-"), ("⚠️ Failures", str(STATS["errors"]))])
            + "\n\n🌐 <b>REACH</b>\n"
            + table([("👥 Users seen", str(len(STATE["users"]))), ("🛡 Groups", f"{len(STATE['groups'])} + {len(PENDING)} pending"),
                     ("🚫 Active bans", str(bans)), ("🧩 Commands", str(len(SOURCES))), ("🛡 Protected", str(len(STATE["blocked"])))])
            + "\n\n⚙️ <b>STATUS</b>\n"
            + table([("📣 Log channel", str(STATE["log_chat"]) if STATE.get("log_chat") else "not set"),
                     ("🔒 Lockdown", "ON" if S["lockdown"] else "off"), ("💾 Storage", STORE.kind),
                     ("⏱ Uptime", f"{up // 3600}h {up % 3600 // 60}m")])
            + (f"\n\n⚠️ <b>{esc(STATE['_note'])}</b>" if STATE.get("_note") else "")
            + f"\n\n{DIV}\n<i>Refreshed {clock()} UTC</i>")
    rows = [[btn("⚙️ Settings", "adm|settings|0"), btn("🧩 Commands", "cx|_.list|0", "success")],
            [btn("🛡 Groups", "adm|groups|0"), btn("🚫 Ban list", "adm|bans|0")],
            [btn("🏆 Top users", "adm|users|0"), btn("📣 Log channel", "adm|logch|0")],
            [btn("📤 Export 24h log", "adm|export|0", "success"), btn("💾 Test storage", "adm|dbping|0", "success")],
            [btn("🧹 Clear cache", "adm|clear|0", "danger"), btn("🔄 Refresh", "adm|home|0")]]
    return text, kb(rows)


def render_settings() -> tuple[str, InlineKeyboardMarkup]:
    def show(k: str, kind: str) -> str:
        v = S[k]
        return fmt_dur(v) if kind == "dur" else ("unlimited" if k == "daily_limit" and not v else str(v))

    text = (f"⚙️ <b>SETTINGS</b>\n{DIV}\n"
            + table([(label, show(k, kind)) for k, label, kind, _ in SPECS] + [(label, "ON" if S[k] else "off") for k, label in TOGGLES])
            + "\n\n<i>Changes apply instantly and are saved.</i>")
    rows = []
    for k, label, kind, opts in SPECS:
        rows.append([btn(label, "noop", None), btn("✏️ Custom", f"adm|val_{k}|0", "success")])
        rows.append([btn(("✅ " if float(S[k]) == float(o) else "") + (fmt_dur(o) if kind == "dur" else ("∞" if k == "daily_limit" and o == 0 else str(o))),
                         f"set|{k}|{o}", "success" if float(S[k]) == float(o) else "primary") for o in opts])
    tg = [btn(f"{'🟢' if S[k] else '⚪'} {label}", f"set|{k}|t", ("danger" if k == "lockdown" else "success") if S[k] else "primary")
          for k, label in TOGGLES]
    rows += [tg[i: i + 2] for i in range(0, len(tg), 2)]
    rows.append(BACK)
    return text, kb(rows)


async def render_groups(bot) -> tuple[str, InlineKeyboardMarkup]:
    items = list(STATE["groups"].items())[:10]
    stat = await asyncio.gather(*(bot_status_in(bot, int(g)) for g, _ in items))
    lines, rows = [], []
    for (gid, meta), st in zip(items, stat):
        lines.append(f"{'✅' if st else '❌'} <b>{esc(meta.get('title', gid))}</b>{' · 🔇 muted' if meta.get('muted') else ''}\n   <code>{gid}</code>")
        rows.append([btn(("🔊 Unmute " if meta.get("muted") else "🔇 Mute ") + shorten(meta.get("title", gid), 12), f"gm|{gid}|0"),
                     btn("🚪 Leave", f"lg|{gid}|0", "danger")])
    text = f"🛡 <b>GROUP MANAGER</b>\n{DIV}\n" + ("\n\n".join(lines) or "<i>No authorized groups.</i>")
    if PENDING:
        text += f"\n\n{DIV}\n⏳ <b>WAITING FOR APPROVAL</b>"
        for gid, info in list(PENDING.items())[:8]:
            text += f"\n▪️ <b>{esc(info['title'])}</b> · <code>{gid}</code> · by {esc(info['name'])}"
            rows.insert(0, [btn(f"✅ {shorten(info['title'], 16)}", f"ap|{gid}|0", "success"), btn("❌ Reject", f"rj|{gid}|0", "danger")])
    rows.append(BACK)
    return text, kb(rows)


def render_bans() -> tuple[str, InlineKeyboardMarkup]:
    ids = [int(u) for u in list(STATE["bans"]) if is_banned(int(u))][:15]
    lines = []
    for uid in ids:
        b = STATE["bans"][str(uid)]
        lines.append(f"🚫 <code>{uid}</code> · {esc(b.get('name') or '?')}\n   "
                     f"{'⏱ ' + fmt_left(b['until'] - time.time()) + ' left' if b.get('until') else '♾ permanent'} · {esc(b.get('reason', ''))}")
    rows = [[btn(f"✅ Unban {u}", f"ub|{u}|0", "success"), btn("🕵️ Report", f"ui|{u}|view", "primary")] for u in ids]
    rows.append(BACK)
    return f"🚫 <b>BAN LIST</b> <i>({len(ids)})</i>\n{DIV}\n" + ("\n".join(lines) or "<i>Nobody is banned.</i>"), kb(rows)


def render_top_users() -> tuple[str, InlineKeyboardMarkup]:
    ranked = sorted(STATE["users"].items(), key=lambda kv: kv[1].get("count", 0), reverse=True)[:10]
    medals = ["🥇", "🥈", "🥉"] + ["🔹"] * 7
    body = "\n".join(f"{medals[i]} <b>{esc(shorten(u.get('name'), 22))}</b> · <code>{uid}</code>\n   🔎 {u.get('count', 0)} lookups · last {clock(u.get('last'))}"
                     for i, (uid, u) in enumerate(ranked)) or "<i>No activity yet.</i>"
    rows = [[btn(f"🕵️ {shorten(u.get('name'), 14)}", f"ui|{uid}|view")] for uid, u in ranked[:6]]
    rows.append(BACK)
    return f"🏆 <b>TOP USERS</b>\n{DIV}\n\n{body}", kb(rows)


def render_logch() -> tuple[str, InlineKeyboardMarkup]:
    cur = STATE.get("log_chat")
    text = (f"📣 <b>LOG CHANNEL</b>\n{DIV}\n" + table([("Current", str(cur) if cur else "not set")])
            + "\n\n<b>Set it up</b>\n" + tree(["Create a channel and add this bot as <b>admin</b> (you must add it) - it registers automatically",
                                               "or send <code>/setlog -100xxxxxxxxxx</code>", "or set <code>LOG_CHANNEL_ID</code> env"])
            + "\n\nEverything is also stored in the bot's event store: use <code>/userinfo</code> for one person or "
              "<code>/exportlog [hours] [json|txt]</code> for all.")
    return text, kb([[btn("📨 Send test", "adm|logtest|0", "success"), btn("🚫 Disable", "adm|logoff|0", "danger")], BACK])


# ---- command (source) editor ----

EDIT_FIELDS = {
    "title": ("🏷 Title", "Send the new title, e.g. <code>Telegram Lookup</code>."),
    "emoji": ("😀 Emoji", "Send one emoji (Premium custom emoji work too)."),
    "url": ("🔗 API URL", "Send the URL with <code>{q}</code> where the query goes.\n<i>Your message is deleted instantly.</i>"),
    "backup_url": ("🛟 Backup API", "Send a backup URL (with <code>{q}</code>) or <code>clear</code>."),
    "headers": ("🔑 Headers", 'Send a JSON object e.g. <code>{"x-api-key":"abc"}</code> or <code>clear</code>.'),
    "transform": ("🧬 Response map", 'Send JSON, e.g.\n<pre>{"rows_path":"data.result","remove_keys":["credit","developer"],"rename":{"fname":"Father Name"},"replace":{"@OldBrand":"@MyBrand"},"regex":{"(?i)powered by .*":""}}</pre>Send <code>clear</code> to reset.'),
    "hide": ("🙈 Hidden fields", "Send comma-separated keywords, e.g. <code>id, hash</code>, or <code>clear</code>."),
    "icons": ("🧾 Field icons", "One per line: <code>keyword=emoji</code>, or <code>clear</code>."),
    "footer": ("📝 Footer", "Send the footer text shown under results, or <code>clear</code>."),
    "min_len": ("🔢 Min length", "Send a number 1-64."),
    "cooldown": ("⏱ Cooldown", "Seconds/duration (<code>7</code>, <code>45s</code>, <code>2m</code>) or <code>global</code>."),
    "daily_limit": ("📅 Daily limit", "A number, <code>unlimited</code> or <code>global</code>."),
    "auto_delete": ("🧹 Auto-delete", "Duration (<code>90s</code>, <code>3m</code>), <code>off</code> or <code>global</code>."),
    "maint_msg": ("💬 Maintenance text", "Send the text users see in maintenance, or <code>clear</code>."),
}


def parse_edit(field_: str, text: str, msg=None) -> tuple[bool, Any]:
    t = text.strip()
    low = t.lower()
    if field_ in ("title", "footer", "maint_msg"):
        return True, "" if low == "clear" and field_ != "title" else shorten(t, 160 if field_ != "title" else 40)
    if field_ == "emoji":
        return True, t.split()[0][:16] if t else "🛰"
    if field_ in ("url", "backup_url"):
        if low == "clear" and field_ == "backup_url":
            return True, ""
        return (True, t) if t.startswith(("http://", "https://")) and len(t) <= 2000 else (False, "That is not a valid http(s) URL.")
    if field_ == "headers":
        if low == "clear":
            return True, {}
        try:
            d = json.loads(t)
            assert isinstance(d, dict)
            return True, {str(k): str(v) for k, v in d.items()}
        except Exception:  # noqa: BLE001
            return False, "Send a valid JSON object."
    if field_ == "transform":
        if low == "clear":
            return True, {}
        try:
            d = json.loads(t)
            assert isinstance(d, dict)
        except Exception:  # noqa: BLE001
            return False, "Send a valid JSON object."
        out: dict[str, Any] = {}
        if d.get("rows_path"):
            out["rows_path"] = str(d["rows_path"])
        if isinstance(d.get("remove_keys"), list):
            out["remove_keys"] = [str(x) for x in d["remove_keys"]][:200]
        for k in ("rename", "replace", "regex"):
            if isinstance(d.get(k), dict):
                out[k] = {str(a): str(b) for a, b in d[k].items()}
        for pat in out.get("regex", {}):
            try:
                re.compile(pat)
            except re.error:
                return False, f"Invalid regex: {esc(pat)}"
        return True, out
    if field_ == "hide":
        return True, [] if low == "clear" else [h.strip().lower() for h in re.split(r"[,\n]+", t) if h.strip()][:30]
    if field_ == "icons":
        if low == "clear":
            return True, {}
        found = {}
        for part in re.split(r"[\n,;]+", t):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() and v.strip():
                    found[k.strip().lower()] = v.strip()[:16]
        return (True, found) if found else (False, "Use <code>keyword=emoji</code>, one per line.")
    if field_ == "min_len":
        return (True, int(t)) if t.isdigit() and 1 <= int(t) <= 64 else (False, "Send a number 1-64.")
    if low in {"g", "global", "default"}:
        return True, None
    if field_ == "daily_limit":
        if low in {"unlimited", "inf", "∞"}:
            return True, 0
        return (True, int(t)) if t.isdigit() else (False, "Send a number or <code>unlimited</code>.")
    v = parse_secs(t)
    if v is None or v > 7 * 86400:
        return False, "Send a duration like <code>45s</code>, <code>10m</code>, <code>2h</code> or <code>off</code>."
    return True, float(v) if field_ == "cooldown" else int(v)


def render_cmd_list() -> tuple[str, InlineKeyboardMarkup]:
    lines = [f"{'🛠' if s.get('maintenance') else ('🟢' if s.get('enabled') else '⚪')} {esc(s.get('emoji') or '')} <b>/{n}</b> ▸ {esc(s.get('title', n))} · "
             f"<code>{esc(urlparse(s['url']).netloc or 'no API')}</code>" for n, s in SOURCES.items()]
    text = f"🧩 <b>COMMANDS</b>\n{DIV}\n<i>Each command = its own API, look and response map.</i>\n\n" + "\n".join(lines)
    rows = [[btn(f"{s.get('emoji') or '🧩'} /{n} · {shorten(s.get('title', n), 16)}", f"cx|{n}.view|0")] for n, s in SOURCES.items()]
    rows.append([btn("➕ New command", "cx|_.new|0", "success")])
    rows.append(BACK)
    return text, kb(rows)


def render_cmd_panel(name: str) -> tuple[str, InlineKeyboardMarkup]:
    s = SOURCES[name]
    tf = s.get("transform") or {}
    text = (f"{emoji_html(s)} <b>/{esc(name)}</b> · <b>{esc(s['title'])}</b>\n{DIV}\n"
            + tree([f"🔗 <b>API</b> ▸ <code>{esc(urlparse(s['url']).netloc or 'not set')}</code>",
                    f"🛟 <b>Backup</b> ▸ <code>{'set' if s.get('backup_url') else 'none'}</code>",
                    f"🔑 <b>Headers</b> ▸ <code>{len(s.get('headers') or {})}</code>",
                    f"🙈 <b>Hidden</b> ▸ <code>{esc(shorten(', '.join(s.get('hide') or []) or 'none', 50))}</code>",
                    f"⏱ <b>Cooldown</b> ▸ <code>{'global' if s.get('cooldown') is None else str(s['cooldown']) + 's'}</code>",
                    f"📅 <b>Daily</b> ▸ <code>{'global' if s.get('daily_limit') is None else s['daily_limit'] or '∞'}</code>",
                    f"🧹 <b>Auto-delete</b> ▸ <code>{'global' if s.get('auto_delete') is None else fmt_dur(s['auto_delete'])}</code>",
                    f"🧾 <b>Raw JSON by default</b> ▸ <code>{'yes' if s.get('raw_default') else 'no'}</code>",
                    f"🕵️ <b>Hide from logs</b> ▸ <code>{'yes' if s.get('no_log') else 'no'}</code>",
                    f"📶 <b>Status</b> ▸ {'🟢 enabled' if s.get('enabled') else '⚪ disabled'}{' · 🛠 maintenance' if s.get('maintenance') else ''}"])
            + "\n\n🧬 <b>RESPONSE MAP</b>\n<blockquote expandable>" + (json_block(tf, 1200) if tf else "<i>none - raw API output is shown</i>") + "</blockquote>"
            + f"\n▶️ <code>/{name} &lt;query&gt;</code>")
    n = name
    protected = n == "num"
    rows = [[btn("🧬 Response map", f"cx|{n}.e_transform|0", "success"), btn("🧹 Strip branding", f"cx|{n}.brand|0", "success")],
            [btn("🔗 API", f"cx|{n}.e_url|0"), btn("🛟 Backup", f"cx|{n}.e_backup_url|0"), btn("🔑 Headers", f"cx|{n}.e_headers|0")],
            [btn("🏷 Title", f"cx|{n}.e_title|0"), btn("😀 Emoji", f"cx|{n}.e_emoji|0"), btn("🎨 Colour", f"cx|{n}.style|0")],
            [btn("🙈 Hide", f"cx|{n}.e_hide|0"), btn("🧾 Icons", f"cx|{n}.e_icons|0"), btn("📝 Footer", f"cx|{n}.e_footer|0")],
            [btn("⏱ Cooldown", f"cx|{n}.e_cooldown|0"), btn("📅 Daily", f"cx|{n}.e_daily_limit|0"), btn("🧹 Delete timer", f"cx|{n}.e_auto_delete|0")],
            [btn("🔢 Min length", f"cx|{n}.e_min_len|0"), btn("💬 Maint. text", f"cx|{n}.e_maint_msg|0")],
            [btn(("✅ " if s.get("raw_default") else "") + "Raw JSON default", f"cx|{n}.tg_raw|0"),
             btn(("✅ " if s.get("no_log") else "") + "Hide from logs", f"cx|{n}.tg_nolog|0")],
            [btn("🛠 Maintenance: ON" if s.get("maintenance") else "🛠 Maintenance: off", f"cx|{n}.tg_maint|0", "danger" if s.get("maintenance") else "primary"),
             btn("⚪ Disable" if s.get("enabled") else "🟢 Enable", f"cx|{n}.tg_enabled|0")],
            [btn("🧪 Test", f"cx|{n}.test|0", "success"), btn("👁 Reveal API", f"cx|{n}.reveal|0")],
            ([] if protected else [btn("🗑 Delete", f"cx|{n}.del|0", "danger")]),
            [btn("⬅️ Commands", "cx|_.list|0")]]
    return text, kb(rows)


# --------------------------------------------------------------------------- #
# Admin: text input flow + callbacks                                           #
# --------------------------------------------------------------------------- #


async def _safe_edit(query, text: str, markup: InlineKeyboardMarkup | None) -> None:
    try:
        await query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW)
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            log.warning("edit failed: %s", exc)


async def _show(context, st: dict[str, Any], text: str, markup: InlineKeyboardMarkup) -> None:
    try:
        await context.bot.edit_message_text(text, chat_id=st["chat"], message_id=st["mid"], parse_mode=ParseMode.HTML,
                                            reply_markup=markup, link_preview_options=NO_PREVIEW)
    except TelegramError:
        await context.bot.send_message(st["chat"], text, parse_mode=ParseMode.HTML, reply_markup=markup, link_preview_options=NO_PREVIEW)


def cancel_markup(name: str | None) -> InlineKeyboardMarkup:
    return kb([[btn("✖️ Cancel", f"cx|{name or '_'}.cancel|0", "danger")]])


def back_view(st: dict[str, Any]) -> tuple[str, InlineKeyboardMarkup]:
    if st["op"] == "setval":
        return render_settings()
    n = st.get("cmd")
    return render_cmd_panel(n) if n in SOURCES else render_cmd_list()


async def handle_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    msg, uid = update.effective_message, update.effective_user.id
    st = INPUT.get(uid)
    if not st or time.time() - st["ts"] > 300:
        INPUT.pop(uid, None)
        return False
    text = (msg.text or "").strip()
    op, name = st["op"], st.get("cmd")
    if op == "test":
        INPUT.pop(uid, None)
        await _show(context, st, *back_view(st))
        await lookup(update, context, name, text)
        return True
    try:
        await msg.delete()
    except TelegramError:
        pass
    if text.lower() == "cancel":
        INPUT.pop(uid, None)
        await _show(context, st, *back_view(st))
        return True
    err = None
    if op == "new_name":
        n = text.lower().lstrip("/")
        if not CMD_RE.match(n):
            err = "Use 2-32 chars: a-z, 0-9, _ (start with a letter)."
        elif n in RESERVED or n in SOURCES:
            err = "That name is reserved or already used."
        else:
            INPUT[uid] = {**st, "op": "new_url", "cmd": n, "ts": time.time()}
            await _show(context, st, f"/{n} ✔️\n\n🔗 <b>API URL</b>\nSend the URL with <code>{{q}}</code> for the query.", cancel_markup(n))
            return True
    elif op == "new_url":
        if not text.startswith(("http://", "https://")):
            err = "That is not a valid http(s) URL."
        else:
            SOURCES[name] = new_source(name, text)
            persist()
            QCACHE.clear()
            INPUT.pop(uid, None)
            await refresh_commands(context.bot)
            emit("admin", uid=uid, card=f"🧩 <b>COMMAND CREATED</b> /{esc(name)} by <code>{uid}</code>")
            await _show(context, st, f"✅ <b>/{name} created.</b>\n\n" + render_cmd_panel(name)[0], render_cmd_panel(name)[1])
            return True
    elif op == "setval":
        spec = next((s for s in SPECS if s[0] == st["field"]), None)
        if spec:
            v = parse_secs(text) if spec[2] == "dur" else (int(text) if text.isdigit() else None)
            if v is None:
                err = "Send a valid value (e.g. <code>90s</code>, <code>5m</code> or a whole number)."
            else:
                S[st["field"]] = type(DEFAULTS[st["field"]])(v)
                persist()
    elif op == "edit":
        src = SOURCES.get(name)
        if src is None:
            INPUT.pop(uid, None)
            await _show(context, st, *render_cmd_list())
            return True
        ok, val = parse_edit(st["field"], text, msg)
        if not ok:
            err = val
        else:
            fld = st["field"]
            if fld == "emoji":
                ents = [e for e in (msg.entities or []) if e.type == "custom_emoji"]
                src["emoji_id"] = ents[0].custom_emoji_id if ents else None
            src[fld] = val
            persist()
            QCACHE.clear()
            if fld in ("title", "emoji"):
                await refresh_commands(context.bot)
    if err:
        await _show(context, st, f"⚠️ {err}\n\n" + prompt_for(st), cancel_markup(name))
        return True
    INPUT.pop(uid, None)
    await _show(context, st, *back_view(st))
    return True


def prompt_for(st: dict[str, Any]) -> str:
    if st["op"] == "setval":
        return f"✏️ Send the new value for <b>{esc(st['field'])}</b> (e.g. <code>90s</code>, <code>5m</code>, <code>37</code>)."
    return f"{EDIT_FIELDS[st['field']][0]} · /{esc(st.get('cmd'))}\n{EDIT_FIELDS[st['field']][1]}"


async def handle_cx(update: Update, context: ContextTypes.DEFAULT_TYPE, key: str) -> None:
    q = update.callback_query
    uid = q.from_user.id
    name, _, op = key.partition(".")
    INPUT.pop(uid, None)
    if op == "list":
        await q.answer()
        await _safe_edit(q, *render_cmd_list())
        return
    if op == "new":
        await q.answer()
        INPUT[uid] = {"op": "new_name", "cmd": None, "chat": q.message.chat_id, "mid": q.message.message_id, "ts": time.time()}
        await _safe_edit(q, "➕ <b>New command</b>\nSend the command name, e.g. <code>tg</code> (a-z, 0-9, _).", cancel_markup(None))
        return
    if op == "cancel":
        await q.answer("Cancelled")
        await _safe_edit(q, *(render_cmd_panel(name) if name in SOURCES else render_cmd_list()))
        return
    src = SOURCES.get(name)
    if not src:
        await q.answer("That command no longer exists.", show_alert=True)
        await _safe_edit(q, *render_cmd_list())
        return
    if op == "view":
        await q.answer()
    elif op.startswith("e_"):
        field_ = op[2:]
        if field_ not in EDIT_FIELDS:
            await q.answer("Unknown field.")
            return
        await q.answer()
        st = {"op": "edit", "cmd": name, "field": field_, "chat": q.message.chat_id, "mid": q.message.message_id, "ts": time.time()}
        INPUT[uid] = st
        await _safe_edit(q, prompt_for(st), cancel_markup(name))
        return
    elif op == "test":
        await q.answer()
        INPUT[uid] = {"op": "test", "cmd": name, "chat": q.message.chat_id, "mid": q.message.message_id, "ts": time.time()}
        await _safe_edit(q, f"🧪 <b>Test /{esc(name)}</b>\nSend a sample query now.", cancel_markup(name))
        return
    elif op == "brand":
        tf = src.setdefault("transform", {})
        tf["remove_keys"] = sorted(set(tf.get("remove_keys", [])) | set(BRAND_KEYS))
        persist()
        QCACHE.clear()
        await q.answer("Branding keys added ✅ - add text replacements via Response map", show_alert=True)
    elif op.startswith("tg_"):
        f = {"raw": "raw_default", "nolog": "no_log", "maint": "maintenance", "enabled": "enabled"}[op[3:]]
        src[f] = not src.get(f, False)
        persist()
        if f in ("maintenance", "enabled"):
            await refresh_commands(context.bot)
        await q.answer("Saved ✅")
    elif op == "style":
        cyc = ["primary", "success", "danger", "default"]
        src["style"] = cyc[(cyc.index(src.get("style", "primary")) + 1) % len(cyc)] if src.get("style") in cyc else "primary"
        persist()
        await q.answer(f"Button colour: {src['style']}")
    elif op == "reveal":
        await q.answer("Sent below - auto-deletes in 60s")
        sent = await context.bot.send_message(q.message.chat_id, f"🔐 <b>/{esc(name)} API</b>\n<blockquote expandable><code>{esc(src['url'])}</code></blockquote>",
                                              parse_mode=ParseMode.HTML, link_preview_options=NO_PREVIEW)
        autodelete(context.bot, sent, delay=60)
        return
    elif op == "del":
        await q.answer()
        await _safe_edit(q, f"🗑 <b>Delete /{esc(name)}?</b>\nThis cannot be undone.",
                         kb([[btn("🗑 Yes, delete", f"cx|{name}.delok|0", "danger"), btn("↩️ Keep", f"cx|{name}.view|0", "success")]]))
        return
    elif op == "delok":
        if name != "num":
            SOURCES.pop(name, None)
            persist()
            await refresh_commands(context.bot)
            emit("admin", uid=uid, card=f"🗑 <b>COMMAND DELETED</b> /{esc(name)} by <code>{uid}</code>")
        await q.answer("Deleted")
        await _safe_edit(q, *render_cmd_list())
        return
    await _safe_edit(q, *render_cmd_panel(name))


async def handle_admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, action: str, key: str, arg: str) -> None:
    q = update.callback_query
    uid = q.from_user.id
    bot = context.bot
    done = InlineKeyboardMarkup([])

    if action == "cx":
        await handle_cx(update, context, key)
        return

    if action == "adm":
        if key == "clear":
            n = len(CACHE) + len(QCACHE)
            CACHE.clear(); META.clear(); QCACHE.clear()  # noqa: E702
            await q.answer(f"🧹 Cleared {n} cached item(s).", show_alert=True)
            key = "home"
        elif key == "dbping":
            await q.answer((await STORE.ping())[:190], show_alert=True)
            return
        elif key == "export":
            await q.answer("Preparing…")
            events = await STORE.events(since=time.time() - 86400, limit=50000)
            blob = json.dumps({"count": len(events), "events": events}, indent=2, ensure_ascii=False, default=str).encode()
            await send_file(bot, q.message.chat_id, blob, "events_24h.json", f"📤 <b>EVENT EXPORT</b> · 24h · {len(events)} events\n⏳ <i>Self-destructs in 5 min</i>")
            return
        elif key == "logtest":
            tolog(f"✅ <b>Log channel test</b>\nBot is connected. {stamp()}")
            await q.answer("Test queued - check the channel", show_alert=True)
            return
        elif key == "logoff":
            STATE["log_chat"] = 0
            persist()
            await q.answer("Log channel disabled")
            key = "logch"
        elif key.startswith("val_"):
            f = key[4:]
            if not any(s[0] == f for s in SPECS):
                await q.answer("Unknown setting.")
                return
            await q.answer()
            st = {"op": "setval", "field": f, "cmd": None, "chat": q.message.chat_id, "mid": q.message.message_id, "ts": time.time()}
            INPUT[uid] = st
            await _safe_edit(q, prompt_for(st), cancel_markup(None))
            return
        else:
            await q.answer()
        views = {"settings": render_settings, "bans": render_bans, "users": render_top_users, "logch": render_logch}
        if key == "groups":
            text, markup = await render_groups(bot)
        elif key in views:
            text, markup = views[key]()
        else:
            text, markup = render_admin()
        await _safe_edit(q, text, markup)
        return

    if action == "set":
        spec_keys = {s[0] for s in SPECS} | {t[0] for t in TOGGLES}
        if key not in spec_keys:
            await q.answer("Unknown setting.")
            return
        cur = S[key]
        S[key] = (not cur) if arg == "t" else type(DEFAULTS[key])(float(arg))
        persist()
        emit("admin", uid=uid, card=f"⚙️ <b>SETTING</b> <code>{key}</code> → <code>{S[key]}</code> by <code>{uid}</code>")
        await q.answer("Saved ✅")
        await _safe_edit(q, *render_settings())
        return

    if action == "ui":  # user report buttons
        target = int(key)
        if arg == "view":
            await q.answer()
            await _safe_edit(q, *await render_userinfo(target))
        elif arg in ("json", "txt"):
            await q.answer("Preparing…")
            d = await build_dossier(target)
            blob = (json.dumps(d, indent=2, ensure_ascii=False, default=str) if arg == "json" else dossier_txt(d)).encode()
            await send_file(bot, q.message.chat_id, blob, f"user_{target}.{arg}",
                            f"🕵️ <b>USER REPORT</b> · <code>{target}</code> · {d['summary']['searches']} lookups\n⏳ <i>Self-destructs in 5 min</i>")
        elif arg == "ban":
            await apply_ban(bot, target, STATE["users"].get(str(target), {}).get("name", "user"), None, None, 0, "banned by admin", uid)
            await q.answer("Banned 🚫")
            await _safe_edit(q, *await render_userinfo(target))
        elif arg == "unban":
            await do_unban(bot, target, uid)
            await q.answer("Unbanned ✅")
            await _safe_edit(q, *await render_userinfo(target))
        elif arg == "warn":
            u = STATE["users"].get(str(target), {})

            class _U:  # minimal user shim
                id, full_name, username = target, u.get("name", "user"), u.get("username", "")

            await warn_user(bot, _U, None, None, "warned by admin", uid)
            await q.answer("Warned ⚠️")
            await _safe_edit(q, *await render_userinfo(target))
        return

    if action == "ub":
        await do_unban(bot, int(key), uid)
        await q.answer("Unbanned ✅")
        await _safe_edit(q, *render_bans())
        return

    if action == "gm":
        meta = STATE["groups"].get(key)
        if meta is not None:
            meta["muted"] = not meta.get("muted", False)
            persist()
        await q.answer("Saved ✅")
        await _safe_edit(q, *await render_groups(bot))
        return

    if action == "lg":
        gid = int(key)
        PENDING.pop(gid, None)
        STATE["groups"].pop(str(gid), None)
        persist()
        try:
            await bot.leave_chat(gid)
        except TelegramError:
            pass
        await q.answer("Left & revoked ✅")
        await _safe_edit(q, *await render_groups(bot))
        return

    if action in {"ap", "rj"}:
        gid = int(key)
        info = PENDING.get(gid) or STATE["groups"].get(str(gid)) or {}
        title = info.get("title") or str(gid)
        if action == "ap":
            if await bot_status_in(bot, gid) is None:
                PENDING.pop(gid, None)
                await q.answer("The bot is no longer in that group.", show_alert=True)
                await _safe_edit(q, f"⚪ <b>{esc(title)}</b> - bot no longer in group.", done)
                return
            authorize_group(gid, title, uid)
            await q.answer("Approved ✅")
            await _safe_edit(q, f"✅ <b>APPROVED</b>\n{DIV}\n" + table([("Group", title), ("ID", str(gid))]), done)
            fake = type("C", (), {"title": title})()
            try:
                await bot.send_message(gid, build_welcome("everyone", fake, bot.username), parse_mode=ParseMode.HTML,
                                       reply_markup=welcome_markup(bot.username), link_preview_options=NO_PREVIEW)
            except TelegramError:
                pass
            emit("group_approved", uid=uid, card=f"✅ <b>GROUP APPROVED</b>\n<blockquote>{esc(title)} · <code>{gid}</code>\nby <code>{uid}</code></blockquote>")
        else:
            PENDING.pop(gid, None)
            STATE["groups"].pop(str(gid), None)
            persist()
            try:
                await bot.leave_chat(gid)
            except TelegramError:
                pass
            await q.answer("Rejected")
            await _safe_edit(q, f"🚫 <b>REJECTED &amp; LEFT</b>\n{DIV}\n" + table([("Group", title), ("ID", str(gid))]), done)
            emit("group_rejected", uid=uid, card=f"🚫 <b>GROUP REJECTED</b> {esc(title)} · <code>{gid}</code>")
        return

    if action == "oo":
        req = OPTOUTS.pop(key, None)
        if req is None:
            await q.answer("Already handled.")
            return
        if arg == "1":
            if req["norm"] not in STATE["blocked"]:
                STATE["blocked"].append(req["norm"])
            persist()
            QCACHE.clear()
            await q.answer("Protected ✅")
            await _safe_edit(q, f"🛡 <b>PROTECTED</b> ▸ <code>{esc(mask_norm(req['norm']))}</code>", done)
            try:
                await bot.send_message(req["uid"], "🛡 Your opt-out request was approved.")
            except TelegramError:
                pass
        else:
            await q.answer("Declined")
            await _safe_edit(q, f"❌ <b>DECLINED</b> ▸ <code>{esc(mask_norm(req['norm']))}</code>", done)
        return

    if action == "brk":
        BREAKER.pop(key, None)
        await q.answer("Breaker reset ✅")
        await _safe_edit(q, f"🧯 Breaker reset for <code>/{esc(key)}</code>.", done)


async def do_unban(bot, uid: int, by: int) -> None:
    was = STATE["bans"].pop(str(uid), None)
    STRIKES.pop(uid, None)
    persist()
    if was is None:
        return
    try:
        await bot.send_message(uid, "✅ <b>Your ban has been lifted.</b> Please follow the rules.", parse_mode=ParseMode.HTML)
    except TelegramError:
        pass
    emit("unban", uid=uid, name=was.get("name", ""), by=by,
         card=f"✅ <b>UNBANNED</b>\n<blockquote>👤 <code>{uid}</code> · {esc(was.get('name', ''))}\n👮 by <code>{by}</code></blockquote>")


# --------------------------------------------------------------------------- #
# Callbacks (results + routing)                                                #
# --------------------------------------------------------------------------- #

ADMIN_ACTIONS = {"adm", "set", "ub", "lg", "ap", "rj", "cx", "oo", "brk", "gm", "ui"}
KEYED = {"p", "d", "j", "x", "f", "close"}


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    q = update.callback_query
    data = q.data or ""
    uid = q.from_user.id if q.from_user else 0
    if data == "noop":
        await q.answer()
        return
    try:
        action, key, arg = data.split("|", 2)
    except ValueError:
        await q.answer("Unsupported button.")
        return
    if action in ADMIN_ACTIONS:
        if not is_admin(uid):
            await q.answer("Not available.", show_alert=True)
            return
        try:
            await handle_admin_callback(update, context, action, key, arg)
        except (ValueError, TypeError, KeyError):
            log.exception("admin callback failed")
            await q.answer("Bad request.")
        return

    in_group = bool(q.message and q.message.chat.type in GROUP_TYPES)
    if action in KEYED and in_group and not is_admin(uid):
        meta = META.get(key)
        if meta is None or meta["owner"] != uid:
            await q.answer(f"🔒 Only {(meta or {}).get('by') or 'the person who ran the search'} can use these buttons.", show_alert=True)
            return
    if action == "close":
        await q.answer("Closed")
        try:
            await q.message.delete()
        except TelegramError:
            pass
        return
    if action == "menu":
        await q.answer()
        await _safe_edit(q, *render_menu(uid))
        return
    if action == "help":
        await q.answer()
        await _safe_edit(q, render_help(is_admin(uid)), kb([[btn("🏠 Menu", "menu|0|0")]]) if not in_group else None)
        return
    if action == "usage":
        parts = []
        for n, s in SOURCES.items():
            day, cnt = USAGE.get((uid, n), (today(), 0))
            cnt = cnt if day == today() else 0
            lim = user_limit(uid, s)
            parts.append(f"/{n}: {cnt}" + (f"/{lim}" if lim and not is_admin(uid) else ""))
        await q.answer(" · ".join(parts)[:190] or "No usage", show_alert=True)
        return

    res = CACHE.get(key)
    if not res:
        await q.answer("This result expired - run the lookup again.", show_alert=True)
        return
    idx = int(arg) if arg.isdigit() else 0
    if action in {"x", "f"}:
        p = profile(META.get(key, {}).get("src"))
        rec = min(idx, len(res.items) - 1)
        payload = {"query": res.query, "total": len(res.items), "results": masked_copy(res.items, hide=p.get("hide"))} if action == "x" \
            else {"query": res.query, "record": masked_copy(res.items[rec], hide=p.get("hide"))}
        blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str).encode()
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", res.query)[:40] or "lookup"
        await q.answer("Preparing file…")
        await send_file(context.bot, q.message.chat_id, blob, f"{safe}_{'results' if action == 'x' else 'record_' + str(rec + 1)}.json",
                        f"📥 <b>EXPORT READY</b>\n🎯 <code>{esc(shorten(res.query, 50))}</code>" + delete_note(eff(p, "auto_delete")),
                        delete_after=eff(p, "auto_delete") or 0)
        return
    if action == "p":
        text, markup = render_results(key, res, idx)
    elif action == "j":
        text, markup = render_raw_page(key, res, idx)
    elif action == "d":
        text, markup = render_detail(key, res, idx)
    else:
        await q.answer("Unsupported button.")
        return
    await q.answer()
    await _safe_edit(q, text, markup)


# --------------------------------------------------------------------------- #
# Admin commands                                                               #
# --------------------------------------------------------------------------- #


def admin_only(fn):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not is_admin(update.effective_user.id if update.effective_user else None):
            return
        return await fn(update, context)
    wrapper.__name__ = fn.__name__
    return wrapper


def authorize_group(gid: int, title: str | None, by: int) -> None:
    STATE["groups"][str(gid)] = {**STATE["groups"].get(str(gid), {}), "title": title or str(gid), "by": by, "ts": int(time.time())}
    PENDING.pop(gid, None)
    persist()


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat.type == ChatType.PRIVATE:
        text, markup = render_menu(update.effective_user.id)
        await update.effective_message.reply_html(text, reply_markup=markup, link_preview_options=NO_PREVIEW)
    else:
        sent = await update.effective_message.reply_html(build_welcome("everyone", chat, context.bot.username),
                                                         reply_markup=welcome_markup(context.bot.username), link_preview_options=NO_PREVIEW)
        autodelete(context.bot, sent, update.effective_message, delay=S["welcome_delete"])


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    admin = is_admin(update.effective_user.id)
    sent = await update.effective_message.reply_html(render_help(admin and update.effective_chat.type == ChatType.PRIVATE),
                                                     link_preview_options=NO_PREVIEW)
    if update.effective_chat.type != ChatType.PRIVATE:
        autodelete(context.bot, sent, update.effective_message, delay=S["auto_delete"] or 120)


@admin_only
async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_admin()
    await update.effective_message.reply_html(text, reply_markup=markup)


@admin_only
async def cmd_cmds(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_cmd_list()
    await update.effective_message.reply_html(text, reply_markup=markup)


@admin_only
async def cmd_addcmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    a = context.args or []
    if len(a) < 2:
        await update.effective_message.reply_html("Usage: <code>/addcmd &lt;name&gt; &lt;url-with-{q}&gt;</code>")
        return
    n, url = a[0].lower().lstrip("/"), a[1]
    err = None
    if not CMD_RE.match(n):
        err = "Name must be 2-32 chars: a-z, 0-9, _."
    elif n in RESERVED or n in SOURCES:
        err = "That name is reserved or already used."
    elif not url.startswith(("http://", "https://")):
        err = "URL must start with http:// or https://"
    if err:
        await update.effective_message.reply_html(f"⚠️ {err}")
        return
    SOURCES[n] = new_source(n, url)
    persist()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    await refresh_commands(context.bot)
    text, markup = render_cmd_panel(n)
    await context.bot.send_message(update.effective_user.id, f"✅ <b>/{n} created.</b>\n\n" + text, parse_mode=ParseMode.HTML,
                                   reply_markup=markup, link_preview_options=NO_PREVIEW)


@admin_only
async def cmd_delcmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = (context.args[0].lower().lstrip("/") if context.args else "")
    if n not in SOURCES or n == "num":
        await update.effective_message.reply_html("Usage: <code>/delcmd &lt;name&gt;</code> (see /cmds; /num can't be deleted)")
        return
    SOURCES.pop(n)
    persist()
    await refresh_commands(context.bot)
    await update.effective_message.reply_html(f"🗑 <b>/{esc(n)}</b> deleted.")


@admin_only
async def cmd_setmap(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = (context.args[0].lower().lstrip("/") if context.args else "")
    if n not in SOURCES:
        await update.effective_message.reply_html("Usage: <code>/setmap &lt;command&gt;</code> then send the JSON map.")
        return
    st = {"op": "edit", "cmd": n, "field": "transform", "chat": update.effective_chat.id, "ts": time.time()}
    sent = await update.effective_message.reply_html(prompt_for(st), reply_markup=cancel_markup(n))
    INPUT[update.effective_user.id] = {**st, "mid": sent.message_id}


@admin_only
async def cmd_connect(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].startswith(("http://", "https://")):
        await update.effective_message.reply_html("Usage: <code>/connect https://api.example.com/x?q={q}</code> (sets the /num source)")
        return
    SOURCES["num"]["url"] = context.args[0]
    persist()
    QCACHE.clear()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    await context.bot.send_message(update.effective_user.id, "✅ <b>/num source connected.</b> Your message was deleted to keep the URL private.", parse_mode=ParseMode.HTML)


@admin_only
async def cmd_groups(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = await render_groups(context.bot)
    await update.effective_message.reply_html(text, reply_markup=markup)


@admin_only
async def cmd_allowgroup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    try:
        gid = int(context.args[0]) if context.args else (chat.id if chat.type in GROUP_TYPES else None)
    except ValueError:
        gid = None
    if gid is None:
        await update.effective_message.reply_html("Usage: <code>/allowgroup [chat_id]</code>")
        return
    if await bot_status_in(context.bot, gid) is None:
        await update.effective_message.reply_html("⚠️ The bot is not in that chat. Add it first.")
        return
    try:
        title = (await context.bot.get_chat(gid)).title
    except TelegramError:
        title = str(gid)
    authorize_group(gid, title, update.effective_user.id)
    await update.effective_message.reply_html(f"✅ <b>Authorized</b>\n{table([('Group', title or str(gid)), ('ID', str(gid))])}")


@admin_only
async def cmd_denygroup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        gid = int(context.args[0])
    except (IndexError, ValueError):
        await update.effective_message.reply_html("Usage: <code>/denygroup &lt;chat_id&gt;</code>")
        return
    PENDING.pop(gid, None)
    STATE["groups"].pop(str(gid), None)
    persist()
    try:
        await context.bot.leave_chat(gid)
    except TelegramError:
        pass
    await update.effective_message.reply_html("🗑 Revoked &amp; left.")


def target_and_args(update: Update, context: ContextTypes.DEFAULT_TYPE) -> tuple[Any, list[str]]:
    args = list(context.args or [])
    reply = update.effective_message.reply_to_message
    if reply and reply.from_user:
        u = reply.from_user
        touch_user(u, None)
        return u, args
    if args:
        uid = find_user(args[0])
        if uid is not None:
            args.pop(0)
            info = STATE["users"].get(str(uid), {})
            return type("U", (), {"id": uid, "full_name": info.get("name", "user"), "username": info.get("username", "")})(), args
    return None, args


@admin_only
async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    target, args = target_and_args(update, context)
    if target is None:
        await msg.reply_html("Usage: <code>/ban &lt;user_id|@user&gt; [30m|6h|7d|perm] [reason]</code> or reply with <code>/ban [duration] [reason]</code>")
        return
    if is_admin(target.id):
        await msg.reply_html("🛡 You can't ban an admin.")
        return
    minutes = 0
    if args and (p := parse_minutes(args[0])) is not None:
        minutes = p
        args.pop(0)
    reason = " ".join(args) or "violating the rules"
    chat = update.effective_chat
    await apply_ban(context.bot, target.id, target.full_name, chat.id, (msg.reply_to_message or msg).message_id, minutes, reason,
                    update.effective_user.id, getattr(target, "username", "") or "")


@admin_only
async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target, _ = target_and_args(update, context)
    if target is None:
        await update.effective_message.reply_html("Usage: <code>/unban &lt;user_id&gt;</code>")
        return
    await do_unban(context.bot, target.id, update.effective_user.id)
    await update.effective_message.reply_html(f"✅ <b>Unbanned</b> <code>{target.id}</code>")


@admin_only
async def cmd_warn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    target, args = target_and_args(update, context)
    if target is None:
        await msg.reply_html("Usage: <code>/warn &lt;user_id|@user&gt; [reason]</code> or reply with <code>/warn [reason]</code>")
        return
    await warn_user(context.bot, target, update.effective_chat, msg.reply_to_message or msg, " ".join(args) or "breaking the rules",
                    update.effective_user.id)


@admin_only
async def cmd_unwarn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target, _ = target_and_args(update, context)
    if target is None:
        await update.effective_message.reply_html("Usage: <code>/unwarn &lt;user_id&gt;</code>")
        return
    w = STATE["warns"].get(str(target.id))
    if w and w["count"] > 0:
        w["count"] -= 1
        persist()
    await update.effective_message.reply_html(f"✅ Removed one warning from <code>{target.id}</code> ({(w or {}).get('count', 0)}/{S['warn_limit']}).")


@admin_only
async def cmd_banned(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text, markup = render_bans()
    await update.effective_message.reply_html(text, reply_markup=markup)


@admin_only
async def cmd_block(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = " ".join(context.args or []).strip()
    norms = list(dict.fromkeys(norm_query(p) for p in re.split(r"[\n,;]+", raw) if len(p.strip()) >= 3))
    if not norms:
        await update.effective_message.reply_html("Usage: <code>/block &lt;phone / username / email&gt;</code> - refused on every command.")
        return
    for n in norms:
        if n not in STATE["blocked"]:
            STATE["blocked"].append(n)
    persist()
    QCACHE.clear()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    sent = await context.bot.send_message(update.effective_user.id, f"🛡 <b>Protected</b> ▸ <code>{esc(mask_norm(norms[0]))}</code> · {len(STATE['blocked'])} total", parse_mode=ParseMode.HTML)
    autodelete(context.bot, sent, delay=60)


@admin_only
async def cmd_unblock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    n = norm_query(" ".join(context.args or []))
    if n in STATE["blocked"]:
        STATE["blocked"].remove(n)
        persist()
    try:
        await update.effective_message.delete()
    except TelegramError:
        pass
    sent = await context.bot.send_message(update.effective_user.id, "✅ Done.", parse_mode=ParseMode.HTML)
    autodelete(context.bot, sent, delay=30)


@admin_only
async def cmd_setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target, args = target_and_args(update, context)
    val = args[0].lower() if args else ""
    if target is None or not val:
        await update.effective_message.reply_html("Usage: <code>/setlimit &lt;user_id&gt; &lt;N|unlimited|off&gt;</code>")
        return
    if val in {"off", "reset"}:
        STATE["limits"].pop(str(target.id), None)
    elif val in {"unlimited", "inf", "0"}:
        STATE["limits"][str(target.id)] = 0
    elif val.isdigit():
        STATE["limits"][str(target.id)] = int(val)
    else:
        await update.effective_message.reply_html("⚠️ Send a number, <code>unlimited</code> or <code>off</code>.")
        return
    persist()
    emit("admin", uid=update.effective_user.id, card=f"📅 <b>LIMIT</b> <code>{target.id}</code> → <code>{val}</code> by <code>{update.effective_user.id}</code>")
    await update.effective_message.reply_html(f"✅ <code>{target.id}</code> ▸ <b>{val}</b>")


@admin_only
async def cmd_setlog(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("-").isdigit():
        await update.effective_message.reply_html("Usage: <code>/setlog -100xxxxxxxxxx</code> (or <code>/setlog off</code>)")
        return
    STATE["log_chat"] = int(context.args[0])
    persist()
    tolog(f"✅ <b>Log channel connected</b>\n{stamp()}")
    await update.effective_message.reply_html("📣 Log channel saved. A test message was queued - check the channel.")


@admin_only
async def cmd_setwelcome(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.effective_message.text or "").partition(" ")[2].strip()
    if not text:
        await update.effective_message.reply_html(
            "Usage: <code>/setwelcome &lt;HTML text&gt;</code>\nPlaceholders: <code>{name}</code> <code>{group}</code> <code>{commands}</code> <code>{bot}</code>\n"
            "<code>/setwelcome reset</code> restores the default.")
        return
    S["welcome_text"] = "" if text.lower() == "reset" else text[:3000]
    persist()
    await update.effective_message.reply_html("✅ Welcome message saved." if S["welcome_text"] else "✅ Default welcome restored.")


@admin_only
async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.effective_message.text or "").partition(" ")[2].strip()
    if not text:
        await update.effective_message.reply_html("Usage: <code>/broadcast &lt;message&gt;</code>")
        return
    ok = 0
    for gid in list(STATE["groups"]):
        try:
            await context.bot.send_message(int(gid), f"📣 <b>Announcement</b>\n{DIV}\n{esc(text)}", parse_mode=ParseMode.HTML)
            ok += 1
        except TelegramError:
            pass
        await asyncio.sleep(0.05)
    await update.effective_message.reply_html(f"📣 Sent to {ok}/{len(STATE['groups'])} groups.")


async def cmd_optout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user, chat, msg = update.effective_user, update.effective_chat, update.effective_message
    raw = " ".join(context.args or [])
    try:
        await msg.delete()
    except TelegramError:
        pass
    if len(raw.strip()) < 3:
        await reply_to(context.bot, chat.id, "🛡 Usage: <code>/optout &lt;your number / username / email&gt;</code> - your message is deleted instantly.", delete_after=30)
        return
    n = norm_query(raw)
    if is_admin(user.id):
        if n not in STATE["blocked"]:
            STATE["blocked"].append(n)
        persist()
        await reply_to(context.bot, chat.id, "🛡 Protected.", delete_after=20)
        return
    if throttle("optout", user.id, 120) is False:
        await reply_to(context.bot, chat.id, "⏳ Please wait before sending another request.", delete_after=20)
        return
    rid = secrets.token_hex(4)
    OPTOUTS[rid] = {"norm": n, "uid": user.id, "name": user.full_name, "ts": time.time()}
    await notify_admins(context.bot, f"📬 <b>OPT-OUT REQUEST</b>\n{DIV}\n" + table([("Query", mask_norm(n)), ("From", f"{user.full_name} ({user.id})"), ("Where", where(chat))]),
                        kb([[btn("✅ Protect", f"oo|{rid}|1", "success"), btn("❌ Decline", f"oo|{rid}|0", "danger")]]))
    await reply_to(context.bot, chat.id, "🛡 <b>Request received.</b> An admin will review it.", delete_after=30)


# --------------------------------------------------------------------------- #
# Chat member updates, commands menu, lifecycle                                #
# --------------------------------------------------------------------------- #

ADMIN_COMMANDS = [BotCommand(c, d) for c, d in [
    ("start", "Open the menu"), ("admin", "Control center"), ("cmds", "Manage commands"), ("addcmd", "Add a command"),
    ("setmap", "Edit a command's response map"), ("userinfo", "User report + export"), ("exportlog", "Export event log"),
    ("ban", "Ban a user"), ("unban", "Unban"), ("warn", "Warn a user"), ("unwarn", "Remove a warning"), ("banned", "Ban list"),
    ("block", "Protect a query"), ("unblock", "Unprotect"), ("setlimit", "Per-user daily limit"), ("setlog", "Set log channel"),
    ("setwelcome", "Edit welcome message"), ("groups", "Manage groups"), ("allowgroup", "Authorize a group"),
    ("denygroup", "Revoke a group"), ("connect", "Set the /num API"), ("broadcast", "Announce to groups"), ("help", "Help")]]


async def refresh_commands(bot) -> None:
    custom = [BotCommand(n, shorten(f"{s.get('emoji') or ''} {s.get('title') or n}".strip(), 200) or n)
              for n, s in SOURCES.items() if s.get("enabled") and n != "num"]
    group_cmds = ([BotCommand("num", "Run a lookup")] if SOURCES.get("num", {}).get("enabled") else []) + custom[:50] \
        + [BotCommand("optout", "Protect your number/username"), BotCommand("help", "How to use")]
    try:
        await bot.delete_my_commands()
        await bot.set_my_commands(group_cmds, scope=BotCommandScopeAllGroupChats())
        await bot.set_my_commands(group_cmds, scope=BotCommandScopeAllChatAdministrators())
    except TelegramError as exc:
        log.warning("set_my_commands failed: %s", exc)
    for a in ADMIN_IDS:
        try:
            await bot.set_my_commands(ADMIN_COMMANDS + custom[:60 - len(ADMIN_COMMANDS)], scope=BotCommandScopeChat(a))
        except TelegramError:
            pass


async def on_my_chat_member(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ev = update.my_chat_member
    chat, adder = ev.chat, ev.from_user
    old, new = ev.old_chat_member.status, ev.new_chat_member.status
    gone = (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED)
    present = (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR)

    if chat.type == ChatType.CHANNEL:  # adding the bot as admin of a channel = log channel
        if new == ChatMemberStatus.ADMINISTRATOR and is_admin(adder.id):
            STATE["log_chat"] = chat.id
            persist()
            tolog(f"✅ <b>Log channel connected</b>\n<blockquote>{esc(chat.title or chat.id)}</blockquote>\nEvery user, lookup, warning and ban will be posted here.")
            await notify_admins(context.bot, f"📣 <b>Log channel set</b> → <b>{esc(chat.title or chat.id)}</b> <code>{chat.id}</code>")
        return
    if chat.type not in GROUP_TYPES:
        return
    title = esc(chat.title)
    if new in present and old in gone:
        if is_admin(adder.id):
            authorize_group(chat.id, chat.title, adder.id)
            await notify_admins(context.bot, f"✅ <b>Added &amp; authorized</b>\n<b>{title}</b> · <code>{chat.id}</code>")
            try:
                await context.bot.send_message(chat.id, build_welcome("everyone", chat, context.bot.username), parse_mode=ParseMode.HTML,
                                               reply_markup=welcome_markup(context.bot.username), link_preview_options=NO_PREVIEW)
            except TelegramError:
                pass
            emit("group_added", adder, chat, card=f"➕ <b>BOT ADDED &amp; AUTHORIZED</b>\n<blockquote>{title} · <code>{chat.id}</code>\nby {utag(adder.id, adder.full_name, adder.username or '')}</blockquote>")
        else:
            PENDING[chat.id] = {"title": chat.title or str(chat.id), "by": adder.id, "name": adder.full_name, "ts": time.time()}
            card = (f"🆕 <b>APPROVAL NEEDED</b>\n{DIV}\n" + table([("Group", chat.title or str(chat.id)), ("ID", str(chat.id)), ("Added by", f"{adder.full_name} ({adder.id})")])
                    + f"\n\n<i>The bot stays silent until you decide and leaves after {max(1, round(PENDING_TTL / 3600))}h.</i>")
            await notify_admins(context.bot, card, kb([[btn("✅ Approve", f"ap|{chat.id}|0", "success"), btn("❌ Reject & leave", f"rj|{chat.id}|0", "danger")]]))
            tolog(card)
            await reply_to(context.bot, chat.id, "⏳ <b>Awaiting approval</b>\nThis is a private bot. The owner has been notified.")
    elif new in gone:
        was = PENDING.pop(chat.id, None) is not None
        if STATE["groups"].pop(str(chat.id), None) is not None:
            persist()
            await notify_admins(context.bot, f"👋 Removed from <b>{title}</b> - authorization cleared.")
            emit("group_removed", chat=chat, card=f"👋 <b>BOT REMOVED</b> from {title} · <code>{chat.id}</code>")
        elif was:
            await notify_admins(context.bot, f"👋 Removed from pending group <b>{title}</b>.")


async def housekeeping(bot) -> None:
    while True:
        await asyncio.sleep(60)
        try:
            now = time.time()
            for u in [u for u, b in STATE["bans"].items() if b.get("until") and now >= b["until"]]:
                b = STATE["bans"].pop(u)
                persist()
                try:
                    await bot.send_message(int(u), "✅ <b>Your temporary ban has ended.</b> Please follow the rules.", parse_mode=ParseMode.HTML)
                except TelegramError:
                    pass
                emit("unban", uid=int(u), name=b.get("name", ""), by=0, card=f"⏱ <b>BAN EXPIRED</b> <code>{u}</code> · {esc(b.get('name', ''))}")
            for uid, dq in list(STRIKES.items()):
                while dq and now - dq[0] > 600:
                    dq.popleft()
                if not dq:
                    STRIKES.pop(uid, None)
            for rid in [r for r, q in OPTOUTS.items() if now - q["ts"] > 7 * 86400]:
                OPTOUTS.pop(rid, None)
            for gid, info in list(PENDING.items()):
                if now - info["ts"] > PENDING_TTL:
                    PENDING.pop(gid, None)
                    try:
                        await bot.leave_chat(gid)
                    except TelegramError:
                        pass
                    await notify_admins(bot, f"⌛ Left <b>{esc(info['title'])}</b> - no approval in time.")
            for k in [k for k, t in NOTICE.items() if now - t > 600]:
                NOTICE.pop(k, None)
        except Exception:  # noqa: BLE001
            log.exception("housekeeping failed")


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error("handler error", exc_info=context.error)
    if isinstance(update, Update) and update.effective_chat and update.effective_chat.type == ChatType.PRIVATE and update.effective_message:
        try:
            await update.effective_message.reply_html("💥 Something went wrong. Please try again.")
        except TelegramError:
            pass


async def post_init(app: Application) -> None:
    bot = app.bot
    await init_storage()
    await refresh_commands(bot)
    app.bot_data["tasks"] = [asyncio.create_task(c) for c in (flusher(), log_worker(bot), housekeeping(bot))]
    me = await bot.get_me()
    log.info("Online as @%s", me.username)
    await notify_admins(bot, f"🟢 <b>{esc(BOT_NAME)} online</b>\n" + table([
        ("Commands", str(len(SOURCES))), ("Groups", str(len(STATE["groups"]))), ("Users seen", str(len(STATE["users"]))),
        ("Log channel", str(STATE["log_chat"]) if STATE.get("log_chat") else "not set"), ("Storage", STORE.kind)])
        + (f"\n\n⚠️ <b>{esc(STATE['_note'])}</b>" if STATE.get("_note") else ""))
    tolog(f"🟢 <b>{esc(BOT_NAME)} started</b> · {stamp()}")


async def post_shutdown(app: Application) -> None:
    for t in app.bot_data.get("tasks", []):
        t.cancel()
    if STORE is not None:
        try:
            await STORE.save_state({k: v for k, v in STATE.items() if not k.startswith("_")})
        except Exception:  # noqa: BLE001
            pass
        await STORE.close()
    if _SESSION and not _SESSION.closed:
        await _SESSION.close()


def main() -> None:
    app = (ApplicationBuilder().token(BOT_TOKEN).rate_limiter(AIORateLimiter()).concurrent_updates(256)
           .connection_pool_size(256).pool_timeout(20.0).post_init(post_init).post_shutdown(post_shutdown).build())
    private = filters.ChatType.PRIVATE

    app.add_handler(TypeHandler(Update, access_gate), group=-1)
    app.add_handler(ChatMemberHandler(on_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, on_new_members))

    for name, fn, flt in [
        ("start", cmd_start, None), ("help", cmd_help, None), ("optout", cmd_optout, None),
        ("admin", cmd_admin, private), ("cmds", cmd_cmds, private), ("addcmd", cmd_addcmd, private),
        ("delcmd", cmd_delcmd, private), ("setmap", cmd_setmap, private), ("connect", cmd_connect, private),
        ("groups", cmd_groups, private), ("denygroup", cmd_denygroup, private), ("banned", cmd_banned, private),
        ("block", cmd_block, private), ("unblock", cmd_unblock, private), ("setlog", cmd_setlog, private),
        ("setwelcome", cmd_setwelcome, private), ("broadcast", cmd_broadcast, private),
        ("userinfo", cmd_userinfo, private), ("exportlog", cmd_exportlog, private),
        ("allowgroup", cmd_allowgroup, None), ("ban", cmd_ban, None), ("unban", cmd_unban, None),
        ("warn", cmd_warn, None), ("unwarn", cmd_unwarn, None), ("setlimit", cmd_setlimit, None)]:
        app.add_handler(CommandHandler(name, admin_only(fn) if name == "userinfo" or name == "exportlog" else fn, filters=flt))
    app.add_handler(MessageHandler(filters.COMMAND, on_source_command))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & private, on_text))
    app.add_error_handler(on_error)

    if WEBHOOK_URL:
        log.info("webhook mode on :%s", PORT)
        app.run_webhook(listen="0.0.0.0", port=PORT, url_path="telegram", webhook_url=f"{WEBHOOK_URL}/telegram",
                        secret_token=WEBHOOK_SECRET, allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
    else:
        log.info("long-polling mode")
        app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
