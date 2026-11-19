#!/usr/bin/env python3
"""
HubChat - offline LAN chat server for a local hub.
#General (time-gated to join date), Announcements (always fully visible),
Direct Messages with a proper inbox + unread badges + sound, member profiles
with avatars + bios, and a modern UI. Pure standard library, no internet needed.
"""

import hashlib
import hmac
import json
import mimetypes
import os
import queue
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
HISTORY_FILE = Path(__file__).parent / "messages.jsonl"
UPLOAD_DIR = Path(__file__).parent / "uploads"
USERS_FILE = Path(__file__).parent / "users.json"
ACCESS_CODE_FILE = Path(__file__).parent / "hub_access_code.txt"
HISTORY_LIMIT = 400
MAX_MESSAGE_LEN = 2000
MAX_USERNAME_LEN = 24
MIN_USERNAME_LEN = 3
MIN_PASSWORD_LEN = 4
MAX_BIO_LEN = 300
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{%d,%d}$" % (MIN_USERNAME_LEN, MAX_USERNAME_LEN))
RESERVED_USERNAMES = {"general", "announcement", "announcements", "admin", "system", "you"}

# --- AI assistant (HubBot) ---------------------------------------------------
# Set the ANTHROPIC_API_KEY environment variable before starting the server to
# enable this. HubBot then shows up as a normal member people can DM like
# anyone else; the reply comes back as a message from HubBot in that same
# conversation. Uses only the Python standard library (urllib) - no pip installs.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
BOT_USERNAME = "HubBot"
BOT_MODEL = "claude-haiku-4-5-20251001"
RESERVED_USERNAMES.add(BOT_USERNAME.lower())


def call_claude(api_messages):
    if not ANTHROPIC_API_KEY:
        return "I'm not set up yet — ask your hub admin to start the server with an ANTHROPIC_API_KEY environment variable to enable me."
    try:
        req_body = json.dumps({
            "model": BOT_MODEL,
            "max_tokens": 600,
            "messages": api_messages,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=req_body,
            headers={
                "content-type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "".join(parts).strip() or "(no response)"
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            msg = err_body.get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        return f"Sorry, I hit an error talking to the AI service: {msg}"
    except Exception as e:
        return f"Sorry, I couldn't reach the AI service right now ({e})."


def handle_bot_dm(asking_user):
    """Runs in a background thread so it never blocks the person's own message send."""
    convo = []
    with history_lock:
        if HISTORY_FILE.exists():
            with HISTORY_FILE.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        m = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if m.get("recipient") == BOT_USERNAME and m.get("username") == asking_user:
                        convo.append(("user", m))
                    elif m.get("recipient") == asking_user and m.get("username") == BOT_USERNAME:
                        convo.append(("assistant", m))
    convo.sort(key=lambda pair: pair[1].get("ts", 0))
    convo = convo[-20:]

    api_messages = [{"role": role, "content": m.get("text") or ""} for role, m in convo if m.get("text")]
    if not api_messages or api_messages[-1]["role"] != "user":
        return

    reply_text = call_claude(api_messages)

    bot_message = {
        "id": uuid.uuid4().hex,
        "username": BOT_USERNAME,
        "text": reply_text,
        "ts": time.time(),
        "system": False,
        "media_url": None,
        "reply_to": None,
        "recipient": asking_user,
        "channel": None,
    }
    append_history(bot_message)
    broadcast("message", bot_message, target_users=[asking_user, BOT_USERNAME])

UPLOAD_DIR.mkdir(exist_ok=True)


def get_or_create_access_code():
    if ACCESS_CODE_FILE.exists():
        code = ACCESS_CODE_FILE.read_text().strip()
        if code:
            return code
    code = secrets.token_hex(4).upper()
    ACCESS_CODE_FILE.write_text(code)
    return code


HUB_ACCESS_CODE = get_or_create_access_code()

# ---------------------------------------------------------------------------
# In-memory state (thread-safe)
# ---------------------------------------------------------------------------

lock = threading.Lock()
subscribers = {}
online_users = {}
users_lock = threading.Lock()
sessions = {}
history_lock = threading.Lock()


def load_users():
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def hash_password(password, salt_hex=None):
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 100_000)
    return salt_hex, dk.hex()


def verify_password(password, salt_hex, expected_hash_hex):
    _, dk_hex = hash_password(password, salt_hex)
    return hmac.compare_digest(dk_hex, expected_hash_hex)


def create_session(username):
    token = secrets.token_hex(24)
    with users_lock:
        sessions[token] = username
    return token


def username_taken(users, username):
    return username.lower() in {u.lower() for u in users.keys()}


def load_history(requesting_user):
    """#General is time-gated: a user only sees messages sent from the moment
    they joined onward (new/returning-offline members don't see the backlog).
    Announcements are always fully visible to everyone. DMs are unchanged."""
    with users_lock:
        users = load_users()
    joined_at = users.get(requesting_user, {}).get("joined_at", 0)

    with history_lock:
        if not HISTORY_FILE.exists():
            return []
        messages = []
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    m = json.loads(line)
                except json.JSONDecodeError:
                    continue
                recip = m.get("recipient")
                channel = m.get("channel", "general")
                if recip:
                    if recip != requesting_user and m.get("username") != requesting_user:
                        continue
                elif channel == "announcement":
                    pass  # always visible to everyone, regardless of join date
                else:
                    if m.get("ts", 0) < joined_at:
                        continue
                messages.append(m)
        return messages[-HISTORY_LIMIT:]


def find_message(message_id, requesting_user):
    """Look up a message by id, only if the requester is allowed to see it.
    Used to build safe, server-verified reply-quote previews (can't be forged)."""
    with history_lock:
        if not HISTORY_FILE.exists():
            return None
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    m = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if m.get("id") != message_id:
                    continue
                recip = m.get("recipient")
                if recip and recip != requesting_user and m.get("username") != requesting_user:
                    return None
                return m
    return None


def build_reply_preview(original):
    text = original.get("text") or ("[Image]" if original.get("media_url") else "")
    if len(text) > 120:
        text = text[:117] + "…"
    return {"id": original["id"], "username": original["username"], "text": text}


def append_history(message):
    with history_lock:
        with HISTORY_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(message, ensure_ascii=False) + "\n")


def delete_message_from_history(msg_id, username):
    """Returns the media_url of the deleted message (or True if none), or False if not found/not owner."""
    with history_lock:
        if not HISTORY_FILE.exists():
            return False
        lines = HISTORY_FILE.read_text(encoding="utf-8").strip().split('\n')
        new_lines = []
        deleted = False
        deleted_media_url = None
        for line in lines:
            if not line:
                continue
            try:
                m = json.loads(line)
                if m.get("id") == msg_id and m.get("username") == username:
                    deleted = True
                    deleted_media_url = m.get("media_url")
                    continue
                new_lines.append(line)
            except json.JSONDecodeError:
                continue
        if deleted:
            HISTORY_FILE.write_text("\n".join(new_lines) + ("\n" if new_lines else ""), encoding="utf-8")
            return deleted_media_url or True
        return False


def broadcast(event_type, payload, target_users=None):
    data = json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False)
    sse_chunk = f"data: {data}\n\n"
    with lock:
        dead = []
        for cid, q in subscribers.items():
            if target_users is not None:
                user_for_cid = online_users.get(cid)
                if user_for_cid not in target_users:
                    continue
            try:
                q.put_nowait(sse_chunk)
            except queue.Full:
                dead.append(cid)
        for cid in dead:
            subscribers.pop(cid, None)
            online_users.pop(cid, None)


def broadcast_user_list():
    with lock:
        names = sorted(set(online_users.values()))
    broadcast("users", names)


# ---------------------------------------------------------------------------
# HTML / CSS / JS
# ---------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HubChat</title>
<style>
  :root {
    --bg: #09090b;
    --panel: #18181b;
    --panel-2: #27272a;
    --border: #3f3f46;
    --text: #f4f4f5;
    --muted: #a1a1aa;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --bubble-me: #3b82f6;
    --bubble-other: #27272a;
    --radius: 18px;
    --active-bg: #3b82f6;
    --amber: #f59e0b;
  }

  * { box-sizing: border-box; }

  html, body {
    height: 100%; margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  }

  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--panel-2); border-radius: 10px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--border); }

  #app { display: flex; height: 100%; overflow: hidden; }

  #sidebar {
    width: 270px; background: var(--panel); border-right: 1px solid var(--border);
    padding: 20px 14px; display: flex; flex-direction: column; flex-shrink: 0;
    z-index: 2; overflow-y: auto;
  }

  #my-profile-row {
    display: flex; align-items: center; gap: 10px; padding: 10px 10px;
    border-radius: 12px; cursor: pointer; margin-bottom: 14px;
    background: var(--panel-2); transition: background 0.2s;
  }
  #my-profile-row:hover { background: var(--border); }

  #sidebar h1 {
    font-size: 19px; font-weight: 700; margin: 0 0 4px;
    background: linear-gradient(90deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }

  .section-label {
    color: var(--muted); font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.05em; font-weight: 700;
  }

  .section-header {
    display: flex; align-items: center; gap: 6px; padding: 8px 8px;
    margin-top: 12px; cursor: pointer; user-select: none; border-radius: 8px;
  }
  .section-header:hover { background: var(--panel-2); }
  .chevron { font-size: 10px; color: var(--muted); transition: transform 0.2s; display: inline-block; }
  .chevron.collapsed { transform: rotate(-90deg); }
  .count-badge { background: var(--panel-2); color: var(--muted); font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
  .count-badge.unread-total { background: var(--accent); color: #fff; }

  ul.nav-list { list-style: none; padding: 0; margin: 4px 0 0; }
  ul.nav-list li {
    padding: 9px 10px; border-radius: 10px; font-size: 13.5px; font-weight: 500;
    display: flex; align-items: center; gap: 10px; cursor: pointer;
    transition: background 0.15s ease; margin-bottom: 3px; color: var(--muted);
  }
  ul.nav-list li:hover { background: var(--panel-2); color: var(--text); }
  ul.nav-list li.active { background: var(--active-bg); font-weight: 600; color: #fff; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); }
  ul.nav-list li .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; flex-shrink: 0; box-shadow: 0 0 8px rgba(34, 197, 94, 0.5); }
  ul.nav-list li.active .dot { background: #fff; box-shadow: 0 0 8px rgba(255, 255, 255, 0.8); }

  ul.member-list, ul.dm-list {
    max-height: 240px; overflow-y: auto; transition: max-height 0.25s ease, margin 0.25s ease;
  }
  ul.member-list.collapsed, ul.dm-list.collapsed { max-height: 0; overflow: hidden; margin: 0; }

  .avatar-dot {
    position: relative; width: 32px; height: 32px; border-radius: 50%;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    background-size: cover; background-position: center;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 12.5px; color: #0b0b10; flex-shrink: 0;
  }
  .avatar-dot.large { width: 84px; height: 84px; font-size: 30px; margin: 0 auto; }
  .avatar-dot::after {
    content: ''; position: absolute; right: -1px; bottom: -1px; width: 10px; height: 10px;
    border-radius: 50%; background: var(--muted); border: 2px solid var(--panel);
  }
  .avatar-dot.online::after { background: #22c55e; box-shadow: 0 0 6px rgba(34, 197, 94, 0.6); }
  .avatar-dot.large::after { display: none; }
  .avatar-dot.bot-avatar { background: linear-gradient(135deg, #1e293b, #334155); font-size: 16px; }
  .bot-badge {
    background: linear-gradient(135deg, #a78bfa, #60a5fa); color: #0b0b10; font-size: 9px;
    font-weight: 800; padding: 1px 5px; border-radius: 6px; margin-left: 4px;
    letter-spacing: 0.03em; vertical-align: middle;
  }

  .dm-row-text { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .dm-name { font-weight: 600; color: var(--text); font-size: 13.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .dm-preview { font-size: 11.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

  .unread-badge {
    background: var(--accent); color: #fff; font-size: 11px; font-weight: 700;
    min-width: 18px; height: 18px; border-radius: 9px; display: flex; align-items: center;
    justify-content: center; padding: 0 5px; flex-shrink: 0; animation: pulse 1.6s ease-in-out infinite;
  }
  @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.15); } }

  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; position: relative; }

  #topbar {
    padding: 20px 32px; background: rgba(9, 9, 11, 0.8); backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border); display: flex; justify-content: space-between;
    align-items: center; position: absolute; top: 0; left: 0; right: 0; z-index: 10;
  }
  #topbar #chat-title { font-size: 16px; font-weight: 600; }
  #topbar .status { font-size: 13px; font-weight: 500; color: var(--muted); display: flex; align-items: center; gap: 6px; }
  #topbar .status::before { content: ''; display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #eab308; }
  #topbar .status.connected::before { background: #22c55e; }

  #messages {
    flex: 1; overflow-y: auto; padding: 90px 32px 24px;
    display: flex; flex-direction: column; gap: 6px; scroll-behavior: smooth;
    transition: opacity 0.12s ease;
  }

  .day-divider {
    align-self: center; color: var(--muted); font-size: 11.5px; font-weight: 700;
    letter-spacing: 0.05em; text-transform: uppercase; background: var(--panel-2);
    padding: 5px 14px; border-radius: 14px; margin: 18px 0 10px;
  }

  @keyframes slideIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

  .msg-row { display: flex; flex-direction: column; max-width: 70%; margin-bottom: 12px; position: relative; animation: slideIn 0.3s ease-out forwards; }
  .msg-row.me { align-self: flex-end; align-items: flex-end; }
  .msg-row.other { align-self: flex-start; align-items: flex-start; }
  .msg-row.announcement-row { max-width: 85%; align-self: center; }

  .announcement-header {
    display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: var(--amber);
    font-weight: 700; margin-bottom: 6px; padding: 0 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .msg-row.announcement-row .bubble {
    background: linear-gradient(135deg, rgba(245,158,11,0.14), rgba(245,158,11,0.04));
    border: 1px solid rgba(245,158,11,0.3);
  }

  .msg-meta { font-size: 12px; color: var(--muted); margin-bottom: 4px; padding: 0 4px; display: flex; gap: 10px; align-items: center; font-weight: 500; }
  .msg-time { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; opacity: 0.85; }

  .msg-actions { display: none; gap: 12px; opacity: 0; transition: opacity 0.2s; }
  .msg-row:hover .msg-actions { display: flex; opacity: 1; }
  .action-btn { background: none; border: none; color: var(--muted); font-size: 12px; font-weight: 500; cursor: pointer; padding: 0; transition: color 0.2s; }
  .action-btn:hover { color: var(--text); }
  .delete-btn:hover { color: #ef4444; }

  .reply-block {
    font-size: 13px; background: rgba(0,0,0,0.15); border-left: 3px solid rgba(255,255,255,0.5);
    padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; color: rgba(255,255,255,0.8);
  }
  .msg-row.other .reply-block { background: rgba(255,255,255,0.05); border-left-color: var(--accent); color: var(--muted); }
  .reply-block strong { color: #fff; }

  .bubble {
    padding: 12px 16px; border-radius: var(--radius); font-size: 15px;
    line-height: 1.5; white-space: pre-wrap; word-break: break-word;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  }
  .bubble img.chat-image { max-width: 320px; max-height: 320px; border-radius: 12px; display: block; cursor: zoom-in; margin-top: 8px; }

  .msg-row.me .bubble { background: var(--bubble-me); color: #fff; border-bottom-right-radius: 4px; }
  .msg-row.other .bubble { background: var(--bubble-other); color: var(--text); border-bottom-left-radius: 4px; }
  .msg-row.announcement-row .bubble { color: var(--text); border-radius: var(--radius); }

  .system-msg { align-self: center; color: var(--muted); font-size: 13px; font-weight: 500; margin: 16px 0; background: var(--panel-2); padding: 6px 16px; border-radius: 20px; }

  #jump-bottom-btn {
    position: absolute; bottom: 100px; left: 50%; transform: translateX(-50%);
    background: var(--accent); color: #fff; border: none; padding: 10px 18px; border-radius: 20px;
    font-size: 13px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 16px rgba(59,130,246,0.4);
    z-index: 5; align-items: center; gap: 6px;
  }
  #jump-bottom-btn:hover { background: var(--accent-hover); }

  #reply-preview {
    display: none; align-items: center; justify-content: space-between;
    padding: 12px 32px; background: var(--panel); border-top: 1px solid var(--border);
    font-size: 13px; color: var(--muted); font-weight: 500;
  }
  #reply-preview-close { background: var(--panel-2); border: none; color: var(--text); cursor: pointer; font-size: 16px; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; transition: background 0.2s; }
  #reply-preview-close:hover { background: var(--border); }

  #upload-preview { display: none; align-items: center; gap: 12px; padding: 0 32px 12px; color: var(--muted); font-size: 13px; font-weight: 500; }
  #upload-preview img { height: 48px; width: 48px; object-fit: cover; border-radius: 8px; border: 2px solid var(--border); }

  #composer { display: flex; gap: 12px; padding: 16px 32px 24px; background: var(--bg); border-top: 1px solid var(--border); }

  #attach-btn {
    background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    width: 48px; height: 48px; border-radius: 50%; font-size: 18px; cursor: pointer;
    display: flex; align-items: center; justify-content: center; transition: all 0.2s;
  }
  #attach-btn:hover { background: var(--border); transform: scale(1.05); }

  #composer input[type=text] {
    flex: 1; background: var(--panel); border: 1px solid var(--border); color: var(--text);
    padding: 0 20px; border-radius: 24px; font-size: 15px; outline: none; transition: border-color 0.2s;
  }
  #composer input[type=text]:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }

  #send-btn {
    background: var(--accent); color: white; border: none; padding: 0 24px; height: 48px;
    border-radius: 24px; font-size: 15px; font-weight: 600; cursor: pointer;
    transition: all 0.2s; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
  }
  #send-btn:hover { background: var(--accent-hover); transform: translateY(-1px); }

  #logout-btn {
    margin-top: 14px; padding: 12px; border-radius: 12px; background: transparent;
    border: 1px solid var(--border); color: var(--muted); cursor: pointer; font-weight: 600;
    transition: all 0.2s; font-size: 14px;
  }
  #logout-btn:hover { background: #ef4444; color: white; border-color: #ef4444; }

  #login-overlay {
    position: fixed; inset: 0; background: radial-gradient(circle at 20% 20%, #1e2a4a 0%, #0f0f12 45%, #09090b 100%);
    display: flex; align-items: center; justify-content: center; z-index: 100;
  }
  #login-overlay::before { content: ''; position: absolute; inset: 0; background: rgba(9, 9, 11, 0.35); backdrop-filter: blur(6px); }

  #login-card {
    background: rgba(24, 24, 27, 0.6); border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 24px; padding: 40px; width: 340px; text-align: center;
    position: relative; z-index: 101; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
  }
  #login-card h2 { margin: 0 0 24px; font-size: 28px; font-weight: 700; background: linear-gradient(90deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

  #login-tabs { display: flex; margin-bottom: 24px; background: rgba(0,0,0,0.2); border-radius: 12px; padding: 4px; }
  .tab-btn { flex: 1; background: none; border: none; color: var(--muted); padding: 10px; cursor: pointer; font-weight: 600; font-size: 14px; border-radius: 8px; transition: all 0.2s; }
  .tab-btn.active { background: var(--panel-2); color: var(--text); box-shadow: 0 2px 4px rgba(0,0,0,0.2); }

  #login-card input {
    width: 100%; margin-bottom: 16px; padding: 14px 16px; border-radius: 12px; font-size: 15px;
    border: 1px solid rgba(255, 255, 255, 0.1); background: rgba(0,0,0,0.2); color: var(--text);
    outline: none; transition: border-color 0.2s;
  }
  #login-card input:focus { border-color: var(--accent); }

  #login-card button.action-main {
    width: 100%; padding: 14px; background: var(--accent); border: none; cursor: pointer;
    border-radius: 12px; color: white; font-weight: 600; font-size: 15px;
    transition: all 0.2s; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3); margin-top: 8px;
  }
  #login-card button.action-main:hover { background: var(--accent-hover); transform: translateY(-1px); }

  .login-error { color: #ef4444; font-size: 13px; font-weight: 500; margin-top: 16px; background: rgba(239, 68, 68, 0.1); padding: 8px; border-radius: 8px; border: 1px solid rgba(239, 68, 68, 0.2); }

  #profile-modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: none; align-items: center; justify-content: center; z-index: 200; }
  #profile-modal { background: var(--panel); border: 1px solid var(--border); border-radius: 20px; padding: 32px; width: 320px; text-align: center; position: relative; box-shadow: 0 25px 50px -12px rgba(0,0,0,.6); }
  #profile-close { position: absolute; top: 14px; right: 14px; background: var(--panel-2); border: none; color: var(--text); width: 28px; height: 28px; border-radius: 50%; cursor: pointer; font-size: 16px; }
  #profile-name { margin: 16px 0 4px; font-size: 19px; font-weight: 700; }
  .profile-meta { color: var(--muted); font-size: 12.5px; margin-bottom: 16px; }
  .profile-bio { font-size: 14px; color: var(--text); line-height: 1.5; margin-bottom: 20px; white-space: pre-wrap; }
  #profile-bio-edit {
    width: 100%; min-height: 80px; background: var(--panel-2); border: 1px solid var(--border);
    color: var(--text); border-radius: 10px; padding: 10px 12px; font-size: 14px;
    font-family: inherit; resize: vertical; margin-bottom: 16px;
  }
  #profile-avatar-edit-btn {
    background: var(--panel-2); border: 1px solid var(--border); color: var(--text);
    font-size: 12px; padding: 6px 12px; border-radius: 10px; cursor: pointer; margin-top: 10px;
  }
  #profile-avatar-edit-btn:hover { background: var(--border); }
</style>
</head>
<body>

<div id="login-overlay">
  <div id="login-card">
    <h2>HubChat</h2>
    <div id="login-tabs">
      <button class="tab-btn active" data-tab="signin">Sign In</button>
      <button class="tab-btn" data-tab="register">Sign Up</button>
    </div>
    <div id="signin-panel">
      <input id="signin-username" type="text" placeholder="Username" autocomplete="off">
      <input id="signin-password" type="password" placeholder="Password">
      <button id="signin-btn" class="action-main">Sign in</button>
    </div>
    <div id="register-panel" style="display:none;">
      <input id="register-username" type="text" placeholder="Choose username" autocomplete="off">
      <input id="register-password" type="password" placeholder="Choose password">
      <input id="register-code" type="text" placeholder="Hub access code" autocomplete="off">
      <button id="register-btn" class="action-main">Create account</button>
    </div>
    <p id="login-error" class="login-error" style="display:none;"></p>
  </div>
</div>

<div id="app" style="display:none;">
  <div id="sidebar">
    <h1>HubChat</h1>

    <div id="my-profile-row">
      <span class="avatar-dot online" id="my-avatar"></span>
      <div class="dm-row-text">
        <span class="dm-name" id="my-name-label"></span>
        <span class="dm-preview">View / edit your profile</span>
      </div>
    </div>

    <ul class="nav-list" id="channellist">
       <li id="btn-general" class="active" onclick="switchChat('general')"><span class="dot"></span># General</li>
       <li id="btn-announcements" onclick="switchChat('announcement')"><span class="dot" style="background:#f59e0b;box-shadow:0 0 8px rgba(245,158,11,.5);"></span>📢 Announcements</li>
    </ul>

    <div class="section-header" onclick="toggleSection('online')">
      <span class="chevron" id="chev-online">▾</span>
      <span class="section-label">Online Members</span>
      <span class="count-badge" id="online-count">0</span>
    </div>
    <ul class="nav-list member-list" id="onlinelist"></ul>

    <div class="section-header" onclick="toggleSection('total')">
      <span class="chevron" id="chev-total">▾</span>
      <span class="section-label">Total Members</span>
      <span class="count-badge" id="total-count">0</span>
    </div>
    <ul class="nav-list member-list" id="totallist"></ul>

    <div class="section-header" onclick="toggleSection('dm')">
      <span class="chevron" id="chev-dm">▾</span>
      <span class="section-label">Private Chats</span>
      <span class="count-badge unread-total" id="dm-total-badge" style="display:none;"></span>
    </div>
    <ul class="nav-list dm-list" id="dmlist"></ul>

    <button id="logout-btn">Sign out</button>
  </div>
  <div id="main">
    <div id="topbar">
      <strong id="chat-title"># General</strong>
      <span id="status" class="status disconnected">Connecting...</span>
    </div>
    <div id="messages"></div>
    <button id="jump-bottom-btn" style="display:none;" onclick="jumpToBottom()">↓ New messages</button>

    <div id="reply-preview">
        <span id="reply-preview-text"></span>
        <button id="reply-preview-close">×</button>
    </div>

    <div id="upload-preview">
      <img id="upload-preview-img" src="">
      <span id="upload-preview-name"></span>
      <button id="upload-cancel" style="background:none;border:none;color:var(--muted);cursor:pointer;font-weight:600;">Remove</button>
    </div>
    <div id="composer">
      <input id="file-input" type="file" accept="image/*" style="display:none;">
      <button id="attach-btn" title="Attach an image">📎</button>
      <input id="text-input" type="text" placeholder="Type a message..." autocomplete="off">
      <button id="send-btn">Send</button>
    </div>
  </div>
</div>

<div id="profile-modal-overlay" onclick="if(event.target===this) closeProfile()">
  <div id="profile-modal">
    <button id="profile-close" onclick="closeProfile()">×</button>
    <span class="avatar-dot large" id="profile-avatar"></span>
    <div>
      <input id="avatar-file-input" type="file" accept="image/*" style="display:none;">
      <button id="profile-avatar-edit-btn" style="display:none;" onclick="document.getElementById('avatar-file-input').click()">Change photo</button>
    </div>
    <h3 id="profile-name"></h3>
    <div id="profile-joined" class="profile-meta"></div>
    <div id="profile-bio-view" class="profile-bio"></div>
    <textarea id="profile-bio-edit" style="display:none;" maxlength="300" placeholder="Write a short bio..."></textarea>
    <button id="profile-save-btn" class="action-main" style="display:none;">Edit profile</button>
    <button id="profile-message-btn" class="action-main" style="display:none;">Send message</button>
  </div>
</div>

<script>
const TOKEN_KEY = "hubchat_token";
const USERNAME_KEY = "hubchat_username";
let token = localStorage.getItem(TOKEN_KEY) || "";
let username = localStorage.getItem(USERNAME_KEY) || "";
let clientId = localStorage.getItem("hubchat_client_id") || (Math.random().toString(36).slice(2) + Date.now().toString(36));
localStorage.setItem("hubchat_client_id", clientId);

let allMessages = [];
let currentChat = 'general';   // 'general' | 'announcement' | <username string> for a DM
let onlineUsers = [];
let fullRoster = [];           // [{username, avatar_url, bio, joined_at, online}]
let dmLastSeen = JSON.parse(localStorage.getItem('hubchat_dm_lastseen') || '{}');
let collapsedSections = JSON.parse(localStorage.getItem('hubchat_collapsed') || '{}');
let lastRenderedDateKey = null;
let profileViewingUser = null;
let profileEditing = false;
let pendingAvatarUrl = null;
let pendingMediaUrl = null;
let replyingToData = null;
let audioCtx = null;

function saveDmLastSeen() { localStorage.setItem('hubchat_dm_lastseen', JSON.stringify(dmLastSeen)); }
function saveCollapsed() { localStorage.setItem('hubchat_collapsed', JSON.stringify(collapsedSections)); }
function authHeaders(extra) { return Object.assign({ "Authorization": "Bearer " + token }, extra || {}); }
function escapeHtml(s) { const d = document.createElement("div"); d.innerText = s ?? ""; return d.innerHTML; }
function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
function fmtDateHeader(ts) { return new Date(ts * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' }); }
function fmtFullDateTime(ts) { return new Date(ts * 1000).toLocaleString([], { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function dateKey(ts) { return new Date(ts * 1000).toDateString(); }
function initials(name) { return (name || "?").charAt(0).toUpperCase(); }

// --- Notification sound (synthesized, no external audio file needed) ---
function ensureAudioContext() {
  if (!audioCtx) { try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) {} }
  return audioCtx;
}
function playNotificationSound() {
  const ctx = ensureAudioContext();
  if (!ctx) return;
  try {
    if (ctx.state === 'suspended') ctx.resume();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination);
    o.type = 'sine';
    const now = ctx.currentTime;
    o.frequency.setValueAtTime(880, now);
    o.frequency.exponentialRampToValueAtTime(1108, now + 0.09);
    g.gain.setValueAtTime(0.0001, now);
    g.gain.exponentialRampToValueAtTime(0.22, now + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, now + 0.28);
    o.start(now); o.stop(now + 0.3);
  } catch (e) {}
}
document.addEventListener('click', () => { const c = ensureAudioContext(); if (c && c.state === 'suspended') c.resume(); }, { once: true });

// --- Auth ---
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("signin-panel").style.display = btn.dataset.tab === "signin" ? "block" : "none";
    document.getElementById("register-panel").style.display = btn.dataset.tab === "register" ? "block" : "none";
    document.getElementById("login-error").style.display = "none";
  };
});

async function auth(url, body) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) { document.getElementById("login-error").textContent = data.error; document.getElementById("login-error").style.display = "block"; return; }
  token = data.token; username = data.username;
  localStorage.setItem(TOKEN_KEY, token); localStorage.setItem(USERNAME_KEY, username);
  startApp();
}
document.getElementById("signin-btn").onclick = () => { ensureAudioContext(); auth("/login", { username: document.getElementById("signin-username").value, password: document.getElementById("signin-password").value }); };
document.getElementById("register-btn").onclick = () => { ensureAudioContext(); auth("/register", { username: document.getElementById("register-username").value, password: document.getElementById("register-password").value, access_code: document.getElementById("register-code").value }); };
document.getElementById("logout-btn").onclick = () => { localStorage.clear(); location.reload(); };

// --- Collapsible sections ---
function toggleSection(name) {
  collapsedSections[name] = !collapsedSections[name];
  saveCollapsed();
  applyCollapsedState();
}
function applyCollapsedState() {
  [["online", "onlinelist"], ["total", "totallist"], ["dm", "dmlist"]].forEach(([name, listId]) => {
    const collapsed = !!collapsedSections[name];
    document.getElementById(listId).classList.toggle('collapsed', collapsed);
    document.getElementById('chev-' + name).classList.toggle('collapsed', collapsed);
  });
}

// --- Roster ---
async function loadRoster() {
  try {
    const res = await fetch("/roster", { headers: authHeaders() });
    if (res.ok) fullRoster = await res.json();
  } catch (e) {}
}

// --- Channel/DM switching ---
function switchChat(target) {
    if (target === username) return;
    currentChat = target;
    lastRenderedDateKey = null;

    let title = "# General";
    if (target === 'announcement') title = "📢 Announcements";
    else if (target !== 'general') title = `Private: @${escapeHtml(target)}`;
    document.getElementById("chat-title").innerHTML = title;

    document.getElementById("btn-general").classList.toggle("active", target === 'general');
    document.getElementById("btn-announcements").classList.toggle("active", target === 'announcement');

    if (target !== 'general' && target !== 'announcement') {
      dmLastSeen[target] = Date.now() / 1000;
      saveDmLastSeen();
    }

    renderMembersLists();
    replyingToData = null;
    document.getElementById("reply-preview").style.display = "none";

    const container = document.getElementById("messages");
    container.style.opacity = "0";
    renderAllMessages();
    hideJumpButton();
    requestAnimationFrame(() => { container.style.opacity = "1"; });
}

function messageBelongsToCurrentView(m) {
    if (m.system) return currentChat === 'general';
    if (currentChat === 'general') return !m.recipient && (m.channel || 'general') === 'general';
    if (currentChat === 'announcement') return !m.recipient && m.channel === 'announcement';
    return (m.recipient === currentChat && m.username === username) ||
           (m.username === currentChat && m.recipient === username);
}

// --- Reply / unsend ---
const replyPreview = document.getElementById("reply-preview");
const replyPreviewText = document.getElementById("reply-preview-text");
function setReply(msg) {
    replyingToData = { id: msg.id, username: msg.username, text: msg.text || (msg.media_url ? "[Image]" : "") };
    replyPreviewText.innerHTML = `Replying to <strong>${escapeHtml(msg.username)}</strong>: ${escapeHtml(replyingToData.text)}`;
    replyPreview.style.display = "flex";
    document.getElementById("text-input").focus();
}
document.getElementById("reply-preview-close").onclick = () => { replyingToData = null; replyPreview.style.display = "none"; };

async function unsendMessage(id) {
    if (!confirm("Unsend this message for everyone?")) return;
    await fetch("/delete", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ id }) });
}

// --- Message rendering (incremental append, not full-rebuild, so it won't lag as history grows) ---
function maybeInsertDayDivider(ts) {
    const key = dateKey(ts);
    if (key !== lastRenderedDateKey) {
        lastRenderedDateKey = key;
        const div = document.createElement("div");
        div.className = "day-divider";
        div.textContent = fmtDateHeader(ts);
        document.getElementById("messages").appendChild(div);
    }
}

function renderAllMessages() {
    const container = document.getElementById("messages");
    container.innerHTML = "";
    lastRenderedDateKey = null;
    allMessages.filter(messageBelongsToCurrentView).forEach(m => renderMessageNode(m));
    scrollToBottom(true);
}

function renderMessageNode(m) {
  const container = document.getElementById("messages");
  if (m.system) {
    maybeInsertDayDivider(m.ts);
    const row = document.createElement("div"); row.className = "system-msg"; row.textContent = m.text;
    container.appendChild(row);
    return;
  }
  maybeInsertDayDivider(m.ts);

  const isAnnouncement = !m.recipient && m.channel === 'announcement';
  const row = document.createElement("div");
  row.className = "msg-row " + (m.username === username ? "me" : "other") + (isAnnouncement ? " announcement-row" : "");
  row.id = "msg-" + m.id;

  if (isAnnouncement) {
    const header = document.createElement("div");
    header.className = "announcement-header";
    header.innerHTML = `📢 ${escapeHtml(m.username)} · ${fmtFullDateTime(m.ts)}`;
    row.appendChild(header);
  }

  const meta = document.createElement("div");
  meta.className = "msg-meta";
  meta.innerHTML = `<span>${m.username === username ? "You" : escapeHtml(m.username)}</span><span class="msg-time">${fmtTime(m.ts)}</span>`;

  const actions = document.createElement("div");
  actions.className = "msg-actions";
  actions.innerHTML = `<button class="action-btn" onclick='setReply(${JSON.stringify(m).replace(/'/g, "&#39;")})'>Reply</button>`;
  if (m.username === username) {
      actions.innerHTML += `<button class="action-btn delete-btn" onclick="unsendMessage('${m.id}')">Delete</button>`;
  }
  if (m.username === username) { meta.prepend(actions); } else { meta.appendChild(actions); }

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (m.reply_to) {
      const rb = document.createElement("div");
      rb.className = "reply-block";
      rb.innerHTML = `<strong>${escapeHtml(m.reply_to.username)}:</strong> ${escapeHtml(m.reply_to.text)}`;
      bubble.appendChild(rb);
  }
  if (m.media_url) {
    const img = document.createElement("img"); img.className = "chat-image"; img.src = m.media_url;
    bubble.appendChild(img);
  }
  if (m.text) {
    const txt = document.createElement("div"); txt.innerHTML = escapeHtml(m.text);
    bubble.appendChild(txt);
  }

  row.appendChild(meta);
  row.appendChild(bubble);
  container.appendChild(row);
}

// --- Scroll handling: don't yank the user to the bottom while they're reading old messages ---
function isNearBottom() {
  const m = document.getElementById("messages");
  return (m.scrollHeight - m.scrollTop - m.clientHeight) < 80;
}
function scrollToBottom(force) {
    const m = document.getElementById("messages");
    if (force || isNearBottom()) { m.scrollTop = m.scrollHeight; hideJumpButton(); }
}
function showJumpButton() { document.getElementById("jump-bottom-btn").style.display = "flex"; }
function hideJumpButton() { document.getElementById("jump-bottom-btn").style.display = "none"; }
function jumpToBottom() { const m = document.getElementById("messages"); m.scrollTop = m.scrollHeight; hideJumpButton(); }
document.getElementById("messages").addEventListener('scroll', () => { if (isNearBottom()) hideJumpButton(); });

// --- Members / DM inbox rendering ---
function getDmPartnerTimestamps() {
  const lastTs = {};
  allMessages.forEach(m => {
    if (m.system || !m.recipient) return;
    const partner = m.username === username ? m.recipient : (m.recipient === username ? m.username : null);
    if (!partner) return;
    if (!lastTs[partner] || m.ts > lastTs[partner]) lastTs[partner] = m.ts;
  });
  return lastTs;
}

function computeDmStats() {
  const lastTs = getDmPartnerTimestamps();
  const stats = {};
  Object.keys(lastTs).forEach(p => { stats[p] = { lastTs: lastTs[p], lastText: '', unread: 0 }; });
  allMessages.forEach(m => {
    if (m.system || !m.recipient) return;
    const partner = m.username === username ? m.recipient : (m.recipient === username ? m.username : null);
    if (!partner) return;
    if (m.ts === stats[partner].lastTs) {
      let preview = (m.media_url && !m.text) ? '📷 Photo' : (m.text || '');
      if (m.username === username) preview = 'You: ' + preview;
      stats[partner].lastText = preview;
    }
    if (m.recipient === username && m.username !== username && partner !== currentChat) {
      const seen = dmLastSeen[partner] || 0;
      if (m.ts > seen) stats[partner].unread++;
    }
  });
  return stats;
}

function renderAvatarSpan(name, url, online) {
  const style = url ? ` style="background-image:url('${url}')"` : '';
  const isBot = name === 'HubBot';
  const inner = url ? '' : (isBot ? '🤖' : escapeHtml(initials(name)));
  const onlineClass = online ? ' online' : '';
  const botClass = isBot ? ' bot-avatar' : '';
  return `<span class="avatar-dot${onlineClass}${botClass}"${style}>${inner}</span>`;
}

function renderMembersLists() {
  const others = fullRoster.filter(r => r.username !== username);

  const onlineList = others.filter(r => onlineUsers.includes(r.username));
  document.getElementById("online-count").textContent = onlineList.length;
  document.getElementById("onlinelist").innerHTML = onlineList.map(r => `
    <li onclick="openProfile('${r.username}')">
      ${renderAvatarSpan(r.username, r.avatar_url, true)}
      <div class="dm-row-text"><span class="dm-name">${escapeHtml(r.username)}</span></div>
    </li>`).join('') || '<li style="cursor:default;color:var(--muted);font-size:12.5px;">No one else is online</li>';

  document.getElementById("total-count").textContent = others.length;
  document.getElementById("totallist").innerHTML = others.map(r => `
    <li onclick="openProfile('${r.username}')">
      ${renderAvatarSpan(r.username, r.avatar_url, r.username === 'HubBot' ? true : onlineUsers.includes(r.username))}
      <div class="dm-row-text"><span class="dm-name">${escapeHtml(r.username)}${r.username === 'HubBot' ? ' <span class="bot-badge">BOT</span>' : ''}</span></div>
    </li>`).join('') || '<li style="cursor:default;color:var(--muted);font-size:12.5px;">No members yet</li>';

  const stats = computeDmStats();
  const partners = Object.keys(stats).sort((a, b) => stats[b].lastTs - stats[a].lastTs);
  let totalUnread = 0;
  document.getElementById("dmlist").innerHTML = partners.map(p => {
    const s = stats[p];
    totalUnread += s.unread;
    const rec = fullRoster.find(r => r.username === p);
    const isActive = p === currentChat ? "active" : "";
    return `<li class="${isActive}" onclick="switchChat('${p}')">
      ${renderAvatarSpan(p, rec ? rec.avatar_url : null, p === 'HubBot' ? true : onlineUsers.includes(p))}
      <div class="dm-row-text">
        <span class="dm-name">${escapeHtml(p)}${p === 'HubBot' ? ' <span class="bot-badge">BOT</span>' : ''}</span>
        <span class="dm-preview">${escapeHtml(s.lastText)}</span>
      </div>
      ${s.unread > 0 ? `<span class="unread-badge">${s.unread > 9 ? '9+' : s.unread}</span>` : ''}
    </li>`;
  }).join('') || '<li style="cursor:default;color:var(--muted);font-size:12.5px;">No conversations yet — tap a member to start one</li>';

  const totalBadge = document.getElementById("dm-total-badge");
  if (totalUnread > 0) { totalBadge.textContent = totalUnread > 9 ? '9+' : totalUnread; totalBadge.style.display = 'inline-flex'; }
  else totalBadge.style.display = 'none';

  const me = fullRoster.find(r => r.username === username);
  const myAvatarEl = document.getElementById("my-avatar");
  if (myAvatarEl) {
    if (me && me.avatar_url) { myAvatarEl.style.backgroundImage = `url('${me.avatar_url}')`; myAvatarEl.textContent = ''; }
    else { myAvatarEl.style.backgroundImage = ''; myAvatarEl.textContent = initials(username); }
  }
  document.getElementById("my-name-label").textContent = username;
}

// --- Profile modal ---
function openProfile(user) {
    profileViewingUser = user;
    const rec = fullRoster.find(r => r.username === user) || { username: user, avatar_url: null, bio: '', joined_at: 0 };
    const isSelf = user === username;
    profileEditing = false;
    pendingAvatarUrl = null;

    const avatarEl = document.getElementById("profile-avatar");
    if (rec.avatar_url) { avatarEl.style.backgroundImage = `url('${rec.avatar_url}')`; avatarEl.textContent = ''; }
    else { avatarEl.style.backgroundImage = ''; avatarEl.textContent = initials(user); }

    document.getElementById("profile-name").textContent = user;
    document.getElementById("profile-joined").textContent = rec.joined_at
        ? `Member since ${new Date(rec.joined_at * 1000).toLocaleDateString([], { month: 'long', year: 'numeric' })}`
        : 'Member';

    document.getElementById("profile-bio-view").textContent = rec.bio && rec.bio.trim() ? rec.bio : (isSelf ? "You haven't added a bio yet." : "No bio yet.");
    document.getElementById("profile-bio-view").style.display = "block";
    document.getElementById("profile-bio-edit").style.display = "none";
    document.getElementById("profile-bio-edit").value = rec.bio || "";

    document.getElementById("profile-avatar-edit-btn").style.display = isSelf ? "inline-block" : "none";
    document.getElementById("profile-save-btn").style.display = isSelf ? "block" : "none";
    document.getElementById("profile-save-btn").textContent = "Edit profile";
    document.getElementById("profile-message-btn").style.display = isSelf ? "none" : "block";

    document.getElementById("profile-modal-overlay").style.display = "flex";
}
function closeProfile() { document.getElementById("profile-modal-overlay").style.display = "none"; profileEditing = false; }

document.getElementById("profile-message-btn").onclick = () => { if (profileViewingUser) switchChat(profileViewingUser); closeProfile(); };

document.getElementById("profile-save-btn").onclick = async () => {
    if (!profileEditing) {
        profileEditing = true;
        document.getElementById("profile-bio-view").style.display = "none";
        document.getElementById("profile-bio-edit").style.display = "block";
        document.getElementById("profile-save-btn").textContent = "Save changes";
        return;
    }
    const bio = document.getElementById("profile-bio-edit").value.trim();
    const payload = { bio };
    if (pendingAvatarUrl) payload.avatar_url = pendingAvatarUrl;
    await fetch("/profile", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(payload) });
    await loadRoster();
    renderMembersLists();
    closeProfile();
};

document.getElementById("avatar-file-input").onchange = async (e) => {
    const file = e.target.files[0]; if (!file) return;
    const formData = new FormData(); formData.append("file", file);
    const res = await fetch("/upload", { method: "POST", headers: authHeaders(), body: formData });
    if (!res.ok) return;
    const data = await res.json();
    pendingAvatarUrl = data.url;
    const avatarEl = document.getElementById("profile-avatar");
    avatarEl.style.backgroundImage = `url('${data.url}')`;
    avatarEl.textContent = '';
};

document.getElementById("my-profile-row").onclick = () => openProfile(username);

// --- Live updates ---
function connectStream() {
  const statusEl = document.getElementById("status");
  const es = new EventSource("/events?token=" + encodeURIComponent(token));
  es.onopen = () => { statusEl.textContent = "Connected"; statusEl.className = "status connected"; };
  es.onerror = () => {
    if (es.readyState === EventSource.CLOSED) {
      // The browser gave up retrying - this happens when the server rejects the
      // connection outright (e.g. a server restart cleared everyone's session).
      // A transient network blip leaves readyState as CONNECTING and the browser
      // retries on its own, so we only act here on a truly dead connection.
      es.close();
      fetch("/whoami", { headers: authHeaders() }).then(res => {
        if (!res.ok) {
          localStorage.removeItem(TOKEN_KEY);
          localStorage.removeItem(USERNAME_KEY);
          document.getElementById("app").style.display = "none";
          document.getElementById("login-overlay").style.display = "flex";
          const err = document.getElementById("login-error");
          err.textContent = "Your session expired (the server may have restarted). Please sign in again.";
          err.style.display = "block";
        }
      }).catch(() => {});
    } else {
      statusEl.textContent = "Reconnecting...";
      statusEl.className = "status disconnected";
    }
  };
  es.onmessage = (e) => {
    const evt = JSON.parse(e.data);
    if (evt.type === "message") {
        allMessages.push(evt.payload);
        const belongs = messageBelongsToCurrentView(evt.payload);
        if (belongs) {
          const wasNearBottom = isNearBottom();
          renderMessageNode(evt.payload);
          if (evt.payload.username === username || wasNearBottom) { scrollToBottom(true); }
          else { showJumpButton(); }
        }
        if (evt.payload.recipient) {
          const isIncomingDm = evt.payload.recipient === username && evt.payload.username !== username;
          if (isIncomingDm) {
            if (evt.payload.username !== currentChat) playNotificationSound();
            else { dmLastSeen[evt.payload.username] = evt.payload.ts; saveDmLastSeen(); }
          }
          renderMembersLists();
        }
    }
    else if (evt.type === "delete") {
        const deleted = allMessages.find(m => m.id === evt.payload.id);
        allMessages = allMessages.filter(m => m.id !== evt.payload.id);
        const row = document.getElementById("msg-" + evt.payload.id);
        if (row) row.remove();
        if (deleted && deleted.recipient) renderMembersLists();
    }
    else if (evt.type === "users") {
      onlineUsers = evt.payload;
      renderMembersLists();
    }
  };
}

// --- Composer ---
document.getElementById("attach-btn").onclick = () => document.getElementById("file-input").click();
document.getElementById("file-input").onchange = async (e) => {
  const file = e.target.files[0]; if (!file) return;
  const formData = new FormData(); formData.append("file", file);
  const res = await fetch("/upload", { method: "POST", headers: authHeaders(), body: formData });
  const data = await res.json();
  pendingMediaUrl = data.url;
  document.getElementById("upload-preview-img").src = data.url;
  document.getElementById("upload-preview-name").textContent = file.name;
  document.getElementById("upload-preview").style.display = "flex";
};
document.getElementById("upload-cancel").onclick = () => { pendingMediaUrl = null; document.getElementById("upload-preview").style.display = "none"; };

async function sendMessage() {
  const text = document.getElementById("text-input").value.trim();
  if (!text && !pendingMediaUrl) return;
  document.getElementById("text-input").value = "";

  const payload = { text, client_id: clientId, media_url: pendingMediaUrl };
  if (currentChat === 'announcement') payload.channel = 'announcement';
  else if (currentChat !== 'general') payload.recipient = currentChat;
  if (replyingToData) payload.reply_to_id = replyingToData.id;

  await fetch("/send", { method: "POST", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(payload) });

  pendingMediaUrl = null;
  replyingToData = null;
  document.getElementById("upload-preview").style.display = "none";
  document.getElementById("reply-preview").style.display = "none";
}
document.getElementById("send-btn").onclick = sendMessage;
document.getElementById("text-input").onkeydown = (e) => { if (e.key === "Enter") sendMessage(); };

// --- Boot ---
async function startApp() {
  document.getElementById("login-overlay").style.display = "none";
  document.getElementById("app").style.display = "flex";
  document.getElementById("my-name-label").textContent = username;
  applyCollapsedState();

  await loadRoster();

  const res = await fetch("/history", { headers: authHeaders() });
  if (!res.ok) {
    localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USERNAME_KEY);
    document.getElementById("login-overlay").style.display = "flex";
    document.getElementById("app").style.display = "none";
    return;
  }
  allMessages = await res.json();
  if (!Array.isArray(allMessages)) allMessages = [];

  const initialTs = getDmPartnerTimestamps();
  Object.keys(initialTs).forEach(p => { if (!(p in dmLastSeen)) dmLastSeen[p] = initialTs[p]; });
  saveDmLastSeen();

  renderAllMessages();
  renderMembersLists();
  connectStream();
}

async function tryResumeSession() {
  if (!token || !username) return;
  try {
    const res = await fetch("/whoami", { headers: authHeaders() });
    if (res.ok) startApp();
    else { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USERNAME_KEY); }
  } catch (e) { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USERNAME_KEY); }
}
tryResumeSession();
</script>
</body>
</html>
"""

def parse_multipart_file(body, content_type):
    m = re.search(r'boundary=([^;]+)', content_type)
    if not m:
        return None, None
    delimiter = b"--" + m.group(1).strip().strip('"').encode()
    for part in body.split(delimiter):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        headers_raw, data = part.split(b"\r\n\r\n", 1)
        fm = re.search(r'filename="([^"]*)"', headers_raw.decode(errors="ignore"))
        if fm and fm.group(1):
            if data.endswith(b"\r\n"):
                data = data[:-2]
            return fm.group(1), data
    return None, None

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "HubChat/1.4"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (time.strftime("%H:%M:%S"), fmt % args))

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/history":
            username = self._get_authed_username()
            if username is None:
                self._send_json(401, {"error": "not signed in"})
                return
            self._send_json(200, load_history(username))
        elif self.path.startswith("/events"):
            self._handle_sse()
        elif self.path.startswith("/uploads/"):
            self._serve_upload()
        elif self.path == "/whoami":
            u = self._get_authed_username()
            if u is None:
                self._send_json(401, {"error": "not signed in"})
            else:
                self._send_json(200, {"username": u})
        elif self.path == "/roster":
            u = self._get_authed_username()
            if u is None:
                self._send_json(401, {"error": "not signed in"})
                return
            with users_lock:
                users = load_users()
            with lock:
                online_names = set(online_users.values())
            roster = [{
                "username": BOT_USERNAME,
                "avatar_url": None,
                "bio": "Ask me anything — I'm an AI assistant." if ANTHROPIC_API_KEY
                       else "AI assistant (not yet configured by your hub admin).",
                "joined_at": 0,
                "online": True,
            }]
            for name, rec in sorted(users.items(), key=lambda kv: kv[0].lower()):
                roster.append({
                    "username": name,
                    "avatar_url": rec.get("avatar_url"),
                    "bio": rec.get("bio", ""),
                    "joined_at": rec.get("joined_at", 0),
                    "online": name in online_names,
                })
            self._send_json(200, roster)
        else:
            self.send_response(404)
            self.end_headers()

    def _get_authed_username(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[len("Bearer "):].strip()
            with users_lock:
                return sessions.get(token)
        return None

    def _serve_upload(self):
        name = self.path[len("/uploads/"):].split("?")[0]
        if "/" in name or "\\" in name or ".." in name:
            self.send_response(400)
            self.end_headers()
            return
        filepath = UPLOAD_DIR / name
        if not filepath.is_file():
            self.send_response(404)
            self.end_headers()
            return
        ctype = mimetypes.guess_type(str(filepath))[0] or "application/octet-stream"
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _handle_sse(self):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        token = (qs.get("token") or [""])[0]
        with users_lock:
            username = sessions.get(token)
        if not username:
            self._send_json(401, {"error": "not signed in"})
            return

        client_id = (qs.get("client_id") or [str(uuid.uuid4())])[0]
        q = queue.Queue(maxsize=100)
        with lock:
            subscribers[client_id] = q
            online_users[client_id] = username

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        broadcast("message", {"system": True, "text": f"{username} joined the hub"})
        broadcast_user_list()

        try:
            while True:
                try:
                    chunk = q.get(timeout=15)
                    self.wfile.write(chunk.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with lock:
                subscribers.pop(client_id, None)
                online_users.pop(client_id, None)
            broadcast("message", {"system": True, "text": f"{username} left the hub"})
            broadcast_user_list()

    def do_POST(self):
        if self.path == "/register":
            self._handle_register()

        elif self.path == "/login":
            self._handle_login()

        elif self.path == "/profile":
            username = self._get_authed_username()
            if username is None:
                self._send_json(401, {"error": "not signed in"})
                return
            data = self._read_json_body()
            if data is None:
                self._send_json(400, {"error": "invalid request"})
                return
            with users_lock:
                users = load_users()
                if username not in users:
                    self._send_json(404, {"error": "account not found"})
                    return
                if "bio" in data:
                    users[username]["bio"] = str(data.get("bio") or "")[:MAX_BIO_LEN]
                if "avatar_url" in data:
                    av = data.get("avatar_url")
                    if av is None:
                        users[username]["avatar_url"] = None
                    else:
                        av = str(av)
                        if av.startswith("/uploads/"):
                            users[username]["avatar_url"] = av
                save_users(users)
            self._send_json(200, {"ok": True})

        elif self.path == "/delete":
            username = self._get_authed_username()
            if username is None:
                self._send_json(401, {"error": "not signed in"})
                return
            data = self._read_json_body()
            if data and "id" in data:
                result = delete_message_from_history(data["id"], username)
                if result:
                    if isinstance(result, str) and result.startswith("/uploads/"):
                        fname = result[len("/uploads/"):]
                        if "/" not in fname and "\\" not in fname and ".." not in fname:
                            filepath = UPLOAD_DIR / fname
                            try:
                                if filepath.is_file():
                                    filepath.unlink()
                            except OSError:
                                pass
                    broadcast("delete", {"id": data["id"]})
                    self._send_json(200, {"ok": True})
                else:
                    self._send_json(403, {"error": "Unauthorized or not found"})
            else:
                self._send_json(400, {"error": "Bad request"})

        elif self.path == "/send":
            username = self._get_authed_username()
            if username is None:
                self._send_json(401, {"error": "not signed in"})
                return

            data = self._read_json_body()
            if not data:
                self._send_json(400, {"error": "invalid json"})
                return

            text = str(data.get("text", "")).strip()[:MAX_MESSAGE_LEN]
            media_url = data.get("media_url")
            recipient = data.get("recipient")
            channel = "announcement" if data.get("channel") == "announcement" else "general"

            if media_url and not str(media_url).startswith("/uploads/"):
                media_url = None

            if recipient:
                recipient = str(recipient).strip()
                if recipient.lower() == BOT_USERNAME.lower():
                    recipient = BOT_USERNAME
                else:
                    with users_lock:
                        users = load_users()
                    if not username_taken(users, recipient) or recipient.lower() == username.lower():
                        recipient = None

            if not text and not media_url:
                self._send_json(400, {"error": "empty message"})
                return

            reply_to = None
            reply_to_id = data.get("reply_to_id")
            if reply_to_id:
                original = find_message(str(reply_to_id), username)
                if original is not None:
                    reply_to = build_reply_preview(original)

            message = {
                "id": uuid.uuid4().hex,
                "username": username,
                "text": text,
                "ts": time.time(),
                "system": False,
                "media_url": media_url,
                "reply_to": reply_to,
                "recipient": recipient,
                "channel": None if recipient else channel,
            }
            append_history(message)

            target_users = [username, recipient] if recipient else None
            broadcast("message", message, target_users=target_users)

            if recipient == BOT_USERNAME:
                threading.Thread(target=handle_bot_dm, args=(username,), daemon=True).start()

            self._send_json(200, {"ok": True})

        elif self.path == "/upload":
            username = self._get_authed_username()
            if username is None:
                self._send_json(401, {"error": "not signed in"})
                return

            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            if not content_type.startswith("multipart/form-data"):
                self._send_json(400, {"error": "expected multipart/form-data"})
                return
            if length <= 0 or length > MAX_UPLOAD_BYTES:
                self._send_json(413, {"error": "file too large (8MB max)"})
                return

            body = self.rfile.read(length)
            filename, filedata = parse_multipart_file(body, content_type)
            if not filename or not filedata:
                self._send_json(400, {"error": "no file found"})
                return

            ext = Path(filename).suffix.lower()
            if ext not in ALLOWED_IMAGE_EXT:
                self._send_json(400, {"error": "only images allowed"})
                return

            new_name = f"{uuid.uuid4().hex}{ext}"
            (UPLOAD_DIR / new_name).write_bytes(filedata)
            self._send_json(200, {"url": f"/uploads/{new_name}"})
        else:
            self.send_response(404)
            self.end_headers()

    def _read_json_body(self, max_len=10_000):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > max_len:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def _handle_register(self):
        data = self._read_json_body()
        if not data:
            self._send_json(400, {"error": "invalid request"})
            return
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        access_code = str(data.get("access_code", "")).strip()

        if not hmac.compare_digest(access_code, HUB_ACCESS_CODE):
            self._send_json(403, {"error": "invalid access code"})
            return
        if not USERNAME_RE.match(username):
            self._send_json(400, {"error": "invalid username format"})
            return
        if username.lower() in RESERVED_USERNAMES:
            self._send_json(400, {"error": "that username is reserved"})
            return
        if len(password) < MIN_PASSWORD_LEN:
            self._send_json(400, {"error": "password too short"})
            return

        with users_lock:
            users = load_users()
            if username_taken(users, username):
                self._send_json(409, {"error": "username taken"})
                return
            salt_hex, hash_hex = hash_password(password)
            users[username] = {
                "salt": salt_hex,
                "hash": hash_hex,
                "joined_at": time.time(),
                "bio": "",
                "avatar_url": None,
            }
            save_users(users)
        self._send_json(200, {"token": create_session(username), "username": username})

    def _handle_login(self):
        data = self._read_json_body()
        if not data:
            self._send_json(400, {"error": "invalid request"})
            return
        username_input = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        with users_lock:
            users = load_users()
            match = next((u for u in users if u.lower() == username_input.lower()), None)
            if match is None or not verify_password(password, users[match]["salt"], users[match]["hash"]):
                self._send_json(401, {"error": "invalid username or password"})
                return

        self._send_json(200, {"token": create_session(match), "username": match})


def local_ip_hint():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    ip = local_ip_hint()
    print("=" * 56)
    print(" HubChat is running with a Modern UI")
    print(f" On this machine:      http://localhost:{PORT}")
    print(f" For others on WiFi:   http://{ip}:{PORT}")
    print("-" * 56)
    print(f" Hub access code:      {HUB_ACCESS_CODE}")
    print(" New members need this code once to create an account.")
    print("-" * 56)
    if ANTHROPIC_API_KEY:
        print(" AI Assistant (HubBot): enabled")
    else:
        print(" AI Assistant (HubBot): disabled")
        print(" To enable, restart with: ANTHROPIC_API_KEY=sk-ant-... python3 server.py")
    print("=" * 56)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
