# HubChat

Offline LAN chat app for a coworking space (~200 users), written in pure Python with no pip installs.

## Features
- Real-time messaging with Server-Sent Events
- Image sharing, DMs with unread badges, reply-with-quote
- Access-code gated registration, PBKDF2 password hashing
- HubBot AI assistant via the Claude API, which degrades gracefully when offline
- Glassmorphism dark UI

## Run it
```bash
python3 server.py
```
Optional, to enable HubBot:
```bash
ANTHROPIC_API_KEY=your-key python3 server.py
```
On first run, the server creates its own access code file and data files.
