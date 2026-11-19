# HubChat

Offline LAN chat app for a coworking space (about 200 users), written in pure Python with no pip installs.

## Features

- Real-time messaging with Server-Sent Events
- Image sharing, DMs with unread badges, reply-with-quote
- Access-code gated registration, PBKDF2 password hashing
- HubBot AI assistant via the Claude API

## Run it

    python3 server.py

To enable HubBot:

    ANTHROPIC_API_KEY=your-key python3 server.py
