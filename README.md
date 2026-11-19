# gmail-codes

Gmail verification codes -> Telegram, in seconds. Holds an IMAP IDLE connection to Gmail, extracts verification codes (or verify links) from every new message and sends them to a Telegram bot. Everything else is ignored.

- Push via IMAP IDLE; every loop re-fetches by UID, so a missed notification is caught within `IDLE_SECONDS`.
- Mailbox is read-only (`BODY.PEEK[]`, readonly select) - nothing is marked read, moved or flagged.
- Persistent state (SQLite): `last_uid` advances only after the message is sent or queued in an outbox. Restarts lose nothing and duplicate nothing (Message-ID + sender/code dedup).
- Telegram failures and 429s are retried with backoff; IMAP drops reconnect with backoff; a revoked app password alerts once an hour.
- Watchdog timer alerts and restarts the service if the heartbeat goes stale.
- Logs contain metadata only - never codes, bodies or full subjects.
- Stack: Python 3.12, `imapclient`, stdlib. systemd units in `deploy/`.

## Install (systemd)
```sh
python3 -m venv venv && venv/bin/pip install -r requirements.txt
# the units assume the project lives in /data/projects/gmail-codes - adjust paths in deploy/*.service if not
cp deploy/gmail-codes*.service deploy/gmail-codes-watchdog.timer /etc/systemd/system/
install -m 600 /dev/null /etc/gmail-codes.env   # fill in per deploy/gmail-codes.env.example
ln -s "$PWD/gmail_codes.py" /usr/local/bin/gmail-codes
gmail-codes check                                # PASS/FAIL for env, IMAP, Telegram
systemctl daemon-reload && systemctl enable --now gmail-codes gmail-codes-watchdog.timer
```
Needs: IMAP enabled in Gmail, 2-Step Verification + an App Password, a Telegram bot token and chat id.

## Ops
- `journalctl -u gmail-codes -f`, `gmail-codes selftest` (offline tests)
- First start of a mailbox = baseline (history is not replayed). UIDVALIDITY change = re-baseline + alert.
- Watches `INBOX` and `[Gmail]/Spam` by default; override with `MAILBOXES` (localized Gmail names differ).

MIT licensed.

## Telegram interface

This is a **send-only verification-code notifier**. It deliberately has no persistent reply keyboard or interactive command menu: user interaction cannot safely improve IMAP delivery. After Gmail credential changes, check the IMAP authentication health, heartbeat and watchdog independently.

## /help

`/help`/`/start` are provided through the independent private `tg-help-listener` service (separate Telegram polling with per-bot offset), **not the IMAP worker**. Gmail delivery and credential handling are unchanged.
