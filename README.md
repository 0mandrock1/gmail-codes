# gmail-codes

IMAP IDLE на Gmail -> verification-коди/лінки з нових листів -> Telegram-бот.
Пошта лише читається (`BODY.PEEK[]`, readonly). State: SQLite `state.db`. Логи: journald, лише метадані.

## Встановлення
1. Gmail: 2FA + App Password. Telegram: бот + chat id.
2. Env (значення — з `/etc/gmail-codes.env.example`):
   ```
   install -m 600 /dev/null /etc/gmail-codes.env && $EDITOR /etc/gmail-codes.env
   ```
3. Перевірка (без побічок; PASS/FAIL по кожному):
   ```
   gmail-codes check
   ```
4. Запуск:
   ```
   systemctl enable --now gmail-codes gmail-codes-watchdog.timer
   ```

## Експлуатація
- Логи: `journalctl -u gmail-codes -f`, watchdog: `journalctl -u gmail-codes-watchdog`
- Тести: `gmail-codes selftest`
- Перший старт mailbox = baseline (історія не реплеїться). Зміна UIDVALIDITY = baseline + алерт у TG.
- Недоставлене лежить в `outbox` і ретраїться (backoff, 429 -> retry_after).
- Ротація app password -> алерт «IMAP auth failed» раз на годину, backoff до 10 хв.
- Watchdog: heartbeat старший 15 хв -> алерт «завис» + restart.
