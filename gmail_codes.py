#!/data/projects/gmail-codes/venv/bin/python
"""gmail-codes: IMAP IDLE on Gmail -> verification codes -> Telegram.

Source of truth is FETCH (BODY.PEEK[], readonly); IDLE only wakes the loop early.
Mail state is never mutated. All logs are metadata only.
"""
import email
import email.header
import hashlib
import html
import json
import logging
import os
import random
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from email import policy
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser

BASE = os.path.dirname(os.path.realpath(__file__))
ENV_FILE = os.environ.get("GMAIL_CODES_ENV", "/etc/gmail-codes.env")
HEARTBEAT = os.environ.get("GMAIL_CODES_HEARTBEAT", os.path.join(BASE, "heartbeat"))
DEFAULT_DB = os.path.join(BASE, "state.db")
REQUIRED = ("GMAIL_USER", "GMAIL_APP_PASSWORD", "TG_BOT_TOKEN", "TG_CHAT_ID")
SC_WINDOW = 600  # (sender, code) dedup window, seconds
HEARTBEAT_MAX_AGE = 900
log = logging.getLogger("gmail-codes")

# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------
_KW = re.compile(
    r"(?<!\w)(?:codes?|verif\w*|otp|one[\s-]?time|passcode|security\s+code|pin|"
    r"confirm\w*|authenticat\w*|log[\s-]?in|sign[\s-]?in|"
    r"код\w*|пароль|підтверд\w*|одноразов\w*|верифікац\w*|подтверд\w*)(?!\w)",
    re.I,
)
_KW_BAD_PREFIX = re.compile(
    r"(?:promo|promotional|discount|coupon|gift|zip|postal|post|area|country|tracking|referral|invite)\s*$",
    re.I,
)
_MON = (
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|січ|лют|бер|квіт|трав|черв|лип|серп|вер|жовт|лист|груд|"
    r"янв|фев|апр|мая|июн|июл|авг|сен|окт|ноя|дек)"
)
_CUR = r"(?:USD|EUR|GBP|UAH|PLN|грн|гривень|руб|₴|₽|\$|€|£|zł)"
_MASKS = [
    re.compile(r"https?://\S+|www\.\S+", re.I),
    re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    re.compile(r"\b\d{1,2}\s+" + _MON + r"\w*\.?,?\s+\d{4}\b", re.I),
    re.compile(r"\b" + _MON + r"\w*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}\b", re.I),
    re.compile(r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}\b"),
    re.compile(r"\b\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}\b"),
    re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp][Mm])?"),
    re.compile(r"[$€£₴¥]\s?\d+(?:[.,]\d+)*"),
    re.compile(r"\d+(?:[ ,.]\d{3})*(?:[.,]\d+)?\s?" + _CUR, re.I),
    re.compile(r"\+\d[ \d().-]{6,}\d"),
    re.compile(r"\(\d{3}\)[ .-]?\d{3}[ .-]?\d{4}"),
    re.compile(r"\b\d{1,2}[-. ]\d{3}[-. ]\d{3}[-. ]\d{4}\b"),
    re.compile(r"\b\d{3}[-. ]\d{3}[-. ]\d{4}\b"),
    re.compile(r"\b0\d{2}[-. ]\d{3}[-. ]?\d{2}[-. ]?\d{2}\b"),
    re.compile(r"#\w+"),
    re.compile(r"\b\d+[.,]\d+\b"),
]
_LABEL = re.compile(
    r"(?:order|invoice|inv|tracking|track|ticket|reference|ref|receipt|case|account|acct|booking|shipment|"
    r"parcel|serial|model|zip|postal|postcode|post\s+code|number|num|id|"
    r"(?:promo|promotional|discount|coupon|voucher|gift)(?:\s+code)?|"
    r"індекс\w*|индекс\w*|заказ\w*|замовлення|номер|інвойс\w*|рахунок|трек\w*|посилк\w*|накладн\w*|"
    r"квитанц\w*|чек|поштов\w*|телефон|тел|tel|phone|no\.?|№)"
    r"\s*[:#№.-]*\s*(?:is|—)?\s*$",
    re.I,
)
_ALNUM = re.compile(
    r"(?<![\w.,#@/+$€£-])((?:[A-Z]{1,4}-)?[A-Z0-9]{4,10}|[A-Z0-9]{2,5}-[A-Z0-9]{2,5})(?![\w@])(?![.,]\d)"
)
_DIGITS = re.compile(
    r"(?<![\w.,#@/+$€£-])(?<!\d[ -])(\d{3}[ -]\d{3}|\d{4}[ -]\d{4}|\d{4,8})(?![\w@])(?![ -]\d)(?![.,]\d)"
)
_SENT = re.compile(r"[.!?](?:\s|$)")
_LINK_KW = re.compile(r"verify|confirm|token|magic|login", re.I)
_LINK_BAD = re.compile(r"unsubscribe|optout|opt-out", re.I)
_URL = re.compile(r"https://[^\s<>\"')\]]+")
WINDOW = 60


def _mask(text):
    for rx in _MASKS:
        text = rx.sub(lambda m: " " * len(m.group(0)), text)
    return text


def _keywords(masked):
    out = []
    for m in _KW.finditer(masked):
        if m.group(0).lower().startswith("code") and _KW_BAD_PREFIX.search(masked[max(0, m.start() - 14):m.start()]):
            continue
        out.append((m.start(), m.end()))
    return out


def _candidates(masked):
    out = []
    for m in _ALNUM.finditer(masked):
        s = m.group(1)
        flat = s.replace("-", "")
        if 5 <= len(flat) <= 10 and any(c.isdigit() for c in flat) and any(c.isalpha() for c in flat):
            out.append((m.start(1), m.end(1), s))
    taken = [(a, b) for a, b, _ in out]
    for m in _DIGITS.finditer(masked):
        a, b = m.start(1), m.end(1)
        if any(a < y and x < b for x, y in taken):
            continue
        flat = re.sub(r"[ -]", "", m.group(1))
        if not 4 <= len(flat) <= 8:
            continue
        before = masked[max(0, a - 30):a]
        if len(flat) == 4 and re.fullmatch(r"(?:19|20)\d\d", flat) and not re.search(r"[:：]\s*$", before):
            continue
        if len(flat) == 5 and re.search(r"\b[A-Z]{2}\s$", before):
            continue
        out.append((a, b, flat))
    return [c for c in out if not _LABEL.search(masked[max(0, c[0] - 30):c[0]])]


def _extract(text):
    masked = _mask(text or "")
    kws = _keywords(masked)
    if not kws:
        return []
    best = {}
    for s, e, norm in _candidates(masked):
        for ks, ke in kws:
            if s >= ke:
                gap = masked[ke:s]
            elif e <= ks:
                gap = masked[e:ks]
            else:
                continue
            if len(gap) > WINDOW or _SENT.search(gap):
                continue
            key = (s, norm)
            best[key] = min(best.get(key, 10 ** 9), len(gap))
    ranked = sorted(best.items(), key=lambda kv: (kv[1], kv[0][0]))
    codes = []
    for (_, norm), _d in ranked:
        if norm not in codes:
            codes.append(norm)
    return codes[:3]


def extract_codes(subject, text):
    codes = []
    for part in (subject, text):
        for c in _extract(part):
            if c not in codes:
                codes.append(c)
    return codes[:3]


def extract_link(subject, text, links=()):
    """Verification link, only when keywords present. Caller ensures no code found."""
    masked = _mask((subject or "") + "\n" + (text or ""))
    if not _keywords(masked):
        return None
    for u in list(links) + _URL.findall(text or ""):
        if u.startswith("https://") and _LINK_KW.search(u) and not _LINK_BAD.search(u):
            return u
    return None


# --------------------------------------------------------------------------
# email parsing
# --------------------------------------------------------------------------
class _Html(HTMLParser):
    BLOCK = {"br", "p", "div", "tr", "td", "th", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.links, self._skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        if tag in self.BLOCK:
            self.out.append("\n")
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href.strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1
        if tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.out.append(data)


def html_to_text(src):
    p = _Html()
    try:
        p.feed(src)
        p.close()
    except Exception:
        pass
    text = re.sub(r"[ \t\xa0]+", " ", "".join(p.out))
    return re.sub(r"\n\s*\n+", "\n", text).strip(), p.links


def _part_text(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        for enc in (part.get_content_charset(), "utf-8", "cp1251", "koi8-r"):
            if not enc:
                continue
            try:
                return payload.decode(enc)
            except (LookupError, UnicodeDecodeError):
                continue
        return payload.decode("utf-8", "replace")


def _header(msg, name):
    try:
        return str(msg.get(name, "") or "")
    except Exception:
        raw = msg.get(name, "")
        try:
            return str(email.header.make_header(email.header.decode_header(str(raw))))
        except Exception:
            return str(raw)


def parse_email(raw):
    msg = email.message_from_bytes(raw, policy=policy.default)
    subject = re.sub(r"\s+", " ", _header(msg, "Subject")).strip()
    name, addr = "", ""
    try:
        a = msg["From"].addresses[0]
        name, addr = a.display_name, a.addr_spec
    except Exception:
        addr = _header(msg, "From")
    try:
        date = parsedate_to_datetime(_header(msg, "Date")).timestamp()
    except Exception:
        date = None
    plain = html_part = None
    try:
        plain = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
    except Exception:
        pass
    ptext = _part_text(plain).strip() if plain is not None else ""
    htext, links = "", []
    if html_part is not None:
        htext, links = html_to_text(_part_text(html_part))
    return {
        "subject": subject, "name": name, "addr": addr, "date": date,
        "mid": _header(msg, "Message-ID").strip(), "plain": ptext, "html": htext, "links": links,
    }


def analyze(p):
    """-> ('code', [codes]) | ('link', url) | (None, None). plain first, html as fallback."""
    for text in (p["plain"], p["html"]):
        if not text:
            continue
        codes = extract_codes(p["subject"], text)
        if codes:
            return "code", codes
    if not (p["plain"] or p["html"]):
        codes = extract_codes(p["subject"], "")
        if codes:
            return "code", codes
    for text in (p["plain"], p["html"]):
        link = extract_link(p["subject"], text, p["links"])
        if link:
            return "link", link
    return None, None


def format_message(p, kind, payload, spam, now):
    esc = lambda s: html.escape(s or "", quote=False)
    if kind == "code":
        l1 = "🔑 " + " ".join("<code>%s</code>" % esc(c) for c in payload)
    else:
        l1 = '🔗 <a href="%s">посилання</a>' % html.escape(payload, quote=True)
    sender = ("%s <%s>" % (p["name"], p["addr"])) if p["name"] else p["addr"]
    subj = p["subject"] if len(p["subject"]) <= 80 else p["subject"][:79] + "…"
    lines = [l1, esc(sender), esc(subj)]
    tail = []
    if p["date"] is not None:
        tail.append("+%ds" % max(0, int(now - p["date"])))
    if spam:
        tail.append("⚠ spam")
    if tail:
        lines.append(" ".join(tail))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------
class State:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS mailbox(name TEXT PRIMARY KEY, uidvalidity INTEGER, last_uid INTEGER);
            CREATE TABLE IF NOT EXISTS seen(message_id TEXT PRIMARY KEY, ts REAL);
            CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT, created REAL,
                                              attempts INTEGER DEFAULT 0, next_try REAL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
            """
        )

    @contextmanager
    def tx(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def mailbox(self, name):
        return self.db.execute("SELECT uidvalidity,last_uid FROM mailbox WHERE name=?", (name,)).fetchone()

    def set_mailbox(self, name, uv, last):
        self.db.execute("INSERT OR REPLACE INTO mailbox VALUES(?,?,?)", (name, uv, last))

    def is_seen(self, mid):
        return self.db.execute("SELECT 1 FROM seen WHERE message_id=?", (mid,)).fetchone() is not None

    def sc_recent(self, key, now):
        r = self.db.execute("SELECT ts FROM seen WHERE message_id=?", (key,)).fetchone()
        return r is not None and now - r[0] < SC_WINDOW

    def mark_seen(self, mid, now):
        self.db.execute("INSERT OR REPLACE INTO seen VALUES(?,?)", (mid, now))

    def enqueue(self, text, now):
        self.db.execute("INSERT INTO outbox(text,created,attempts,next_try) VALUES(?,?,0,0)", (text, now))

    def due(self, now):
        return self.db.execute(
            "SELECT id,text,attempts FROM outbox WHERE next_try<=? ORDER BY id", (now,)).fetchall()

    def next_try(self):
        r = self.db.execute("SELECT MIN(next_try) FROM outbox").fetchone()
        return r[0]

    def done(self, oid):
        self.db.execute("DELETE FROM outbox WHERE id=?", (oid,))

    def fail(self, oid, attempts, next_try):
        self.db.execute("UPDATE outbox SET attempts=?,next_try=? WHERE id=?", (attempts, next_try, oid))

    def kv_get(self, key):
        r = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    def kv_set(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (key, str(value)))

    def prune(self, now):
        self.db.execute("DELETE FROM seen WHERE ts<?", (now - 30 * 86400,))

    def close(self):
        self.db.close()


# --------------------------------------------------------------------------
# telegram
# --------------------------------------------------------------------------
class TgError(Exception):
    def __init__(self, code=0, retry_after=None):
        super().__init__("tg error %s" % code)
        self.code, self.retry_after = code, retry_after


def tg_call(token, method, payload=None, timeout=15):
    url = "https://api.telegram.org/bot%s/%s" % (token, method)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        ra = None
        try:
            ra = json.loads(e.read()).get("parameters", {}).get("retry_after")
        except Exception:
            pass
        raise TgError(e.code, ra) from None
    except Exception as e:
        raise TgError(0) from None


def make_sender(token, chat_id):
    def send(text):
        base = {"chat_id": chat_id, "disable_web_page_preview": True}
        try:
            tg_call(token, "sendMessage", dict(base, text=text, parse_mode="HTML"))
        except TgError as e:
            if e.code != 400:
                raise
            plain = html.unescape(re.sub(r"</?[a-z][^>]*>", "", text))
            tg_call(token, "sendMessage", dict(base, text=plain))
    return send


class Notifier:
    def __init__(self, state, send, clock=time.time, lock=None):
        self.state, self.send, self.clock = state, send, clock
        self.lock = lock or threading.Lock()

    def flush(self):
        with self.lock:
            now = self.clock()
            for oid, text, attempts in self.state.due(now):
                try:
                    self.send(text)
                except TgError as e:
                    attempts += 1
                    wait = e.retry_after if (e.code == 429 and e.retry_after) else min(3600, 5 * 2 ** min(attempts, 10))
                    self.state.fail(oid, attempts, now + wait + 1)
                    log.warning("tg_fail code=%s attempts=%d wait=%ds", e.code, attempts, wait)
                    if e.code == 429:
                        break
                    continue
                self.state.done(oid)

    def alert(self, key, text, interval=3600):
        now = self.clock()
        last = self.state.kv_get("alert:" + key)
        if last is not None and now - float(last) < interval:
            return False
        with self.state.tx():
            self.state.kv_set("alert:" + key, now)
            self.state.enqueue(text, now)
        self.flush()
        return True


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------
class Mailbox:
    def __init__(self, name, state, notifier, clock=time.time):
        self.name, self.state, self.notifier, self.clock = name, state, notifier, clock
        self.spam = "spam" in name.lower()
        self.uv = None

    def open(self, client):
        info = client.select_folder(self.name, readonly=True)
        self.uv = int(info[b"UIDVALIDITY"])
        row = self.state.mailbox(self.name)
        if row is None or row[0] != self.uv:
            uidnext = info.get(b"UIDNEXT")
            if uidnext is not None:
                top = int(uidnext) - 1
            else:
                found = client.search(["ALL"])
                top = max(found) if found else 0
            self.state.set_mailbox(self.name, self.uv, top)
            log.info("baseline mailbox=%s last_uid=%d", self.name, top)
            if row is not None:
                self.notifier.alert("uidvalidity:" + self.name,
                                    "gmail-codes: UIDVALIDITY changed in %s, baseline reset" % html.escape(self.name))

    def poll(self, client):
        last = self.state.mailbox(self.name)[1]
        uids = sorted(u for u in client.search(["UID", "%d:*" % (last + 1)]) if u > last)
        for i in range(0, len(uids), 50):
            chunk = uids[i:i + 50]
            data = client.fetch(chunk, [b"BODY.PEEK[]"])
            for uid in chunk:
                item = data.get(uid) or {}
                raw = item.get(b"BODY[]") or b""
                self.handle(uid, raw)
        self.notifier.flush()

    def handle(self, uid, raw):
        now = self.clock()
        try:
            p = parse_email(raw)
            kind, payload = analyze(p)
        except Exception as e:
            log.warning("parse_error uid=%d mailbox=%s type=%s", uid, self.name, type(e).__name__)
            p, kind, payload = None, None, None
        mid = (p and p["mid"]) or "nomid:" + hashlib.sha1(raw).hexdigest()
        domain = (p["addr"].rsplit("@", 1)[-1] if p and "@" in p["addr"] else "-")
        text = None
        sc_keys = []
        if kind and not self.state.is_seen(mid):
            if kind == "code":
                sender = p["addr"].lower()
                sc_keys = ["sc:%s:%s" % (sender, c) for c in payload]
                fresh = [c for c, k in zip(payload, sc_keys) if not self.state.sc_recent(k, now)]
                if fresh:
                    text = format_message(p, "code", fresh, self.spam, now)
            else:
                text = format_message(p, "link", payload, self.spam, now)
        with self.state.tx():
            if kind:
                self.state.mark_seen(mid, now)
                for k in sc_keys:
                    self.state.mark_seen(k, now)
            if text:
                self.state.enqueue(text, now)
            self.state.set_mailbox(self.name, self.uv, uid)
        log.info("msg uid=%d mailbox=%s domain=%s matched=%d latency=%s", uid, self.name, domain,
                 1 if text else 0, ("%ds" % max(0, int(now - p["date"]))) if p and p["date"] else "-")
        if text:
            self.notifier.flush()


# --------------------------------------------------------------------------
# config / daemon
# --------------------------------------------------------------------------
def load_env_file(path):
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            env[k.strip()] = v
    return env


def get_config(use_file=False):
    env = dict(os.environ)
    if use_file and os.path.exists(ENV_FILE):
        env = dict(load_env_file(ENV_FILE), **{k: v for k, v in env.items() if k in REQUIRED})
    return {
        "user": env.get("GMAIL_USER"), "password": env.get("GMAIL_APP_PASSWORD"),
        "token": env.get("TG_BOT_TOKEN"), "chat": env.get("TG_CHAT_ID"),
        "mailboxes": [m.strip() for m in env.get("MAILBOXES", "INBOX,[Gmail]/Spam").split(",") if m.strip()],
        "idle": int(env.get("IDLE_SECONDS", "300")),
        "db": env.get("STATE_DB", DEFAULT_DB),
    }


def connect(cfg):
    from imapclient import IMAPClient
    c = IMAPClient("imap.gmail.com", ssl=True, timeout=90)
    c.login(cfg["user"], cfg["password"])
    return c


def beat():
    try:
        with open(HEARTBEAT, "a"):
            pass
        os.utime(HEARTBEAT, None)
    except OSError:
        pass


def worker(cfg, name, notifier_lock, stop):
    from imapclient.exceptions import LoginError
    state = State(cfg["db"])
    notifier = Notifier(state, make_sender(cfg["token"], cfg["chat"]), lock=notifier_lock)
    mb = Mailbox(name, state, notifier)
    backoff = 5
    while not stop.is_set():
        client = None
        try:
            client = connect(cfg)
            mb.open(client)
            backoff = 5
            log.info("connected mailbox=%s", name)
            while not stop.is_set():
                beat()
                mb.poll(client)
                wait = cfg["idle"]
                nt = state.next_try()
                if nt is not None:
                    wait = max(1, min(wait, int(nt - time.time()) + 1))
                client.idle()
                try:
                    client.idle_check(timeout=wait)
                finally:
                    client.idle_done()
                notifier.flush()
        except LoginError:
            log.error("auth_failed mailbox=%s", name)
            notifier.alert("auth", "gmail-codes: IMAP auth failed")
            wait = min(600, max(backoff, 30) * 2)
            backoff = wait
        except Exception as e:
            log.warning("session_error mailbox=%s type=%s", name, type(e).__name__)
            wait = backoff * random.uniform(0.8, 1.2)
            backoff = min(60, backoff * 2)
        else:
            continue
        finally:
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass
        beat()
        stop.wait(wait)


def cmd_run():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    cfg = get_config()
    missing = [k for k, v in (("GMAIL_USER", cfg["user"]), ("GMAIL_APP_PASSWORD", cfg["password"]),
                              ("TG_BOT_TOKEN", cfg["token"]), ("TG_CHAT_ID", cfg["chat"])) if not v]
    if missing:
        log.error("missing env: %s", ",".join(missing))
        return 2
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    lock = threading.Lock()
    threads = [threading.Thread(target=worker, args=(cfg, m, lock, stop), daemon=True) for m in cfg["mailboxes"]]
    for t in threads:
        t.start()
    while not stop.is_set():
        stop.wait(5)
    return 0


def cmd_check():
    ok = True

    def out(name, good, note=""):
        nonlocal ok
        ok = ok and good
        print("%s %s%s" % ("PASS" if good else "FAIL", name, (": " + note) if note else ""))

    have_file = os.path.exists(ENV_FILE)
    cfg = get_config(use_file=True)
    missing = [k for k, v in (("GMAIL_USER", cfg["user"]), ("GMAIL_APP_PASSWORD", cfg["password"]),
                              ("TG_BOT_TOKEN", cfg["token"]), ("TG_CHAT_ID", cfg["chat"])) if not v]
    if not have_file and missing:
        out("env", False, "env відсутній (%s)" % ENV_FILE)
    elif missing:
        out("env", False, "порожні змінні: " + ",".join(missing))
    else:
        out("env", True)
    if missing:
        out("imap", False, "пропущено, нема env")
        out("telegram", False, "пропущено, нема env")
        return 1
    try:
        c = connect(cfg)
        try:
            c.select_folder("INBOX", readonly=True)
        finally:
            c.logout()
        out("imap", True)
    except Exception as e:
        out("imap", False, type(e).__name__)
    try:
        r = tg_call(cfg["token"], "getMe")
        out("telegram", bool(r.get("ok")))
    except TgError as e:
        out("telegram", False, "http %s" % e.code)
    return 0 if ok else 1


def cmd_selftest():
    return subprocess.call([sys.executable, "-m", "unittest", "discover", "-s", os.path.join(BASE, "tests"),
                            "-t", BASE], cwd=BASE)


def watchdog_decide(active, hb_age, uptime, now_alert_last, now, max_age=HEARTBEAT_MAX_AGE):
    """-> (stuck, alert). stuck: restart needed. alert: spam-guarded (1/h)."""
    if not active:
        return False, False
    age = uptime if (hb_age is None or hb_age > uptime) else hb_age
    stuck = age > max_age
    return stuck, stuck and (now_alert_last is None or now - now_alert_last >= 3600)


def cmd_watchdog():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    cfg = get_config()
    active = subprocess.run(["systemctl", "is-active", "--quiet", "gmail-codes"]).returncode == 0
    now = time.time()
    hb_age = (now - os.path.getmtime(HEARTBEAT)) if os.path.exists(HEARTBEAT) else None
    uptime = 0
    if active:
        r = subprocess.run(["systemctl", "show", "gmail-codes", "-p", "ActiveEnterTimestampMonotonic", "--value"],
                           capture_output=True, text=True)
        try:
            uptime = time.clock_gettime(time.CLOCK_MONOTONIC) - int(r.stdout.strip()) / 1e6
        except ValueError:
            uptime = 0
    state = State(cfg["db"])
    last = state.kv_get("alert:watchdog")
    stuck, alert = watchdog_decide(active, hb_age, uptime, float(last) if last else None, now)
    if alert:
        state.kv_set("alert:watchdog", now)
        try:
            make_sender(cfg["token"], cfg["chat"])("gmail-codes завис")
        except TgError:
            state.enqueue("gmail-codes завис", now)
    if stuck:
        log.warning("stuck hb_age=%s uptime=%d: restart", hb_age, uptime)
        subprocess.run(["systemctl", "restart", "gmail-codes"])
    state.close()
    return 0


def main(argv):
    cmds = {"run": cmd_run, "check": cmd_check, "selftest": cmd_selftest, "watchdog": cmd_watchdog}
    if len(argv) != 2 or argv[1] not in cmds:
        print("usage: gmail-codes run|check|selftest|watchdog", file=sys.stderr)
        return 2
    return cmds[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
