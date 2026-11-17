import calendar
import os
import tempfile
import unittest
from email.message import EmailMessage

import gmail_codes as g

FORBIDDEN = ("add_flags", "set_flags", "remove_flags", "copy", "move", "delete_messages", "append",
             "expunge", "store", "mark_seen", "set_gmail_labels", "add_gmail_labels")


def mail(mid, body, subj="Login", frm="Svc <no-reply@svc.com>", date="Tue, 17 Nov 2026 09:00:00 +0000"):
    m = EmailMessage()
    m["Message-ID"] = mid
    m["Subject"] = subj
    m["From"] = frm
    m["Date"] = date
    m.set_content(body)
    return m.as_bytes()


class FakeImap:
    def __init__(self, uv=1, uidnext=1, msgs=None):
        self.uv, self.uidnext, self.msgs = uv, uidnext, dict(msgs or {})
        self.calls = []

    def select_folder(self, name, readonly=False):
        self.calls.append(("select_folder", name, readonly))
        return {b"UIDVALIDITY": self.uv, b"UIDNEXT": self.uidnext}

    def search(self, crit):
        self.calls.append(("search", tuple(crit)))
        if crit[0] == "UID":
            lo = int(crit[1].split(":")[0])
            ids = [u for u in self.msgs if u >= lo]
            return ids or ([max(self.msgs)] if self.msgs else [])  # Gmail-style: N:* returns last msg
        return list(self.msgs)

    def fetch(self, uids, parts):
        self.calls.append(("fetch", tuple(uids), tuple(parts)))
        return {u: {b"BODY[]": self.msgs[u]} for u in uids if u in self.msgs}

    def __getattr__(self, name):
        if name in FORBIDDEN:
            def bad(*a, **k):
                self.calls.append(("MUTATION", name))
            return bad
        raise AttributeError(name)


class Tg:
    def __init__(self):
        self.sent, self.fail = [], False

    def __call__(self, text):
        if self.fail:
            raise g.TgError(500)
        self.sent.append(text)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class Pipe(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.db = os.path.join(self.d, "s.db")
        self.tg, self.clock = Tg(), Clock(calendar.timegm((2026, 11, 17, 9, 0, 3)))

    def build(self, name="INBOX"):
        st = g.State(self.db)
        n = g.Notifier(st, self.tg, clock=self.clock)
        return st, n, g.Mailbox(name, st, n, clock=self.clock)

    def run_once(self, mb, im):
        mb.open(im)
        mb.poll(im)

    def baseline(self, mb, im):
        mb.open(im)  # first run: baseline only

    def test_a_normal_mail(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<1@x>", "Your verification code is 123456"); im.uidnext = 2
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 1)
        t = self.tg.sent[0].split("\n")
        self.assertEqual(t[0], "🔑 <code>123456</code>")
        self.assertIn("no-reply@svc.com", t[1])
        self.assertEqual(t[3], "+3s")
        self.assertEqual(st.mailbox("INBOX")[1], 1)

    def test_b_non_code_mail_advances(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<2@x>", "Big sale this week, 50% off", subj="Sale")
        mb.poll(im)
        self.assertEqual(self.tg.sent, [])
        self.assertEqual(st.mailbox("INBOX")[1], 1)
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)

    def test_b2_unrecognized_verification_alerts(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<m1@x>", "Please verify your sign-in. Enter the secret shown in the app.",
                          subj="Your confirmation code " + "x" * 100)
        im.msgs[2] = mail("<m2@x>", "Weekly digest, nothing special", subj="Newsletter")
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 1)
        t = self.tg.sent[0].split("\n")
        self.assertEqual(t[0], "\u26a0 код не розпізнано")
        self.assertIn("no-reply@svc.com", t[1])
        self.assertLessEqual(len(t[2]), 80)
        self.assertNotIn("secret", self.tg.sent[0])
        self.assertEqual(st.mailbox("INBOX")[1], 2)
        mb.handle(1, im.msgs[1])  # same Message-ID -> no repeat
        self.assertEqual(len(self.tg.sent), 1)

    def test_b3_plain_newsletter_silent(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<n1@x>", "Spring sale. Save big, shop now!", subj="Spring sale")
        mb.poll(im)
        self.assertEqual(self.tg.sent, [])

    def test_c_tg_down_outbox_then_delivery(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<3@x>", "Your verification code is 123456")
        self.tg.fail = True
        mb.poll(im)
        self.assertEqual(self.tg.sent, [])
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 1)
        self.assertEqual(st.mailbox("INBOX")[1], 1)
        self.tg.fail = False
        self.clock.t += 600
        mb.poll(im)
        n.flush()
        self.assertEqual(len(self.tg.sent), 1)
        self.clock.t += 600
        mb.poll(im); n.flush()
        self.assertEqual(len(self.tg.sent), 1)
        self.assertEqual(st.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)

    def test_c2_429_retry_after(self):
        st, n, mb = self.build()
        st.enqueue("x", self.clock())
        def send(text):
            raise g.TgError(429, 77)
        n.send = send
        n.flush()
        row = st.db.execute("SELECT attempts,next_try FROM outbox").fetchone()
        self.assertEqual(row[0], 1)
        self.assertGreaterEqual(row[1], self.clock() + 77)

    def test_d_same_message_id_twice(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<4@x>", "Your verification code is 123456")
        im.msgs[2] = mail("<4@x>", "Your verification code is 123456")
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 1)
        self.assertEqual(st.mailbox("INBOX")[1], 2)

    def test_d2_same_sender_code_window(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<5@x>", "Your verification code is 123456")
        im.msgs[2] = mail("<6@x>", "Your verification code is 123456")
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 1)

    def test_e_uidvalidity_change(self):
        st, n, mb = self.build()
        im = FakeImap(uv=1, uidnext=5)
        self.baseline(mb, im)
        self.assertEqual(st.mailbox("INBOX"), (1, 4))
        im2 = FakeImap(uv=2, uidnext=3, msgs={1: mail("<7@x>", "Your verification code is 123456")})
        mb.open(im2)
        self.assertEqual(st.mailbox("INBOX"), (2, 2))
        self.assertEqual(len(self.tg.sent), 1)
        self.assertIn("UIDVALIDITY", self.tg.sent[0])
        mb.poll(im2)  # history not replayed
        self.assertEqual(len(self.tg.sent), 1)

    def test_f_restart_midway(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<8@x>", "Your verification code is 111111", frm="a@a.com")
        im.msgs[2] = mail("<9@x>", "Your verification code is 222222", frm="b@b.com")
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 2)
        # restart with failing TG for third message
        self.tg.fail = True
        im.msgs[3] = mail("<10@x>", "Your verification code is 333333", frm="c@c.com")
        mb.poll(im)
        st.close()
        st2, n2, mb2 = self.build()  # "process restarted", same db
        self.tg.fail = False
        self.clock.t += 600
        mb2.open(im)
        mb2.poll(im)
        n2.flush()
        codes = [s.split("\n")[0] for s in self.tg.sent]
        self.assertEqual(sorted(codes), sorted("🔑 <code>%d</code>" % c for c in (111111, 222222, 333333)))
        mb2.poll(im); n2.flush()
        self.assertEqual(len(self.tg.sent), 3)

    def test_f2_crash_before_commit_no_loss(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<11@x>", "Your verification code is 123456")
        orig = st.enqueue
        def boom(*a):
            raise RuntimeError("crash")
        st.enqueue = boom
        with self.assertRaises(RuntimeError):
            mb.poll(im)
        self.assertEqual(st.mailbox("INBOX")[1], 0)  # not advanced
        st.enqueue = orig
        mb.poll(im)
        self.assertEqual(len(self.tg.sent), 1)

    def test_g_fetch_readonly_peek_only(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<12@x>", "Your verification code is 123456")
        mb.poll(im)
        self.assertTrue(all(c[2] is True for c in im.calls if c[0] == "select_folder"))
        fetches = [c for c in im.calls if c[0] == "fetch"]
        self.assertTrue(fetches)
        self.assertTrue(all(c[2] == (b"BODY.PEEK[]",) for c in fetches))
        self.assertFalse([c for c in im.calls if c[0] == "MUTATION"])

    def test_old_last_message_not_replayed(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=2, msgs={1: mail("<13@x>", "Your verification code is 123456")})
        self.baseline(mb, im)
        mb.poll(im)  # N:* returns uid 1 although <= last_uid
        self.assertEqual(self.tg.sent, [])

    def test_spam_marker(self):
        st, n, mb = self.build("[Gmail]/Spam")
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<14@x>", "Your verification code is 123456")
        mb.poll(im)
        self.assertTrue(self.tg.sent[0].endswith("⚠ spam"))

    def test_escape_and_subject_cut(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<15@x>", "Your verification code is 123456", subj="<b>" + "x" * 100, frm="A&B <a@b.com>")
        mb.poll(im)
        t = self.tg.sent[0].split("\n")
        self.assertIn("A&amp;B", t[1])
        self.assertIn("&lt;b&gt;", t[2])
        self.assertLessEqual(len(t[2]), 80 + 30)

    def test_link_message(self):
        st, n, mb = self.build()
        im = FakeImap(uidnext=1)
        self.baseline(mb, im)
        im.msgs[1] = mail("<16@x>", "Please confirm your email: https://x.com/auth/confirm?token=abc", subj="Confirm email")
        mb.poll(im)
        self.assertTrue(self.tg.sent[0].startswith('🔗 <a href="https://x.com/auth/confirm?token=abc">'))

    def test_alert_antispam(self):
        st, n, mb = self.build()
        self.assertTrue(n.alert("auth", "gmail-codes: IMAP auth failed"))
        self.assertFalse(n.alert("auth", "gmail-codes: IMAP auth failed"))
        self.clock.t += 3601
        self.assertTrue(n.alert("auth", "gmail-codes: IMAP auth failed"))
        self.assertEqual(len(self.tg.sent), 2)


class Watchdog(unittest.TestCase):
    def test_decide(self):
        self.assertEqual(g.watchdog_decide(False, 5000, 9000, None, 0), (False, False))
        self.assertEqual(g.watchdog_decide(True, 10, 9000, None, 0), (False, False))
        self.assertEqual(g.watchdog_decide(True, 1000, 9000, None, 10000), (True, True))
        self.assertEqual(g.watchdog_decide(True, 1000, 9000, 9999, 10000), (True, False))
        self.assertEqual(g.watchdog_decide(True, None, 100, None, 0), (False, False))
        self.assertEqual(g.watchdog_decide(True, 5000, 100, None, 0), (False, False))  # stale hb from earlier run


class Env(unittest.TestCase):
    def test_parse(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "e")
        with open(p, "w") as f:
            f.write('# c\nA=1\nB="two"\n\nC=\n')
        self.assertEqual(g.load_env_file(p), {"A": "1", "B": "two", "C": ""})
