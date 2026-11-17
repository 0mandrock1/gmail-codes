import unittest
import gmail_codes as g
from email.message import EmailMessage

POS = [
    ("", "Your verification code is 123456", ["123456"]),
    ("", "Your verification code is 123 456.", ["123456"]),
    ("", "Verification code: 123-456", ["123456"]),
    ("", "Use code 4821 to sign in", ["4821"]),
    ("", "Your one-time password (OTP) is 90817235", ["90817235"]),
    ("", "Your Google verification code is G-123456", ["G-123456"]),
    ("", "Your login code: ABC-123", ["ABC-123"]),
    ("", "Security code: 7H3K9P", ["7H3K9P"]),
    ("", "Confirm your sign in. Passcode 556677", ["556677"]),
    ("", "123456 is your Instagram code", ["123456"]),
    ("", "Enter this PIN: 8821", ["8821"]),
    ("", "Authentication code\n\n304 951", ["304951"]),
    ("123456 is your Foo verification code", "Hello", ["123456"]),
    ("Your code 778899", "Welcome", ["778899"]),
    ("", "Ваш код підтвердження: 482913", ["482913"]),
    ("", "Одноразовий пароль: 5521", ["5521"]),
    ("", "Код доступу 90210123", ["90210123"]),
    ("", "Ваш код верифікації 112233. Нікому не повідомляйте.", ["112233"]),
    ("", "Ваш код подтверждения: 334455", ["334455"]),
    ("", "Используйте код 6677 для входа", ["6677"]),
    ("", "Your verification code is 123456. Order #99887 on 2024-03-15 at 10:30", ["123456"]),
    ("", "Verification code: 2045", ["2045"]),
    ("", "Your code is 123456 and your backup code is 654321", ["123456", "654321"]),
    ("", "code 111222 code 111222", ["111222"]),
]

NEG = [
    "Copyright 2024 Acme. Confirm your preferences",
    "Confirm your appointment on 2024-03-15 at 10:30",
    "Confirm your appointment on 15.03.2024",
    "Confirm your appointment on 15 March 2024",
    "Please verify your number +380 50 123 4567",
    "Please verify: call (415) 555-2671",
    "Confirm payment of $1299.00",
    "Confirm payment of 1 299 грн",
    "Confirm payment 49.99 USD",
    "Order #482913 confirmed",
    "Order 482913 confirmation",
    "Your confirmation number is 482913",
    "Your tracking number 482913 login to track",
    "Verify address: 10 Main St, zip 90210",
    "Verify address: Kyiv, індекс 01001",
    "Postal code: 01001",
    "Promo code SAVE20 sign in to use",
    "Verification ID 1234567890123456",
    "Sign in to see this week's newsletter and confirm your subscription",
    "Verify your email <color #123456> and #a1b2c3",
    "Click https://example.com/confirm/482913 to confirm",
    "Verify your account at https://example.com/v?x=123456",
    "Verify: version 3.14159 released",
    "Підтвердіть замовлення №482913",
    "Verify your account. Call us today. We are at 123456 Long Street Avenue Number 5555555555",
    "Hello, nothing to see here 123456",
]


class Pos(unittest.TestCase):
    def test_all(self):
        for subj, text, want in POS:
            with self.subTest(text=text):
                self.assertEqual(g.extract_codes(subj, text), want)

    def test_html_bold(self):
        t, _ = g.html_to_text("<html><head><style>.a{color:#123456}</style></head><body><p>Your code is <b>482913</b></p><script>var x=999999;</script></body></html>")
        self.assertEqual(g.extract_codes("", t), ["482913"])

    def test_html_table(self):
        t, _ = g.html_to_text("<table><tr><td>Verification code</td></tr><tr><td><b>731 204</b></td></tr></table>")
        self.assertEqual(g.extract_codes("", t), ["731204"])

    def test_cp1251(self):
        m = EmailMessage()
        m["Subject"] = "Код"
        m["From"] = "A <a@b.ua>"
        m.set_content("Ваш код підтвердження: 482913", charset="cp1251")
        p = g.parse_email(m.as_bytes())
        self.assertEqual(g.analyze(p), ("code", ["482913"]))

    def test_koi8r_and_rfc2047(self):
        m = EmailMessage()
        m["Subject"] = "Код подтверждения 556677"
        m["From"] = "Сервис <s@b.ru>"
        m.set_content("Привет", charset="koi8-r")
        p = g.parse_email(m.as_bytes())
        self.assertEqual(p["subject"], "Код подтверждения 556677")
        self.assertEqual(p["name"], "Сервис")
        self.assertEqual(g.analyze(p), ("code", ["556677"]))


class Neg(unittest.TestCase):
    def test_all(self):
        for text in NEG:
            with self.subTest(text=text):
                self.assertEqual(g.extract_codes("", text), [])


class Link(unittest.TestCase):
    def test_link(self):
        u = "https://x.com/auth/verify?token=abc"
        self.assertEqual(g.extract_link("Confirm your email", "Click to confirm", [u]), u)

    def test_no_keyword_no_link(self):
        self.assertIsNone(g.extract_link("Sale", "Big sale", ["https://x.com/verify?t=1"]))

    def test_unsubscribe(self):
        self.assertIsNone(g.extract_link("Confirm", "confirm", ["https://x.com/confirm/unsubscribe"]))

    def test_non_https(self):
        self.assertIsNone(g.extract_link("Confirm", "confirm", ["http://x.com/confirm"]))
