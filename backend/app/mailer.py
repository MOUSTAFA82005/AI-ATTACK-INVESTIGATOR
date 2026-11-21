"""Sends the 6-digit login and sign-up codes by e-mail (stdlib smtplib only).

Set these on the server (never in the repository):
    AAI_SMTP_HOST      for Gmail: smtp.gmail.com
    AAI_SMTP_PORT      587 (STARTTLS, the default) or 465 (SSL)
    AAI_SMTP_USER      the sending address, e.g. yourproject@gmail.com
    AAI_SMTP_PASSWORD  for Gmail an "app password" (Google account > Security > App passwords),
                       not the normal Gmail password
    AAI_MAIL_FROM      optional, the From address (default: AAI_SMTP_USER)

Instead of typing these in every new terminal, put them in config/mail.env (one KEY=value per
line; config/ is never committed). The server reads that file when it starts; a variable that is
already set in the terminal wins over the file. Example: deploy/mail.env.example.

Without AAI_SMTP_HOST the server runs in "console mode": the code is printed in the server's
terminal instead of being sent. That is for trying the site on your own laptop only; behind the
hosted demo's proxy (AAI_BEHIND_PROXY=1) console mode is refused, because nobody could read it.
"""
import html
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path

APP = "TALON INVESTIGATOR"
SUBJECTS = {
    "login": "Your login code",
    "verify": "Confirm your e-mail address",
    "change": "Your code to change the password",
    "exists": "Someone tried to sign up with your e-mail",
    "changed": "Your password was changed",
}
LINES = {
    "login": "Use this code to finish logging in.",
    "verify": "Use this code to confirm your e-mail address and finish creating your account.",
    "change": "Use this code to change your password.",
    "exists": ("Someone tried to create a new account with this e-mail address, but you already have one. "
               "If it was you, log in instead. If it was not you, nothing changed and you can ignore this e-mail."),
    "changed": ("The password of your account was just changed and every login was ended. "
                "If you did not do this, ask the project team to lock the account now."),
}
# Purposes that carry no code: the e-mail only tells the owner that something happened.
NOTICES = {"exists", "changed"}


TITLES = {
    "login": "Your login code",
    "verify": "Confirm your e-mail",
    "change": "Change your password",
    "exists": "You already have an account",
    "changed": "Your password was changed",
}
LOGO = Path(__file__).with_name("assets") / "mail-logo.png"

# Colours from the site's theme (frontend/static/css/base.css). E-mail clients ignore CSS
# variables, so every style is written inline on tables.
INK, CARD, LINE, BOX, ACCENT, ACCENT2, ACCENT3 = "#070b18", "#0e1428", "#262d45", "#141b36", "#8f9bff", "#4fe3d1", "#c88bff"
FONT = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace"

# Gmail's apps turn dark e-mails light when the phone is in dark mode. Two tricks stop that:
# 1. backgrounds are also given as a background-image (Gmail does not touch images), and
# 2. text is white and sits inside two blend layers that only Gmail applies (the "u + .body"
#    selector matches only there); they undo Gmail's colour change. Grey text is white with
#    opacity, so it survives too.
GMAIL_FIX = ("u + .body .gm-screen{background:#000;mix-blend-mode:screen;}"
             "u + .body .gm-diff{background:#000;mix-blend-mode:difference;}")


def _bg(color):
    return f'bgcolor="{color}" style="background-color:{color};background-image:linear-gradient({color},{color});'


def _text(inner, css):
    """White text that keeps its colour in Gmail's dark mode."""
    return (f'<div class="gm-screen"><div class="gm-diff"><div style="color:#ffffff;{css}">{inner}</div></div></div>')


def build_html(code, purpose, logo_cid=None):
    """The HTML part: dark card, falcon logo, the code in six boxes (no boxes when code is None)."""
    code = code or ""
    title = html.escape(TITLES.get(purpose, "Your code"))
    line = html.escape(LINES.get(purpose, "Use this code."))
    digits = "".join(
        f'<td {_bg(ACCENT)}padding:1px;border-radius:12px;">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td align="center" width="44" height="54" {_bg(BOX)}width:44px;height:54px;border-radius:11px;">'
        + _text(html.escape(d), f"font:700 28px/54px {MONO};") + '</td></tr></table></td>'
        + ('<td style="width:8px;font-size:0;">&nbsp;</td>' if i < len(code) - 1 else "")
        for i, d in enumerate(code))
    logo = (f'<img src="cid:{logo_cid}" width="44" height="44" alt="" style="display:block;border:0;">'
            if logo_cid else "")
    if code:
        preheader = f"{html.escape(code)} is your {APP} code. It works once, for 10 minutes."
        code_block = f"""        <tr><td align="center" style="padding:26px 20px 12px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>{digits}</tr></table>
        </td></tr>
        <tr><td align="center" style="padding:6px 36px 30px;">
          {_text("The code works once and ends in <b>10 minutes</b>.", f"font:400 13px/1.6 {FONT};opacity:.6;")}
        </td></tr>"""
        footer = ("Did not ask for this? Ignore this e-mail. Nobody can log in without your password, "
                  "and we will never ask you for this code.")
    else:
        preheader = title
        code_block = '        <tr><td style="height:26px;font-size:0;">&nbsp;</td></tr>'
        footer = "This e-mail has no code and no link. We will never ask you for your password."
    rule = f'<div {_bg(LINE)}height:1px;line-height:1px;font-size:0;">&nbsp;</div>'.replace('bgcolor="' + LINE + '" ', "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark only"><meta name="supported-color-schemes" content="dark only"><title>{title}</title>
<style>:root{{color-scheme:dark only;}} {GMAIL_FIX}</style></head>
<body class="body" style="margin:0;padding:0;background-color:{INK};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" {_bg(INK)}">
<tr><td align="center" style="padding:40px 16px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">
    <tr><td style="padding:0 4px 22px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="padding-right:12px;vertical-align:middle;">{logo}</td>
        <td style="vertical-align:middle;">
          {_text("TALON", f"font:800 20px/1 {FONT};letter-spacing:1px;")}
          {_text("INVESTIGATOR", f"font:600 10px/1 {FONT};letter-spacing:3px;opacity:.65;padding-top:4px;")}
        </td></tr></table>
    </td></tr>
    <tr><td {_bg(LINE)}padding:1px;border-radius:20px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" {_bg(CARD)}border-radius:19px;overflow:hidden;">
        <tr><td height="4" bgcolor="{ACCENT}" style="height:4px;line-height:4px;font-size:0;background-color:{ACCENT};background-image:linear-gradient(90deg,{ACCENT},{ACCENT3},{ACCENT2});border-radius:19px 19px 0 0;">&nbsp;</td></tr>
        <tr><td style="padding:34px 36px 8px;">
          {_text(title, f"font:700 26px/1.25 {FONT};padding-bottom:10px;")}
          {_text(line, f"font:400 15px/1.6 {FONT};opacity:.72;")}
        </td></tr>
{code_block}
        <tr><td style="padding:0 36px;">{rule}</td></tr>
        <tr><td style="padding:20px 36px 30px;">
          {_text(footer, f"font:400 13px/1.6 {FONT};opacity:.68;")}
        </td></tr>
    </table>
    </td></tr>
    <tr><td align="center" style="padding:22px 8px 0;">
      {_text(f"{APP} &middot; finds the attacks in your web logs<br>This is an automatic message, replies are not read.", f"font:400 12px/1.6 {FONT};opacity:.45;")}
    </td></tr>
  </table>
</td></tr></table>
</body></html>"""


SETTINGS_FILE = Path(__file__).resolve().parents[2] / "config" / "mail.env"


def load_settings(path=SETTINGS_FILE, env=None):
    """Copy AAI_* settings from a KEY=value file into the environment (existing ones win).

    Returns the names that were set. Blank lines and lines starting with # are skipped;
    quotes around a value are removed. A missing file is not an error.
    """
    env = os.environ if env is None else env
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return []
    loaded = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.lower().startswith("export "):
            key = key[7:].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key.startswith("AAI_") and key not in env:
            env[key] = value
            loaded.append(key)
    return loaded


class MailError(RuntimeError):
    """The code could not be sent; the message is safe to show to the user."""


def smtp_ready(env=None):
    env = os.environ if env is None else env
    return bool(env.get("AAI_SMTP_HOST"))


def console_mode_allowed(env=None):
    env = os.environ if env is None else env
    return not smtp_ready(env) and env.get("AAI_BEHIND_PROXY") != "1"


def build_message(to, code, purpose, sender):
    msg = EmailMessage()
    msg["Subject"] = f"{SUBJECTS.get(purpose, 'Your code')}: {code}" if code else SUBJECTS[purpose]
    msg["From"] = f"{APP} <{sender}>"
    msg["To"] = to
    if code:
        msg.set_content(
            f"{LINES.get(purpose, 'Your code:')}\n\n    {code}\n\n"
            "The code works once and ends in 10 minutes.\n"
            "If you did not ask for it, ignore this e-mail; nobody can log in without your password.\n\n"
            f"{APP}\n")
    else:
        msg.set_content(f"{LINES[purpose]}\n\nThis e-mail has no code and no link.\n\n{APP}\n")
    # HTML version with the falcon logo attached inline (cid:), so it shows without loading
    # anything from the internet. Mail apps that cannot show HTML use the text above.
    cid = make_msgid(domain="talon.local")[1:-1] if LOGO.exists() else None
    msg.add_alternative(build_html(code, purpose, cid), subtype="html")
    if cid:
        msg.get_payload()[1].add_related(LOGO.read_bytes(), maintype="image", subtype="png", cid=f"<{cid}>",
                                         filename="talon.png", disposition="inline")
    return msg


def send_code(to, code, purpose, env=None):
    """Send `code` to `to`. Raises MailError when it cannot be delivered."""
    env = os.environ if env is None else env
    if not smtp_ready(env):
        if not console_mode_allowed(env):
            raise MailError("E-mail is not set up on this server yet. Ask the project team.")
        print(f"[console mode] {purpose} {'code' if code else 'notice'} for {to}: {code or SUBJECTS[purpose]}",
              file=sys.stderr, flush=True)
        return
    host = env["AAI_SMTP_HOST"].strip()
    port = int(env.get("AAI_SMTP_PORT") or 587)
    user, password = env.get("AAI_SMTP_USER", "").strip(), env.get("AAI_SMTP_PASSWORD", "").replace(" ", "")
    if user and not password:
        print("[mail] AAI_SMTP_PASSWORD is empty (set it in config/mail.env)", file=sys.stderr, flush=True)
        raise MailError("E-mail is not set up on this server yet. Ask the project team.")
    msg = build_message(to, code, purpose, env.get("AAI_MAIL_FROM") or user)
    # Try the configured port first. If the connection itself fails (a network or antivirus
    # that blocks one port), try Gmail's other port once. A wrong password is not retried.
    ports = [port] + [p for p in (587, 465) if p != port]
    for i, p in enumerate(ports):
        try:
            _deliver(host, p, user, password, msg)
            if i:
                print(f"[mail] port {port} failed, sent on port {p}; set AAI_SMTP_PORT={p}", file=sys.stderr, flush=True)
            return
        except _StepError as e:
            print(f"[mail] sending to {to} failed on port {p} at step '{e.step}': {e.detail}", file=sys.stderr, flush=True)
            if e.step == "login" or i == len(ports) - 1:
                raise MailError("The e-mail could not be sent. Try again in a minute.") from None


def send_notice(to, purpose, env=None):
    """An e-mail without a code ('exists' or 'changed'). Never raises: a notice is a courtesy,
    and failing the request because of it would tell a stranger something."""
    assert purpose in NOTICES
    try:
        send_code(to, None, purpose, env)
    except MailError:
        pass


class _StepError(Exception):
    def __init__(self, step, err):
        super().__init__(step)
        self.step, self.detail = step, f"{type(err).__name__}: {err}"


def _deliver(host, port, user, password, msg):
    """One attempt; raises _StepError naming the step that failed (connect, tls, login, send)."""
    context = ssl.create_default_context()
    step = "connect"
    try:
        s = (smtplib.SMTP_SSL(host, port, timeout=15, context=context) if port == 465
             else smtplib.SMTP(host, port, timeout=15))
        with s:
            if port != 465:
                step = "tls"
                s.starttls(context=context)
            if user:
                step = "login"
                s.login(user, password)
            step = "send"
            s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise _StepError(step, e) from None


def save_password(path=SETTINGS_FILE):
    """Ask for the Gmail app password (hidden while typing) and store it in config/mail.env."""
    import getpass
    pw = getpass.getpass("Paste the Gmail app password (nothing shows while you type), then Enter: ").replace(" ", "")
    if not pw:
        sys.exit("Nothing typed, the file was not changed.")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8-sig").splitlines() if path.exists() else []
    lines = [ln for ln in lines if not ln.strip().startswith("AAI_SMTP_PASSWORD")]
    lines.append(f"AAI_SMTP_PASSWORD={pw}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Saved ({len(pw)} characters) in {path}")


if __name__ == "__main__":
    # Store the app password:      python -m backend.app.mailer --set-password
    # Send a test code by e-mail:  python -m backend.app.mailer you@example.com
    if sys.argv[1:] == ["--set-password"]:
        save_password()
        sys.exit(0)
    if len(sys.argv) != 2 or "@" not in sys.argv[1]:
        sys.exit("usage: python -m backend.app.mailer --set-password | you@example.com")
    for name in load_settings():
        print(f"[settings] read {name} from config/mail.env")
    try:
        send_code(sys.argv[1], "123456", "login")
        print("OK: test e-mail sent" if smtp_ready() else "console mode: AAI_SMTP_HOST is not set")
    except MailError as e:
        sys.exit(f"FAILED: {e} (the [mail] lines above say why)")
