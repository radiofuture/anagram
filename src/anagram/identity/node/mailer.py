"""Mail adapters for the email sign-in fallback."""

from __future__ import annotations

import smtplib
import ssl
from abc import ABC, abstractmethod
from email.message import EmailMessage

from anagram.identity.node.checks import validate_email


class Mailer(ABC):
    @abstractmethod
    def send(self, to: str, subject: str, text: str) -> None: ...


class FakeMailer(Mailer):
    """Keeps messages in memory. For tests and local development."""

    def __init__(self) -> None:
        self.outbox: list[tuple[str, str, str]] = []

    def send(self, to: str, subject: str, text: str) -> None:
        self.outbox.append((to, subject, text))


class ConsoleMailer(Mailer):  # pragma: no cover - local development
    """Prints messages to stderr. For a local node with no mail server."""

    def send(self, to: str, subject: str, text: str) -> None:
        import sys

        print(f"[mail to {to}] {subject}\n{text}", file=sys.stderr)


def mailer_from_env():  # pragma: no cover - reads the environment
    """SMTP when ANAGRAM_SMTP_HOST is set, else the console mailer."""
    import os

    host = os.environ.get("ANAGRAM_SMTP_HOST")
    if not host:
        return ConsoleMailer()
    return SMTPMailer(
        host,
        int(os.environ.get("ANAGRAM_SMTP_PORT", "587")),
        os.environ.get("ANAGRAM_SMTP_FROM", "anagram@" + host),
        os.environ.get("ANAGRAM_SMTP_USER", ""),
        os.environ.get("ANAGRAM_SMTP_PASSWORD", ""),
    )


class SMTPMailer(Mailer):  # pragma: no cover - needs a mail server
    def __init__(self, host: str, port: int, sender: str, user: str = "", password: str = ""):
        self.host, self.port, self.sender = host, port, sender
        self.user, self.password = user, password

    def send(self, to: str, subject: str, text: str) -> None:
        to = validate_email(to)
        if "\r" in subject or "\n" in subject:
            raise ValueError("email subject must not contain newlines")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        msg.set_content(text)
        with smtplib.SMTP(self.host, self.port, timeout=30) as s:
            s.starttls(context=ssl.create_default_context())
            if self.user:
                s.login(self.user, self.password)
            s.send_message(msg, from_addr=self.sender, to_addrs=[to])
