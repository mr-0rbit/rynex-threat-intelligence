"""Alert notification dispatch: Telegram, SMTP email, generic webhooks.

Fire-and-forget with full error isolation: a broken notifier never blocks
ingestion. Channels activate only when their environment is configured.
"""

import asyncio
import logging
from datetime import UTC, datetime

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert

logger = logging.getLogger("rtip.notifications")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


def format_alert_text(alert: Alert) -> str:
    published = alert.first_published_at.strftime("%Y-%m-%d %H:%M UTC") if alert.first_published_at else "unknown"
    lines = [
        f"{SEVERITY_EMOJI.get(alert.severity, '⚪')} RTIP Alert [{alert.severity.upper()}] — {alert.title}",
        "",
        f"Category: {alert.category}",
        f"Confidence: {alert.confidence:.0%}",
        f"Published: {published}",
        f"Detected: {alert.detected_at.strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    if alert.description:
        lines.append("")
        lines.append(alert.description[:600])
    if alert.evidence_sources:
        src = alert.evidence_sources[0]
        if src.get("url"):
            lines.append("")
            lines.append(f"Source: {src['url']}")
    if alert.recommended_action:
        lines.append("")
        lines.append(f"Recommended action: {alert.recommended_action}")
    return "\n".join(lines)


async def send_telegram(text: str) -> bool:
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                url,
                json={"chat_id": settings.TELEGRAM_CHAT_ID, "text": text},
            )
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("telegram notification failed: %s", exc)
        return False


def _smtp_send_sync(text: str, subject: str) -> bool:
    import smtplib
    from email.mime.text import MIMEText

    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        return False
    msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = settings.SMTP_FROM  # ops inbox pattern; configurable later per rules
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as smtp:
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                smtp.starttls()
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("email notification failed: %s", exc)
        return False


async def send_email(text: str, subject: str | None = None) -> bool:
    if not settings.SMTP_HOST:
        return False
    subject = subject or "RTIP Alert"
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _smtp_send_sync, text, subject)


async def send_webhook(alert: Alert, text: str) -> bool:
    if not settings.WEBHOOK_URL:
        return False
    payload = {
        "platform": "rtip",
        "alert_id": str(alert.id),
        "title": alert.title,
        "category": alert.category,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.status,
        "detected_at": alert.detected_at.isoformat(),
        "evidence_sources": alert.evidence_sources,
        "text": text,
        "generated_at": datetime.now(UTC).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(settings.WEBHOOK_URL, json=payload)
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("webhook notification failed: %s", exc)
        return False


def configured_channels() -> list[str]:
    channels = []
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
        channels.append("telegram")
    if settings.SMTP_HOST:
        channels.append("email")
    if settings.WEBHOOK_URL:
        channels.append("webhook")
    return channels


async def dispatch_alert(alert: Alert) -> list[str]:
    """Send one alert through all configured channels. Returns delivered channels."""
    text = format_alert_text(alert)
    results = await asyncio.gather(
        send_telegram(text),
        send_email(text, subject=f"[RTIP][{alert.severity.upper()}] {alert.title[:120]}"),
        send_webhook(alert, text),
        return_exceptions=True,
    )
    delivered = [
        channel
        for channel, ok in zip(("telegram", "email", "webhook"), results)
        if ok is True
    ]
    if delivered:
        logger.info(
            "alert notification delivered",
            extra={"source_id": alert.fingerprint, "records": len(delivered)},
        )
    return delivered
