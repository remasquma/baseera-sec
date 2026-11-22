"""
Baseera Sec - Centralized Secure Structured Logging & Redaction Filter
يضمن حجب وتسجيل السجلات بشكل منظم دون تسريب بيانات الاعتماد (Tokens, Passwords, Keys).
"""
import logging
import re
from typing import Any

# أنماط البيانات الحساسة المراد تنقيحها تلقائياً من السجلات
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(api[_-]?key\s*[:=]\s*["\']?)[a-zA-Z0-9_\-]{8,}'), r'\1[REDACTED_KEY]'),
    (re.compile(r'(?i)((?:access[_-]?token|refresh[_-]?token|token)\s*[:=]\s*["\']?)[^"\'\s,;]{8,}'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(password\s*[:=]\s*["\']?)[^"\'\s]{3,}'), r'\1[REDACTED_PASSWORD]'),
    (re.compile(r'(?i)(secret\s*[:=]\s*["\']?)[^"\'\s]{6,}'), r'\1[REDACTED_SECRET]'),
    (re.compile(r'(?i)((?:private[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']?)[^"\'\s,;]{6,}'), r'\1[REDACTED_KEY]'),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
]

class SensitiveDataRedactor(logging.Filter):
    """مرشح لتنقيح السجلات ومنع تسريب البيانات الحساسة أو بيانات الاعتماد."""
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "uvicorn.access":
            return True
        message = record.getMessage()
        for pattern, replacement in SENSITIVE_PATTERNS:
            message = pattern.sub(replacement, message)
        record.msg = message
        record.args = ()
        return True

def setup_secure_logging(level=logging.INFO) -> logging.Logger:
    """إعداد المسجل الرئيسي مع مرشح التنقيح والتنسيق المنظم."""
    logger = logging.getLogger("baseera")
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    redactor = SensitiveDataRedactor()
    loggers = (
        logging.getLogger(),
        logger,
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("uvicorn.access"),
        logging.getLogger("fastapi"),
    )
    for configured_logger in loggers:
        for handler in configured_logger.handlers:
            if not any(isinstance(item, SensitiveDataRedactor) for item in handler.filters):
                handler.addFilter(redactor)

    return logger
