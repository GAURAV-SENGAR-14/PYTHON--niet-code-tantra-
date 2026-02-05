"""Configuration defaults for the keylogger detector."""

from __future__ import annotations

EXFILTRATION_PORTS = {25, 465, 587, 2525}
SUSPICIOUS_KEYWORDS = {
    "keylog",
    "hook",
    "logger",
    "keystroke",
    "record",
    "capture",
    "spy",
}

CPU_PERCENT_THRESHOLD = 70.0
MEMORY_PERCENT_THRESHOLD = 25.0

DEFAULT_SAMPLE_INTERVAL = 1.0
