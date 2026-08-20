"""Rule-based risk assessment — does not execute or scan file contents."""

import os
import re

from forensic.file_classifier import get_extension
from forensic.integrity_checker import INTEGRITY_MISSING, INTEGRITY_MODIFIED

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".msi", ".scr", ".com"}
SUSPICIOUS_KEYWORDS = [
    "malware",
    "password",
    "credential",
    "dump",
    "keylog",
    "ransom",
    "exploit",
    "payload",
    "backdoor",
    "trojan",
]


def analyze_risk(filename: str, file_size: int, integrity_status: str) -> dict:
    indicators = []
    score = 0
    ext = get_extension(filename)
    base = os.path.basename(filename or "").lower()

    if ext in EXECUTABLE_EXTENSIONS:
        indicators.append("Executable file extension detected")
        score += 30

    if ext in SCRIPT_EXTENSIONS:
        indicators.append("Script file extension detected")
        score += 25

    if re.search(r"\.[a-z0-9]{1,8}\.[a-z0-9]{1,8}$", base):
        indicators.append("Potential double extension detected")
        score += 20

    if base.startswith(".") or ".." in base:
        indicators.append("Hidden or unusual filename pattern")
        score += 10

    unusual = ext and ext not in {
        ".jpg", ".jpeg", ".png", ".webp", ".gif", ".pdf", ".doc", ".docx",
        ".txt", ".log", ".mp4", ".avi", ".mov", ".zip", ".rar", ".7z",
        ".mp3", ".wav", ".xlsx", ".csv",
    }
    if unusual and ext not in EXECUTABLE_EXTENSIONS and ext not in SCRIPT_EXTENSIONS:
        indicators.append("Unusual file extension")
        score += 10

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in base:
            indicators.append(f"Suspicious filename keyword: {kw}")
            score += 15
            break

    if integrity_status == INTEGRITY_MODIFIED:
        indicators.append("Hash mismatch — integrity modified")
        score += 35
    elif integrity_status == INTEGRITY_MISSING:
        indicators.append("Evidence file missing from storage")
        score += 40

    if file_size and file_size > 500 * 1024 * 1024:
        indicators.append("Very large file size")
        score += 10

    score = min(score, 100)

    if score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    elif score <= 75:
        level = "High"
    else:
        level = "Critical"

    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "review_status": "Requires Investigator Review" if score > 20 else "No Immediate Concerns",
    }
