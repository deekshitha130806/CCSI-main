"""Evidence type suggestion from file extension — no file execution."""

import mimetypes
import os

EVIDENCE_TYPES = [
    "Images",
    "Videos",
    "Documents",
    "Hard Disk Image",
    "USB Dump",
    "Memory Dump",
    "Mobile Backup",
    "Audio Files",
    "Log Files",
    "Archive",
    "Executable",
    "Script",
    "Other",
]

EXTENSION_MAP = {
    ".jpg": "Images",
    ".jpeg": "Images",
    ".png": "Images",
    ".webp": "Images",
    ".gif": "Images",
    ".bmp": "Images",
    ".mp4": "Videos",
    ".avi": "Videos",
    ".mov": "Videos",
    ".mkv": "Videos",
    ".wmv": "Videos",
    ".pdf": "Documents",
    ".doc": "Documents",
    ".docx": "Documents",
    ".txt": "Documents",
    ".xlsx": "Documents",
    ".xls": "Documents",
    ".csv": "Documents",
    ".rtf": "Documents",
    ".log": "Log Files",
    ".mp3": "Audio Files",
    ".wav": "Audio Files",
    ".m4a": "Audio Files",
    ".zip": "Archive",
    ".rar": "Archive",
    ".7z": "Archive",
    ".tar": "Archive",
    ".gz": "Archive",
    ".exe": "Executable",
    ".dll": "Executable",
    ".msi": "Executable",
    ".bat": "Script",
    ".cmd": "Script",
    ".ps1": "Script",
    ".vbs": "Script",
    ".js": "Script",
    ".py": "Script",
    ".sh": "Script",
    ".img": "Hard Disk Image",
    ".dd": "Hard Disk Image",
    ".e01": "Hard Disk Image",
    ".iso": "Hard Disk Image",
    ".dmg": "Hard Disk Image",
}


def get_extension(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lower()


def suggest_evidence_type(filename: str) -> str:
    ext = get_extension(filename)
    return EXTENSION_MAP.get(ext, "Other")


def guess_mime_type(filename: str) -> str:
    mime, _ = mimetypes.guess_type(filename or "")
    return mime or "application/octet-stream"
