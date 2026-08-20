"""Safe metadata extraction — read-only analysis, never executes files."""

import os
from datetime import datetime, timezone

from forensic.file_classifier import get_extension, guess_mime_type

TIMESTAMP_NOTE = (
    "File system timestamps may reflect the uploaded copy and should be interpreted with forensic caution."
)


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "Not Available"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "Not Available"


def extract_filesystem_metadata(file_path: str, original_filename: str) -> list[dict]:
    ext = get_extension(original_filename)
    mime = guess_mime_type(original_filename)
    size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
    st = os.stat(file_path) if os.path.isfile(file_path) else None

    rows = [
        ("Original File Name", original_filename, "General"),
        ("File Extension", ext or "Not Available", "General"),
        ("MIME Type", mime, "General"),
        ("File Size", f"{size:,} bytes", "General"),
        ("Created Date", _fmt_ts(st.st_ctime if st else None), "File System"),
        ("Modified Date", _fmt_ts(st.st_mtime if st else None), "File System"),
        ("Last Accessed Date", _fmt_ts(st.st_atime if st else None), "File System"),
        ("Forensic Note", TIMESTAMP_NOTE, "General"),
    ]
    return [{"key": k, "value": v, "category": c} for k, v, c in rows]


def _convert_gps(coord, ref) -> float | None:
    try:
        d = float(coord[0])
        m = float(coord[1])
        s = float(coord[2])
        decimal = d + (m / 60.0) + (s / 3600.0)
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def extract_image_metadata(file_path: str) -> list[dict]:
    rows = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        with Image.open(file_path) as img:
            rows.append(("Width", str(img.width), "Image"))
            rows.append(("Height", str(img.height), "Image"))
            rows.append(("Image Format", img.format or "Not Available", "Image"))
            rows.append(("Color Mode", img.mode or "Not Available", "Image"))

            exif = img.getexif()
            if not exif:
                rows.extend([
                    ("Camera Make", "Not Available", "Image"),
                    ("Camera Model", "Not Available", "Image"),
                    ("Date Taken", "Not Available", "Image"),
                    ("Software", "Not Available", "Image"),
                    ("Orientation", "Not Available", "Image"),
                    ("GPS Available", "No", "GPS"),
                ])
                return [{"key": k, "value": v, "category": c} for k, v, c in rows]

            parsed = {}
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                parsed[tag] = value

            rows.append(("Camera Make", str(parsed.get("Make", "Not Available")), "Image"))
            rows.append(("Camera Model", str(parsed.get("Model", "Not Available")), "Image"))
            rows.append(("Date Taken", str(parsed.get("DateTimeOriginal", parsed.get("DateTime", "Not Available"))), "Image"))
            rows.append(("Software", str(parsed.get("Software", "Not Available")), "Image"))
            rows.append(("Orientation", str(parsed.get("Orientation", "Not Available")), "Image"))

            gps_info = parsed.get("GPSInfo")
            if gps_info:
                gps = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
                lat = _convert_gps(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef"))
                lon = _convert_gps(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef"))
                rows.append(("GPS Available", "Yes", "GPS"))
                rows.append(("Latitude", str(lat) if lat is not None else "Not Available", "GPS"))
                rows.append(("Longitude", str(lon) if lon is not None else "Not Available", "GPS"))
            else:
                rows.extend([
                    ("GPS Available", "No", "GPS"),
                    ("Latitude", "Not Available", "GPS"),
                    ("Longitude", "Not Available", "GPS"),
                ])
    except Exception:
        rows.extend([
            ("Width", "Not Available", "Image"),
            ("Height", "Not Available", "Image"),
            ("Image Format", "Not Available", "Image"),
            ("Color Mode", "Not Available", "Image"),
            ("Camera Make", "Not Available", "Image"),
            ("Camera Model", "Not Available", "Image"),
            ("Date Taken", "Not Available", "Image"),
            ("GPS Available", "No", "GPS"),
        ])
    return [{"key": k, "value": v, "category": c} for k, v, c in rows]


def extract_pdf_metadata(file_path: str) -> list[dict]:
    rows = []
    try:
        from pypdf import PdfReader

        reader = PdfReader(file_path)
        meta = reader.metadata or {}
        rows = [
            ("Title", str(meta.get("/Title") or "Not Available"), "Document"),
            ("Author", str(meta.get("/Author") or "Not Available"), "Document"),
            ("Subject", str(meta.get("/Subject") or "Not Available"), "Document"),
            ("Creator", str(meta.get("/Creator") or "Not Available"), "Document"),
            ("Producer", str(meta.get("/Producer") or "Not Available"), "Document"),
            ("Creation Date", str(meta.get("/CreationDate") or "Not Available"), "Document"),
            ("Modification Date", str(meta.get("/ModDate") or "Not Available"), "Document"),
            ("Number of Pages", str(len(reader.pages)), "Document"),
        ]
    except Exception:
        rows = [
            ("Title", "Not Available", "Document"),
            ("Author", "Not Available", "Document"),
            ("Number of Pages", "Not Available", "Document"),
        ]
    return [{"key": k, "value": v, "category": c} for k, v, c in rows]


def extract_docx_metadata(file_path: str) -> list[dict]:
    rows = []
    try:
        from docx import Document

        doc = Document(file_path)
        cp = doc.core_properties
        rows = [
            ("Title", str(cp.title or "Not Available"), "Document"),
            ("Author", str(cp.author or "Not Available"), "Document"),
            ("Subject", str(cp.subject or "Not Available"), "Document"),
            ("Keywords", str(cp.keywords or "Not Available"), "Document"),
            ("Created Date", str(cp.created or "Not Available"), "Document"),
            ("Modified Date", str(cp.modified or "Not Available"), "Document"),
            ("Last Modified By", str(cp.last_modified_by or "Not Available"), "Document"),
        ]
    except Exception:
        rows = [
            ("Title", "Not Available", "Document"),
            ("Author", "Not Available", "Document"),
            ("Modified Date", "Not Available", "Document"),
        ]
    return [{"key": k, "value": v, "category": c} for k, v, c in rows]


def extract_all_metadata(file_path: str, original_filename: str) -> list[dict]:
    items = extract_filesystem_metadata(file_path, original_filename)
    ext = get_extension(original_filename)

    if ext in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}:
        items.extend(extract_image_metadata(file_path))
    elif ext == ".pdf":
        items.extend(extract_pdf_metadata(file_path))
    elif ext == ".docx":
        items.extend(extract_docx_metadata(file_path))

    return items
