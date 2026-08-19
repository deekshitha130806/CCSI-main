import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Step 1 note: dev default only; override via env var in real deployments
SECRET_KEY = os.environ.get("CCSI_SECRET_KEY", "dev-only-change-this-secret")

DB_PATH = os.path.join(BASE_DIR, "database", "ccsi.db")

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
# Set True only when serving over HTTPS
SESSION_COOKIE_SECURE = False
# Non-permanent session cookies — expire when the browser session ends
SESSION_PERMANENT = False

# Upload limits
MAX_SUSPECT_PHOTO_BYTES = int(os.environ.get("CCSI_MAX_SUSPECT_PHOTO_BYTES", str(5 * 1024 * 1024)))
MAX_EVIDENCE_UPLOAD_BYTES = int(os.environ.get("CCSI_MAX_EVIDENCE_UPLOAD_BYTES", str(100 * 1024 * 1024)))
MAX_CONTENT_LENGTH = MAX_EVIDENCE_UPLOAD_BYTES

SUSPECT_PHOTO_DIR = os.path.join(BASE_DIR, "static", "uploads", "suspects")
EVIDENCE_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "evidence")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

ALLOWED_SUSPECT_PHOTO_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

