"""Evidence, custody, and analysis database/service helpers."""

import os
import re
import secrets
import shutil
import sqlite3
from datetime import datetime, timezone

import config
from forensic.file_classifier import EVIDENCE_TYPES, get_extension, guess_mime_type, suggest_evidence_type
from forensic.hash_analyzer import calculate_all_hashes
from forensic.integrity_checker import (
    INTEGRITY_AUTHENTIC,
    INTEGRITY_MISSING,
    INTEGRITY_MODIFIED,
    INTEGRITY_NOT_VERIFIED,
    verify_integrity,
)
from forensic.metadata_analyzer import extract_all_metadata
from forensic.risk_analyzer import analyze_risk


def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_valid_evidence_id(eid: str) -> bool:
    return bool(re.fullmatch(r"CCSI-EVD-\d{6}", eid))


def generate_next_evidence_id() -> str:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT evidence_id FROM evidence ORDER BY evidence_id DESC LIMIT 1;"
        ).fetchone()
        if not row:
            return "CCSI-EVD-000001"
        try:
            seq = int(row["evidence_id"].split("-")[-1])
        except Exception:
            seq = 0
        return f"CCSI-EVD-{seq + 1:06d}"


def generate_next_custody_id() -> str:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT custody_id FROM chain_of_custody ORDER BY custody_id DESC LIMIT 1;"
        ).fetchone()
        if not row:
            return "CCSI-COC-000001"
        try:
            seq = int(row["custody_id"].split("-")[-1])
        except Exception:
            seq = 0
        return f"CCSI-COC-{seq + 1:06d}"


def safe_evidence_path(case_id: str, evidence_id: str, stored_filename: str) -> str:
    base = os.path.abspath(config.EVIDENCE_UPLOAD_DIR)
    rel = os.path.join(case_id, evidence_id, stored_filename)
    full = os.path.abspath(os.path.join(base, rel))
    if not full.startswith(base + os.sep) and full != base:
        raise ValueError("Invalid storage path.")
    return full


def record_custody(
    evidence_id: str,
    case_id: str,
    action: str,
    performed_by: str,
    investigator_id: str,
    details: str,
    prev_sha256: str | None = None,
    curr_sha256: str | None = None,
):
    cid = generate_next_custody_id()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO chain_of_custody
            (custody_id, evidence_id, case_id, action, performed_by, investigator_id,
             action_date, details, previous_sha256, current_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (cid, evidence_id, case_id, action, performed_by, investigator_id, now_utc_str(), details, prev_sha256, curr_sha256),
        )
        conn.commit()


def save_evidence_metadata(evidence_id: str, items: list[dict]):
    ts = now_utc_str()
    with get_conn() as conn:
        conn.execute("DELETE FROM evidence_metadata WHERE evidence_id = ?;", (evidence_id,))
        for item in items:
            conn.execute(
                """
                INSERT INTO evidence_metadata (evidence_id, metadata_key, metadata_value, metadata_category, created_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (evidence_id, item["key"], item["value"], item["category"], ts),
            )
        conn.commit()


def get_evidence_by_id(evidence_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM evidence WHERE evidence_id = ? LIMIT 1;", (evidence_id,)).fetchone()
        return dict(row) if row else None


def get_evidence_for_case(case_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY id DESC;", (case_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def search_evidence(q: str = "", case_id: str = "", evidence_type: str = "", integrity_status: str = ""):
    sql = "SELECT * FROM evidence WHERE 1=1"
    params = []
    if q:
        like = f"%{q}%"
        sql += " AND (evidence_id LIKE ? OR original_filename LIKE ? OR case_id LIKE ? OR uploaded_by LIKE ? OR evidence_type LIKE ?)"
        params.extend([like, like, like, like, like])
    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    if evidence_type:
        sql += " AND evidence_type = ?"
        params.append(evidence_type)
    if integrity_status:
        sql += " AND integrity_status = ?"
        params.append(integrity_status)
    sql += " ORDER BY id DESC"
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_evidence_summary():
    with get_conn() as conn:
        total = int(conn.execute("SELECT COUNT(1) AS c FROM evidence;").fetchone()["c"])
        verified = int(conn.execute("SELECT COUNT(1) AS c FROM evidence WHERE integrity_status = ?;", (INTEGRITY_AUTHENTIC,)).fetchone()["c"])
        modified = int(conn.execute("SELECT COUNT(1) AS c FROM evidence WHERE integrity_status = ?;", (INTEGRITY_MODIFIED,)).fetchone()["c"])
        pending = int(conn.execute("SELECT COUNT(1) AS c FROM evidence WHERE integrity_status = ?;", (INTEGRITY_NOT_VERIFIED,)).fetchone()["c"])
        return {"total": total, "verified": verified, "modified": modified, "pending": pending}


def get_evidence_counts():
    with get_conn() as conn:
        total = int(conn.execute("SELECT COUNT(1) AS c FROM evidence;").fetchone()["c"])
        pending = int(conn.execute("SELECT COUNT(1) AS c FROM evidence WHERE integrity_status = ?;", (INTEGRITY_NOT_VERIFIED,)).fetchone()["c"])
        return {"total": total, "pending": pending}


def get_evidence_type_distribution():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT evidence_type, COUNT(1) AS c FROM evidence GROUP BY evidence_type ORDER BY c DESC;"
        ).fetchall()
        return {r["evidence_type"]: int(r["c"]) for r in rows}


def get_metadata_for_evidence(evidence_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT metadata_key, metadata_value, metadata_category FROM evidence_metadata WHERE evidence_id = ? ORDER BY id;",
            (evidence_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_analysis_for_evidence(evidence_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM evidence_analysis WHERE evidence_id = ? ORDER BY id DESC LIMIT 1;",
            (evidence_id,),
        ).fetchone()
        return dict(row) if row else None


def get_custody_events(case_id: str = "", evidence_id: str = "", action: str = "", q: str = ""):
    sql = "SELECT * FROM chain_of_custody WHERE 1=1"
    params = []
    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    if evidence_id:
        sql += " AND evidence_id = ?"
        params.append(evidence_id)
    if action:
        sql += " AND action = ?"
        params.append(action)
    if q:
        like = f"%{q}%"
        sql += " AND (details LIKE ? OR performed_by LIKE ? OR investigator_id LIKE ?)"
        params.extend([like, like, like])
    sql += " ORDER BY id DESC"
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_custody_for_case(case_id: str, limit: int = 20):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM chain_of_custody WHERE case_id = ? ORDER BY id DESC LIMIT ?;",
            (case_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def run_integrity_verification(evidence: dict) -> dict:
    try:
        path = safe_evidence_path(evidence["case_id"], evidence["evidence_id"], evidence["stored_filename"])
    except ValueError:
        path = None

    result = verify_integrity(
        path or "",
        evidence.get("original_md5"),
        evidence.get("original_sha1"),
        evidence.get("original_sha256"),
    )
    verified_at = now_utc_str()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE evidence SET current_md5_hash = ?, current_sha1_hash = ?, current_sha256_hash = ?,
                integrity_status = ?, last_verified_at = ?, updated_at = ?
            WHERE evidence_id = ?;
            """,
            (
                result["current_md5"],
                result["current_sha1"],
                result["current_sha256"],
                result["integrity_status"],
                verified_at,
                verified_at,
                evidence["evidence_id"],
            ),
        )
        conn.commit()
    return {**result, "last_verified_at": verified_at}


def run_risk_analysis(evidence: dict) -> dict:
    risk = analyze_risk(
        evidence.get("original_filename", ""),
        evidence.get("file_size", 0),
        evidence.get("integrity_status", INTEGRITY_NOT_VERIFIED),
    )
    indicators_text = "; ".join(risk["indicators"]) if risk["indicators"] else "None"
    ts = now_utc_str()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO evidence_analysis
            (evidence_id, risk_score, risk_level, indicators, review_status, analyzed_at, analyzed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                evidence["evidence_id"],
                risk["risk_score"],
                risk["risk_level"],
                indicators_text,
                risk["review_status"],
                ts,
                evidence.get("uploaded_by", ""),
            ),
        )
        conn.commit()
    return risk


def upload_evidence_file(
    file,
    case_id: str,
    evidence_id: str,
    evidence_type: str,
    notes: str,
    investigator: dict,
) -> tuple[str | None, str | None]:
    if not file or not file.filename:
        return None, "No file selected."

    original = os.path.basename(file.filename)
    ext = get_extension(original)
    stored = f"evd_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(10)}{ext or '.bin'}"
    dir_rel = os.path.join(case_id, evidence_id)
    abs_dir = os.path.join(config.EVIDENCE_UPLOAD_DIR, case_id, evidence_id)
    os.makedirs(abs_dir, exist_ok=True)
    abs_path = os.path.join(abs_dir, stored)

    try:
        file.save(abs_path)
    except Exception:
        return None, "Upload failed. Please try again."

    size = os.path.getsize(abs_path)
    if size > config.MAX_EVIDENCE_UPLOAD_BYTES:
        os.remove(abs_path)
        return None, f"File exceeds maximum size of {config.MAX_EVIDENCE_UPLOAD_BYTES // (1024*1024)} MB."

    try:
        hashes = calculate_all_hashes(abs_path)
    except Exception:
        os.remove(abs_path)
        return None, "Hashing failed."

    mime = guess_mime_type(original)
    ts = now_utc_str()
    storage_path = os.path.join(dir_rel, stored).replace("\\", "/")

    try:
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO evidence
                (evidence_id, case_id, original_filename, stored_filename, evidence_type, file_extension,
                 mime_type, file_size, storage_path, original_md5, original_sha1, original_sha256,
                 current_md5_hash, current_sha1_hash, current_sha256_hash, integrity_status,
                 uploaded_by, uploaded_by_id, upload_time, last_verified_at, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    evidence_id, case_id, original, stored, evidence_type, ext, mime, size, storage_path,
                    hashes["md5"], hashes["sha1"], hashes["sha256"],
                    hashes["md5"], hashes["sha1"], hashes["sha256"],
                    INTEGRITY_NOT_VERIFIED,
                    investigator["investigator_name"], investigator["investigator_id"], ts, ts,
                    notes or None, ts, ts,
                ),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        if os.path.isfile(abs_path):
            os.remove(abs_path)
        return None, "Evidence ID conflict. Please try again."

    try:
        meta_items = extract_all_metadata(abs_path, original)
        save_evidence_metadata(evidence_id, meta_items)
    except Exception:
        pass

    record_custody(
        evidence_id, case_id, "Evidence Uploaded",
        investigator["investigator_name"], investigator["investigator_id"],
        f"Evidence {evidence_id} uploaded for case {case_id}.",
        None, hashes["sha256"],
    )
    record_custody(
        evidence_id, case_id, "SHA-256 Generated",
        investigator["investigator_name"], investigator["investigator_id"],
        f"Original SHA-256: {hashes['sha256']}",
        None, hashes["sha256"],
    )

    return evidence_id, None


def delete_evidence_record(evidence: dict, investigator: dict):
    try:
        path = safe_evidence_path(evidence["case_id"], evidence["evidence_id"], evidence["stored_filename"])
        if os.path.isfile(path):
            os.remove(path)
        ev_dir = os.path.dirname(path)
        if os.path.isdir(ev_dir) and not os.listdir(ev_dir):
            os.rmdir(ev_dir)
    except Exception:
        pass

    with get_conn() as conn:
        conn.execute("DELETE FROM evidence_metadata WHERE evidence_id = ?;", (evidence["evidence_id"],))
        conn.execute("DELETE FROM evidence_analysis WHERE evidence_id = ?;", (evidence["evidence_id"],))
        conn.execute("DELETE FROM evidence WHERE evidence_id = ?;", (evidence["evidence_id"],))
        conn.commit()

    record_custody(
        evidence["evidence_id"], evidence["case_id"], "Evidence Deleted",
        investigator["investigator_name"], investigator["investigator_id"],
        f"Evidence {evidence['evidence_id']} deleted.",
        evidence.get("original_sha256"), None,
    )


def shorten_hash(h: str | None, n: int = 8) -> str:
    if not h:
        return "—"
    if len(h) <= n * 2 + 3:
        return h
    return f"{h[:n]}...{h[-n:]}"
