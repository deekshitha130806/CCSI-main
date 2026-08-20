"""File integrity verification — compares current hashes to original baseline."""

import os

from forensic.hash_analyzer import calculate_all_hashes


INTEGRITY_AUTHENTIC = "Authentic"
INTEGRITY_MODIFIED = "Modified"
INTEGRITY_MISSING = "Missing"
INTEGRITY_NOT_VERIFIED = "Not Verified"


def verify_integrity(file_path: str, original_md5: str, original_sha1: str, original_sha256: str) -> dict:
    if not file_path or not os.path.isfile(file_path):
        return {
            "integrity_status": INTEGRITY_MISSING,
            "current_md5": None,
            "current_sha1": None,
            "current_sha256": None,
            "md5_match": False,
            "sha1_match": False,
            "sha256_match": False,
        }

    current = calculate_all_hashes(file_path)
    md5_match = current["md5"] == (original_md5 or "")
    sha1_match = current["sha1"] == (original_sha1 or "")
    sha256_match = current["sha256"] == (original_sha256 or "")

    if md5_match and sha1_match and sha256_match:
        status = INTEGRITY_AUTHENTIC
    else:
        status = INTEGRITY_MODIFIED

    return {
        "integrity_status": status,
        "current_md5": current["md5"],
        "current_sha1": current["sha1"],
        "current_sha256": current["sha256"],
        "md5_match": md5_match,
        "sha1_match": sha1_match,
        "sha256_match": sha256_match,
    }
