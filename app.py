import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash

import config
import evidence_service as evsvc
from forensic.file_classifier import EVIDENCE_TYPES, suggest_evidence_type
from forensic.integrity_checker import INTEGRITY_AUTHENTIC, INTEGRITY_MODIFIED, INTEGRITY_MISSING, INTEGRITY_NOT_VERIFIED
from forensic.report_generator import generate_investigation_report


CRIME_TYPES = [
    "Cyber Fraud",
    "Phishing",
    "Ransomware",
    "Data Theft",
    "Identity Theft",
    "Malware Attack",
    "Insider Attack",
    "Social Media Crime",
]

CASE_PRIORITIES = ["Low", "Medium", "High", "Critical"]
CASE_STATUSES = ["Open", "Under Investigation", "Pending", "Closed"]


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    app.config["SESSION_PERMANENT"] = getattr(config, "SESSION_PERMANENT", False)
    app.config["MAX_CONTENT_LENGTH"] = getattr(config, "MAX_CONTENT_LENGTH", 100 * 1024 * 1024)

    os.makedirs(os.path.join(os.path.dirname(__file__), "database"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "uploads"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "reports"), exist_ok=True)
    os.makedirs(getattr(config, "SUSPECT_PHOTO_DIR", os.path.join(os.path.dirname(__file__), "static", "uploads", "suspects")), exist_ok=True)
    os.makedirs(getattr(config, "EVIDENCE_UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "uploads", "evidence")), exist_ok=True)

    init_db()
    ensure_demo_investigator()

    def is_authenticated() -> bool:
        inv = session.get("investigator")
        if not isinstance(inv, dict):
            return False
        return bool(inv.get("id") and inv.get("investigator_id") and inv.get("username"))

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_authenticated():
                session.clear()
                return redirect(url_for("index"))
            return fn(*args, **kwargs)

        return wrapper

    @app.before_request
    def validate_session():
        if "investigator" in session and not is_authenticated():
            session.clear()

    @app.get("/")
    def index():
        if is_authenticated():
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        investigator_id = (request.form.get("investigator_id") or "").strip()

        if not username or not password or not investigator_id:
            flash("Please enter Username, Password, and Investigator ID.", "error")
            return redirect(url_for("index"))

        inv = get_investigator_by_credentials(username=username, investigator_id=investigator_id)
        if not inv:
            flash("Invalid credentials. Please verify your Username and Investigator ID.", "error")
            return redirect(url_for("index"))

        if not check_password_hash(inv["password"], password):
            flash("Invalid credentials. Please check your password.", "error")
            return redirect(url_for("index"))

        update_last_login(inv["id"])

        session.clear()
        session.permanent = False
        session["investigator"] = {
            "id": inv["id"],
            "username": inv["username"],
            "investigator_id": inv["investigator_id"],
            "investigator_name": inv["investigator_name"],
            "department": inv["department"],
            "rank": inv["rank"],
        }

        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        inv = session["investigator"]

        counts = get_case_counts()
        ev_counts = evsvc.get_evidence_counts()
        ev_dist = evsvc.get_evidence_type_distribution()
        case_status_counts = get_case_status_distribution()
        monthly_raw = get_monthly_case_counts()
        chart_data = {
            "caseStatus": {
                "open": case_status_counts.get("Open", 0),
                "closed": case_status_counts.get("Closed", 0),
                "pending": case_status_counts.get("Pending", 0),
                "under": case_status_counts.get("Under Investigation", 0),
            },
            "evidenceLabels": list(ev_dist.keys()),
            "evidenceValues": list(ev_dist.values()),
            "monthlyLabels": monthly_raw["labels"],
            "monthlyValues": monthly_raw["values"],
        }
        metrics = {
            "total_cases": counts["total"],
            "open_cases": counts["open"],
            "closed_cases": counts["closed"],
            "evidence_uploaded": ev_counts["total"],
            "pending_analysis": ev_counts["pending"],
        }
        activities = get_recent_activities(limit=6)

        return render_template(
            "dashboard.html",
            investigator=inv,
            metrics=metrics,
            now_iso=datetime.now(timezone.utc).isoformat(),
            activities=activities,
            case_status_counts=case_status_counts,
            evidence_type_dist=ev_dist,
            chart_data=chart_data,
        )

    # Sidebar placeholders (Step 1 only)
    @app.get("/module/<name>")
    @login_required
    def module_placeholder(name: str):
        flash("Module will be added in the next development step.", "info")
        return redirect(url_for("dashboard"))

    # =========================
    # STEP 2: CASE MANAGEMENT
    # =========================
    @app.get("/cases")
    @login_required
    def cases_index():
        q = (request.args.get("q") or "").strip()
        crime_type = (request.args.get("crime_type") or "").strip()
        priority = (request.args.get("priority") or "").strip()
        status = (request.args.get("status") or "").strip()

        cases = search_cases(q=q, crime_type=crime_type, priority=priority, status=status)
        summary = get_case_summary_cards()

        return render_template(
            "cases.html",
            investigator=session["investigator"],
            cases=cases,
            summary=summary,
            q=q,
            crime_type=crime_type,
            priority=priority,
            status=status,
            crime_types=CRIME_TYPES,
            priorities=CASE_PRIORITIES,
            statuses=CASE_STATUSES,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.get("/cases/new")
    @login_required
    def cases_new():
        inv = session["investigator"]
        new_case_id = generate_next_case_id()
        today = datetime.now().date().isoformat()

        return render_template(
            "create_case.html",
            investigator=inv,
            case_id=new_case_id,
            crime_types=CRIME_TYPES,
            priorities=CASE_PRIORITIES,
            statuses=CASE_STATUSES,
            default_date=today,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/cases/new")
    @login_required
    def cases_create():
        inv = session["investigator"]

        case_id = (request.form.get("case_id") or "").strip()
        case_title = (request.form.get("case_title") or "").strip()
        crime_type = (request.form.get("crime_type") or "").strip()
        case_date = (request.form.get("case_date") or "").strip()
        location = (request.form.get("location") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority = (request.form.get("priority") or "").strip()

        if not case_id or not is_valid_case_id(case_id):
            flash("Invalid Case ID.", "error")
            return redirect(url_for("cases_new"))
        if not case_title:
            flash("Case Title is required.", "error")
            return redirect(url_for("cases_new"))
        if crime_type not in CRIME_TYPES:
            flash("Crime Type is required.", "error")
            return redirect(url_for("cases_new"))
        if not case_date:
            flash("Date is required.", "error")
            return redirect(url_for("cases_new"))
        if not location:
            flash("Location is required.", "error")
            return redirect(url_for("cases_new"))
        if not description:
            flash("Description is required.", "error")
            return redirect(url_for("cases_new"))
        if priority not in CASE_PRIORITIES:
            flash("Priority is required.", "error")
            return redirect(url_for("cases_new"))

        created_at = now_utc_str()
        try:
            with get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO cases
                    (case_id, case_title, crime_type, investigation_officer, investigation_officer_id,
                     case_date, location, description, priority, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        case_id,
                        case_title,
                        crime_type,
                        inv["investigator_name"],
                        inv["investigator_id"],
                        case_date,
                        location,
                        description,
                        priority,
                        "Open",
                        created_at,
                        created_at,
                    ),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("Case ID already exists. Please try again.", "error")
            return redirect(url_for("cases_new"))

        log_activity(inv["id"], "case_created", f"Case created: {case_id} • {case_title}", related_case_id=case_id)
        flash("Case created successfully.", "success")
        return redirect(url_for("case_details", case_id=case_id))

    @app.get("/cases/<case_id>")
    @login_required
    def case_details(case_id: str):
        case = get_case_by_case_id(case_id)
        if not case:
            flash("Record not found.", "error")
            return redirect(url_for("cases_index"))

        suspects = get_suspects_for_case(case_id)
        evidence_list = evsvc.get_evidence_for_case(case_id)
        custody_events = evsvc.get_custody_for_case(case_id, limit=10)
        report_path = get_case_report_path(case_id)
        return render_template(
            "case_details.html",
            investigator=session["investigator"],
            case=case,
            suspects=suspects,
            evidence_list=evidence_list,
            custody_events=custody_events,
            report_exists=bool(report_path and os.path.isfile(report_path)),
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.get("/cases/<case_id>/edit")
    @login_required
    def case_edit(case_id: str):
        case = get_case_by_case_id(case_id)
        if not case:
            flash("Record not found.", "error")
            return redirect(url_for("cases_index"))
        return render_template(
            "edit_case.html",
            investigator=session["investigator"],
            case=case,
            crime_types=CRIME_TYPES,
            priorities=CASE_PRIORITIES,
            statuses=CASE_STATUSES,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/cases/<case_id>/edit")
    @login_required
    def case_update(case_id: str):
        inv = session["investigator"]
        case = get_case_by_case_id(case_id)
        if not case:
            flash("Record not found.", "error")
            return redirect(url_for("cases_index"))

        case_title = (request.form.get("case_title") or "").strip()
        crime_type = (request.form.get("crime_type") or "").strip()
        case_date = (request.form.get("case_date") or "").strip()
        location = (request.form.get("location") or "").strip()
        description = (request.form.get("description") or "").strip()
        priority = (request.form.get("priority") or "").strip()
        status = (request.form.get("status") or "").strip()

        if not case_title:
            flash("Case Title is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if crime_type not in CRIME_TYPES:
            flash("Crime Type is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if not case_date:
            flash("Date is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if not location:
            flash("Location is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if not description:
            flash("Description is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if priority not in CASE_PRIORITIES:
            flash("Priority is required.", "error")
            return redirect(url_for("case_edit", case_id=case_id))
        if status not in CASE_STATUSES:
            flash("Status is invalid.", "error")
            return redirect(url_for("case_edit", case_id=case_id))

        updated_at = now_utc_str()
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE cases
                SET case_title = ?, crime_type = ?, case_date = ?, location = ?, description = ?,
                    priority = ?, status = ?, updated_at = ?
                WHERE case_id = ?;
                """,
                (case_title, crime_type, case_date, location, description, priority, status, updated_at, case_id),
            )
            conn.commit()

        log_activity(inv["id"], "case_updated", f"Case updated: {case_id}", related_case_id=case_id)
        flash("Case updated successfully.", "success")
        return redirect(url_for("case_details", case_id=case_id))

    @app.post("/cases/<case_id>/delete")
    @login_required
    def case_delete(case_id: str):
        inv = session["investigator"]
        case = get_case_by_case_id(case_id)
        if not case:
            flash("Record not found.", "error")
            return redirect(url_for("cases_index"))

        with get_conn() as conn:
            conn.execute("DELETE FROM cases WHERE case_id = ?;", (case_id,))
            conn.commit()

        log_activity(inv["id"], "case_deleted", f"Case deleted: {case_id}", related_case_id=case_id)
        flash("Case deleted successfully.", "success")
        return redirect(url_for("cases_index"))

    # =========================
    # STEP 2: SUSPECT MANAGEMENT
    # =========================
    @app.get("/suspects")
    @login_required
    def suspects_index():
        q = (request.args.get("q") or "").strip()
        suspects = search_suspects(q=q)
        summary = get_suspect_summary_cards()
        return render_template(
            "suspects.html",
            investigator=session["investigator"],
            suspects=suspects,
            summary=summary,
            q=q,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.get("/suspects/new")
    @login_required
    def suspects_new():
        inv = session["investigator"]
        suspect_id = generate_next_suspect_id()
        case_id_prefill = (request.args.get("case_id") or "").strip()
        cases = list_cases_for_dropdown()
        return render_template(
            "add_suspect.html",
            investigator=inv,
            suspect_id=suspect_id,
            cases=cases,
            case_id_prefill=case_id_prefill,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/suspects/new")
    @login_required
    def suspects_create():
        inv = session["investigator"]
        suspect_id = (request.form.get("suspect_id") or "").strip()
        case_id = (request.form.get("case_id") or "").strip()
        name = (request.form.get("name") or "").strip()
        age_raw = (request.form.get("age") or "").strip()
        address = (request.form.get("address") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()
        crime_history = (request.form.get("crime_history") or "").strip()

        if not suspect_id or not is_valid_suspect_id(suspect_id):
            flash("Invalid Suspect ID.", "error")
            return redirect(url_for("suspects_new"))
        if not case_id or not get_case_by_case_id(case_id):
            flash("Linked Case is required.", "error")
            return redirect(url_for("suspects_new"))
        if not name:
            flash("Name is required.", "error")
            return redirect(url_for("suspects_new", case_id=case_id))
        age = parse_age(age_raw)
        if age is None:
            flash("Age must be a number between 1 and 120.", "error")
            return redirect(url_for("suspects_new", case_id=case_id))
        if not address:
            flash("Address is required.", "error")
            return redirect(url_for("suspects_new", case_id=case_id))
        if phone and not is_reasonable_phone(phone):
            flash("Phone format looks invalid.", "warning")
            return redirect(url_for("suspects_new", case_id=case_id))
        if email and not is_reasonable_email(email):
            flash("Email format looks invalid.", "warning")
            return redirect(url_for("suspects_new", case_id=case_id))

        photo_rel = None
        file = request.files.get("photograph")
        if file and file.filename:
            try:
                photo_rel = save_suspect_photo(file)
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("suspects_new", case_id=case_id))

        created_at = now_utc_str()
        try:
            with get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO suspects
                    (suspect_id, case_id, name, age, address, phone, email, crime_history, photograph, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        suspect_id,
                        case_id,
                        name,
                        age,
                        address,
                        phone or None,
                        email or None,
                        crime_history or None,
                        photo_rel,
                        created_at,
                        created_at,
                    ),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("Suspect ID already exists. Please try again.", "error")
            return redirect(url_for("suspects_new", case_id=case_id))

        log_activity(inv["id"], "suspect_added", f"Suspect added: {suspect_id} • {name}", related_case_id=case_id)
        flash("Suspect added successfully.", "success")
        return redirect(url_for("suspect_details", suspect_id=suspect_id))

    @app.get("/suspects/<suspect_id>")
    @login_required
    def suspect_details(suspect_id: str):
        suspect = get_suspect_by_suspect_id(suspect_id)
        if not suspect:
            flash("Record not found.", "error")
            return redirect(url_for("suspects_index"))
        case = get_case_by_case_id(suspect["case_id"])
        return render_template(
            "suspect_details.html",
            investigator=session["investigator"],
            suspect=suspect,
            case=case,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.get("/suspects/<suspect_id>/edit")
    @login_required
    def suspect_edit(suspect_id: str):
        suspect = get_suspect_by_suspect_id(suspect_id)
        if not suspect:
            flash("Record not found.", "error")
            return redirect(url_for("suspects_index"))
        cases = list_cases_for_dropdown()
        return render_template(
            "edit_suspect.html",
            investigator=session["investigator"],
            suspect=suspect,
            cases=cases,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/suspects/<suspect_id>/edit")
    @login_required
    def suspect_update(suspect_id: str):
        inv = session["investigator"]
        suspect = get_suspect_by_suspect_id(suspect_id)
        if not suspect:
            flash("Record not found.", "error")
            return redirect(url_for("suspects_index"))

        case_id = (request.form.get("case_id") or "").strip()
        name = (request.form.get("name") or "").strip()
        age_raw = (request.form.get("age") or "").strip()
        address = (request.form.get("address") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        email = (request.form.get("email") or "").strip()
        crime_history = (request.form.get("crime_history") or "").strip()

        if not case_id or not get_case_by_case_id(case_id):
            flash("Linked Case is required.", "error")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))
        if not name:
            flash("Name is required.", "error")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))
        age = parse_age(age_raw)
        if age is None:
            flash("Age must be a number between 1 and 120.", "error")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))
        if not address:
            flash("Address is required.", "error")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))
        if phone and not is_reasonable_phone(phone):
            flash("Phone format looks invalid.", "warning")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))
        if email and not is_reasonable_email(email):
            flash("Email format looks invalid.", "warning")
            return redirect(url_for("suspect_edit", suspect_id=suspect_id))

        photo_rel = suspect["photograph"]
        file = request.files.get("photograph")
        if file and file.filename:
            try:
                photo_rel = save_suspect_photo(file)
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("suspect_edit", suspect_id=suspect_id))

        updated_at = now_utc_str()
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE suspects
                SET case_id = ?, name = ?, age = ?, address = ?, phone = ?, email = ?,
                    crime_history = ?, photograph = ?, updated_at = ?
                WHERE suspect_id = ?;
                """,
                (
                    case_id,
                    name,
                    age,
                    address,
                    phone or None,
                    email or None,
                    crime_history or None,
                    photo_rel,
                    updated_at,
                    suspect_id,
                ),
            )
            conn.commit()

        log_activity(inv["id"], "suspect_updated", f"Suspect updated: {suspect_id}", related_case_id=case_id)
        flash("Suspect updated successfully.", "success")
        return redirect(url_for("suspect_details", suspect_id=suspect_id))

    @app.post("/suspects/<suspect_id>/delete")
    @login_required
    def suspect_delete(suspect_id: str):
        inv = session["investigator"]
        suspect = get_suspect_by_suspect_id(suspect_id)
        if not suspect:
            flash("Record not found.", "error")
            return redirect(url_for("suspects_index"))

        with get_conn() as conn:
            conn.execute("DELETE FROM suspects WHERE suspect_id = ?;", (suspect_id,))
            conn.commit()

        log_activity(inv["id"], "suspect_deleted", f"Suspect deleted: {suspect_id}", related_case_id=suspect["case_id"])
        flash("Suspect deleted successfully.", "success")
        return redirect(url_for("suspects_index"))

    # =========================
    # EVIDENCE MANAGEMENT
    # =========================
    @app.get("/evidence")
    @login_required
    def evidence_index():
        q = (request.args.get("q") or "").strip()
        case_id = (request.args.get("case_id") or "").strip()
        evidence_type = (request.args.get("evidence_type") or "").strip()
        integrity_status = (request.args.get("integrity_status") or "").strip()
        items = evsvc.search_evidence(q=q, case_id=case_id, evidence_type=evidence_type, integrity_status=integrity_status)
        summary = evsvc.get_evidence_summary()
        cases = list_cases_for_dropdown()
        return render_template(
            "evidence.html",
            investigator=session["investigator"],
            evidence_list=items,
            summary=summary,
            cases=cases,
            q=q, case_id=case_id, evidence_type=evidence_type, integrity_status=integrity_status,
            evidence_types=EVIDENCE_TYPES,
            integrity_statuses=[INTEGRITY_NOT_VERIFIED, INTEGRITY_AUTHENTIC, INTEGRITY_MODIFIED, INTEGRITY_MISSING],
            shorten_hash=evsvc.shorten_hash,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.get("/evidence/upload")
    @login_required
    def evidence_upload_form():
        case_prefill = (request.args.get("case_id") or "").strip()
        return render_template(
            "upload_evidence.html",
            investigator=session["investigator"],
            evidence_id=evsvc.generate_next_evidence_id(),
            cases=list_cases_for_dropdown(),
            case_prefill=case_prefill,
            evidence_types=EVIDENCE_TYPES,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/evidence/upload")
    @login_required
    def evidence_upload():
        inv = session["investigator"]
        evidence_id = (request.form.get("evidence_id") or "").strip()
        case_id = (request.form.get("case_id") or "").strip()
        evidence_type = (request.form.get("evidence_type") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        file = request.files.get("evidence_file")

        if not evidence_id or not evsvc.is_valid_evidence_id(evidence_id):
            flash("Invalid Evidence ID.", "error")
            return redirect(url_for("evidence_upload_form"))
        if not case_id or not get_case_by_case_id(case_id):
            flash("Linked case is required.", "error")
            return redirect(url_for("evidence_upload_form"))
        if evidence_type not in EVIDENCE_TYPES:
            flash("Evidence type is required.", "error")
            return redirect(url_for("evidence_upload_form", case_id=case_id))

        eid, err = evsvc.upload_evidence_file(file, case_id, evidence_id, evidence_type, notes, inv)
        if err:
            flash(err, "error")
            return redirect(url_for("evidence_upload_form", case_id=case_id))

        log_activity(inv["id"], "evidence_uploaded", f"Evidence {eid} uploaded for case {case_id}.", related_case_id=case_id)
        flash("Evidence uploaded and analyzed successfully.", "success")
        return redirect(url_for("evidence_details", evidence_id=eid))

    @app.get("/evidence/<evidence_id>")
    @login_required
    def evidence_details(evidence_id: str):
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("evidence_index"))
        case = get_case_by_case_id(ev["case_id"])
        metadata = evsvc.get_metadata_for_evidence(evidence_id)
        analysis = evsvc.get_analysis_for_evidence(evidence_id)
        evsvc.record_custody(evidence_id, ev["case_id"], "Evidence Viewed", session["investigator"]["investigator_name"],
                             session["investigator"]["investigator_id"], f"Evidence {evidence_id} viewed.")
        return render_template(
            "evidence_details.html",
            investigator=session["investigator"],
            evidence=ev, case=case, metadata=metadata, analysis=analysis,
            shorten_hash=evsvc.shorten_hash,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/evidence/<evidence_id>/verify")
    @login_required
    def evidence_verify(evidence_id: str):
        inv = session["investigator"]
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("evidence_index"))
        result = evsvc.run_integrity_verification(ev)
        if result["integrity_status"] == INTEGRITY_AUTHENTIC:
            msg = f"Integrity verification completed for {evidence_id}. Result: Authentic."
            log_activity(inv["id"], "evidence_verified", msg, related_case_id=ev["case_id"])
            evsvc.record_custody(evidence_id, ev["case_id"], "Hash Match Confirmed", inv["investigator_name"],
                                 inv["investigator_id"], msg, ev.get("original_sha256"), result.get("current_sha256"))
            flash("Integrity verified: Authentic.", "success")
        elif result["integrity_status"] == INTEGRITY_MODIFIED:
            msg = f"Hash mismatch detected for {evidence_id}."
            log_activity(inv["id"], "hash_mismatch", msg, related_case_id=ev["case_id"])
            evsvc.record_custody(evidence_id, ev["case_id"], "Hash Mismatch Detected", inv["investigator_name"],
                                 inv["investigator_id"], msg, ev.get("original_sha256"), result.get("current_sha256"))
            flash("Integrity status: MODIFIED — hash mismatch detected.", "error")
        else:
            msg = f"Evidence file missing for {evidence_id}."
            log_activity(inv["id"], "evidence_missing", msg, related_case_id=ev["case_id"])
            evsvc.record_custody(evidence_id, ev["case_id"], "Integrity Verified", inv["investigator_name"],
                                 inv["investigator_id"], "Result: Missing", ev.get("original_sha256"), None)
            flash("Integrity status: MISSING — file not found.", "warning")
        return redirect(url_for("evidence_details", evidence_id=evidence_id))

    @app.post("/evidence/verify-all")
    @login_required
    def evidence_verify_all():
        inv = session["investigator"]
        items = evsvc.search_evidence()
        stats = {"total": 0, "authentic": 0, "modified": 0, "missing": 0}
        for ev in items:
            stats["total"] += 1
            result = evsvc.run_integrity_verification(ev)
            st = result["integrity_status"]
            if st == INTEGRITY_AUTHENTIC:
                stats["authentic"] += 1
            elif st == INTEGRITY_MODIFIED:
                stats["modified"] += 1
            else:
                stats["missing"] += 1
        flash(f"Verification completed. Total: {stats['total']}, Authentic: {stats['authentic']}, Modified: {stats['modified']}, Missing: {stats['missing']}.", "info")
        return redirect(url_for("evidence_index"))

    @app.get("/evidence/<evidence_id>/download")
    @login_required
    def evidence_download(evidence_id: str):
        inv = session["investigator"]
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("evidence_index"))
        try:
            path = evsvc.safe_evidence_path(ev["case_id"], ev["evidence_id"], ev["stored_filename"])
        except ValueError:
            flash("Invalid evidence path.", "error")
            return redirect(url_for("evidence_details", evidence_id=evidence_id))
        if not os.path.isfile(path):
            flash("Evidence file is missing.", "error")
            return redirect(url_for("evidence_details", evidence_id=evidence_id))
        evsvc.record_custody(evidence_id, ev["case_id"], "Evidence Downloaded", inv["investigator_name"],
                             inv["investigator_id"], f"Evidence {evidence_id} downloaded.")
        log_activity(inv["id"], "evidence_downloaded", f"Evidence {evidence_id} downloaded.", related_case_id=ev["case_id"])
        return send_file(path, as_attachment=True, download_name=ev["original_filename"])

    @app.post("/evidence/<evidence_id>/delete")
    @login_required
    def evidence_delete(evidence_id: str):
        inv = session["investigator"]
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("evidence_index"))
        evsvc.delete_evidence_record(ev, inv)
        log_activity(inv["id"], "evidence_deleted", f"Evidence {evidence_id} deleted.", related_case_id=ev["case_id"])
        flash("Evidence deleted successfully.", "success")
        return redirect(url_for("evidence_index"))

    # =========================
    # ANALYSIS
    # =========================
    @app.get("/analysis")
    @login_required
    def analysis_index():
        items = evsvc.search_evidence()
        enriched = []
        for ev in items:
            analysis = evsvc.get_analysis_for_evidence(ev["evidence_id"])
            meta = evsvc.get_metadata_for_evidence(ev["evidence_id"])
            enriched.append({**ev, "analysis": analysis, "has_metadata": len(meta) > 0})
        return render_template(
            "analysis.html",
            investigator=session["investigator"],
            evidence_list=enriched,
            shorten_hash=evsvc.shorten_hash,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/analysis/<evidence_id>/run")
    @login_required
    def analysis_run(evidence_id: str):
        inv = session["investigator"]
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("analysis_index"))
        risk = evsvc.run_risk_analysis(ev)
        evsvc.record_custody(evidence_id, ev["case_id"], "Evidence Analysis Completed", inv["investigator_name"],
                             inv["investigator_id"], f"Rule-Based Risk Score: {risk['risk_score']} ({risk['risk_level']})")
        log_activity(inv["id"], "analysis_completed", f"Analysis completed for {evidence_id}.", related_case_id=ev["case_id"])
        flash(f"Rule-Based Risk Assessment complete. Score: {risk['risk_score']} ({risk['risk_level']}).", "success")
        return redirect(url_for("analysis_index"))

    @app.get("/metadata/<evidence_id>")
    @login_required
    def metadata_details(evidence_id: str):
        ev = evsvc.get_evidence_by_id(evidence_id)
        if not ev:
            flash("Record not found.", "error")
            return redirect(url_for("analysis_index"))
        metadata = evsvc.get_metadata_for_evidence(evidence_id)
        if not metadata:
            try:
                path = evsvc.safe_evidence_path(ev["case_id"], ev["evidence_id"], ev["stored_filename"])
                if os.path.isfile(path):
                    from forensic.metadata_analyzer import extract_all_metadata
                    metadata = extract_all_metadata(path, ev["original_filename"])
                    evsvc.save_evidence_metadata(evidence_id, metadata)
            except Exception:
                pass
        evsvc.record_custody(evidence_id, ev["case_id"], "Metadata Analyzed", session["investigator"]["investigator_name"],
                             session["investigator"]["investigator_id"], f"Metadata viewed for {evidence_id}.")
        grouped = {}
        for m in metadata:
            grouped.setdefault(m["metadata_category"], []).append(m)
        return render_template(
            "metadata_details.html",
            investigator=session["investigator"],
            evidence=ev, grouped_metadata=grouped,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    # =========================
    # CHAIN OF CUSTODY
    # =========================
    @app.get("/custody")
    @login_required
    def custody_index():
        case_id = (request.args.get("case_id") or "").strip()
        evidence_id = (request.args.get("evidence_id") or "").strip()
        action = (request.args.get("action") or "").strip()
        q = (request.args.get("q") or "").strip()
        events = evsvc.get_custody_events(case_id=case_id, evidence_id=evidence_id, action=action, q=q)
        cases = list_cases_for_dropdown()
        return render_template(
            "custody.html",
            investigator=session["investigator"],
            events=events, cases=cases,
            case_id=case_id, evidence_id=evidence_id, action=action, q=q,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    # =========================
    # REPORTS
    # =========================
    @app.get("/reports")
    @login_required
    def reports_index():
        cases = list_cases_for_dropdown()
        reports = []
        for c in cases:
            path = get_case_report_path(c["case_id"])
            reports.append({**c, "report_exists": bool(path and os.path.isfile(path)), "report_filename": os.path.basename(path) if path else None})
        return render_template(
            "reports.html",
            investigator=session["investigator"],
            cases=reports,
            now_iso=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/reports/generate/<case_id>")
    @login_required
    def reports_generate(case_id: str):
        inv = session["investigator"]
        case_id = (case_id or "").strip()
        case = get_case_by_case_id(case_id)
        if not case:
            flash("Case not found.", "error")
            return redirect(url_for("reports_index"))
        suspects = get_suspects_for_case(case_id)
        evidence_list = evsvc.get_evidence_for_case(case_id)
        custody_events = evsvc.get_custody_events(case_id=case_id)
        for ev in evidence_list:
            ev["analysis"] = evsvc.get_analysis_for_evidence(ev["evidence_id"])
        filename = case_report_filename(case_id)
        output_path = os.path.join(config.REPORTS_DIR, filename)
        try:
            generate_investigation_report(output_path, case, suspects, evidence_list, custody_events, inv)
        except Exception:
            flash("Report generation failed.", "error")
            return redirect(url_for("reports_index"))
        save_case_report_record(case_id, filename, inv)
        evsvc.record_custody("", case_id, "Report Generated", inv["investigator_name"], inv["investigator_id"],
                             f"Investigation report generated for {case_id}.")
        log_activity(inv["id"], "report_generated", f"Report generated for {case_id}.", related_case_id=case_id)
        flash("Investigation report generated successfully.", "success")
        return redirect(url_for("reports_index"))

    @app.get("/reports/download/<case_id>")
    @login_required
    def reports_download(case_id: str):
        case_id = (case_id or "").strip()
        path = get_case_report_path(case_id)
        if not path or not os.path.isfile(path):
            flash("Report not found. Generate it first.", "error")
            return redirect(url_for("reports_index"))
        resp = send_file(path, as_attachment=True, download_name=case_report_filename(case_id))
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.get("/logout")
    def logout():
        session.clear()
        resp = make_response(redirect(url_for("index")))
        resp.set_cookie(
            app.config.get("SESSION_COOKIE_NAME", "session"),
            "",
            expires=0,
            httponly=app.config.get("SESSION_COOKIE_HTTPONLY", True),
            samesite=app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        )
        return resp

    return app


def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                investigator_id TEXT NOT NULL,
                investigator_name TEXT NOT NULL,
                department TEXT NOT NULL,
                rank TEXT NOT NULL,
                cases_solved INTEGER NOT NULL DEFAULT 0,
                last_login TEXT
            );
            """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_investigators_username ON investigators(username);"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_investigators_investigator_id ON investigators(investigator_id);"
        )

        # Step 2: cases
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL UNIQUE,
                case_title TEXT NOT NULL,
                crime_type TEXT NOT NULL,
                investigation_officer TEXT NOT NULL,
                investigation_officer_id TEXT NOT NULL,
                case_date TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_priority ON cases(priority);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_crime_type ON cases(crime_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_case_date ON cases(case_date);")

        # Step 2: suspects (linked to cases by unique case_id, cascade on case delete)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suspects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                suspect_id TEXT NOT NULL UNIQUE,
                case_id TEXT NOT NULL,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                address TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                crime_history TEXT,
                photograph TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_suspects_case_id ON suspects(case_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_suspects_name ON suspects(name);")

        # Step 2: activity logs (for dashboard recent activity)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigator_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT NOT NULL,
                related_case_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigator_id) REFERENCES investigators(id)
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_activity_created_at ON activity_logs(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_activity_related_case_id ON activity_logs(related_case_id);")

        # Evidence
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL UNIQUE,
                case_id TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                file_extension TEXT,
                mime_type TEXT,
                file_size INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                original_md5 TEXT,
                original_sha1 TEXT,
                original_sha256 TEXT NOT NULL,
                current_md5_hash TEXT,
                current_sha1_hash TEXT,
                current_sha256_hash TEXT,
                integrity_status TEXT NOT NULL DEFAULT 'Not Verified',
                uploaded_by TEXT NOT NULL,
                uploaded_by_id TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                last_verified_at TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_case_id ON evidence(case_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_type ON evidence(evidence_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_integrity ON evidence(integrity_status);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                metadata_key TEXT NOT NULL,
                metadata_value TEXT,
                metadata_category TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_metadata_eid ON evidence_metadata(evidence_id);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                custody_id TEXT NOT NULL UNIQUE,
                evidence_id TEXT,
                case_id TEXT NOT NULL,
                action TEXT NOT NULL,
                performed_by TEXT NOT NULL,
                investigator_id TEXT NOT NULL,
                action_date TEXT NOT NULL,
                details TEXT,
                previous_sha256 TEXT,
                current_sha256 TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS ix_custody_case ON chain_of_custody(case_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_custody_evidence ON chain_of_custody(evidence_id);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'Low',
                indicators TEXT,
                review_status TEXT,
                analyzed_at TEXT NOT NULL,
                analyzed_by TEXT,
                FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id) ON DELETE CASCADE
            );
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                report_filename TEXT NOT NULL,
                generated_by TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
            );
            """
        )

        conn.commit()


def now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_valid_case_id(case_id: str) -> bool:
    return bool(re.fullmatch(r"CCSI-CASE-\d{4}-\d{4}", case_id))


def generate_next_case_id() -> str:
    year = datetime.now().year
    prefix = f"CCSI-CASE-{year}-"
    with get_conn() as conn:
        row = conn.execute(
            "SELECT case_id FROM cases WHERE case_id LIKE ? ORDER BY case_id DESC LIMIT 1;",
            (prefix + "%",),
        ).fetchone()
        if not row:
            return f"{prefix}0001"
        last = row["case_id"]
        try:
            seq = int(last.split("-")[-1])
        except Exception:
            seq = 0
        return f"{prefix}{seq + 1:04d}"


def is_valid_suspect_id(suspect_id: str) -> bool:
    return bool(re.fullmatch(r"CCSI-SUS-\d{4}", suspect_id))


def generate_next_suspect_id() -> str:
    with get_conn() as conn:
        row = conn.execute("SELECT suspect_id FROM suspects ORDER BY suspect_id DESC LIMIT 1;").fetchone()
        if not row:
            return "CCSI-SUS-0001"
        last = row["suspect_id"]
        try:
            seq = int(last.split("-")[-1])
        except Exception:
            seq = 0
        return f"CCSI-SUS-{seq + 1:04d}"


def parse_age(raw: str):
    try:
        age = int(raw)
    except Exception:
        return None
    return age if 1 <= age <= 120 else None


def is_reasonable_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def is_reasonable_phone(phone: str) -> bool:
    cleaned = re.sub(r"[^\d+]", "", phone)
    return 7 <= len(cleaned.replace("+", "")) <= 16


def save_suspect_photo(file) -> str:
    filename = file.filename or ""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in getattr(config, "ALLOWED_SUSPECT_PHOTO_EXTENSIONS", {".jpg", ".jpeg", ".png", ".webp"}):
        raise ValueError("Invalid photograph type. Allowed: JPG, JPEG, PNG, WEBP.")

    rand = secrets.token_hex(12)
    stored = f"sus_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{rand}{ext}"
    abs_dir = getattr(config, "SUSPECT_PHOTO_DIR", os.path.join(os.path.dirname(__file__), "static", "uploads", "suspects"))
    os.makedirs(abs_dir, exist_ok=True)
    abs_path = os.path.join(abs_dir, stored)
    file.save(abs_path)
    # Store as web path
    return f"uploads/suspects/{stored}"


def log_activity(investigator_pk: int, activity_type: str, description: str, related_case_id: str | None = None):
    created_at = now_utc_str()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO activity_logs (investigator_id, activity_type, description, related_case_id, created_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            (investigator_pk, activity_type, description, related_case_id, created_at),
        )
        conn.commit()


def get_recent_activities(limit: int = 6):
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT a.activity_type, a.description, a.related_case_id, a.created_at, i.investigator_name
            FROM activity_logs a
            JOIN investigators i ON i.id = a.investigator_id
            ORDER BY a.id DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_case_counts():
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(1) AS c FROM cases;").fetchone()["c"]
        open_c = conn.execute("SELECT COUNT(1) AS c FROM cases WHERE status = 'Open';").fetchone()["c"]
        closed_c = conn.execute("SELECT COUNT(1) AS c FROM cases WHERE status = 'Closed';").fetchone()["c"]
        return {"total": int(total), "open": int(open_c), "closed": int(closed_c)}


def get_case_summary_cards():
    with get_conn() as conn:
        total = int(conn.execute("SELECT COUNT(1) AS c FROM cases;").fetchone()["c"])
        open_c = int(conn.execute("SELECT COUNT(1) AS c FROM cases WHERE status = 'Open';").fetchone()["c"])
        under = int(
            conn.execute("SELECT COUNT(1) AS c FROM cases WHERE status = 'Under Investigation';").fetchone()["c"]
        )
        closed = int(conn.execute("SELECT COUNT(1) AS c FROM cases WHERE status = 'Closed';").fetchone()["c"])
        return {"total": total, "open": open_c, "under_investigation": under, "closed": closed}


def search_cases(q: str, crime_type: str, priority: str, status: str):
    sql = """
        SELECT *
        FROM cases
        WHERE 1=1
    """
    params = []

    if q:
        sql += """
            AND (
                case_id LIKE ?
                OR case_title LIKE ?
                OR investigation_officer LIKE ?
                OR location LIKE ?
            )
        """
        like = f"%{q}%"
        params.extend([like, like, like, like])

    if crime_type:
        sql += " AND crime_type = ?"
        params.append(crime_type)
    if priority:
        sql += " AND priority = ?"
        params.append(priority)
    if status:
        sql += " AND status = ?"
        params.append(status)

    sql += " ORDER BY id DESC"

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_case_by_case_id(case_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id = ? LIMIT 1;", (case_id,)).fetchone()
        return dict(row) if row else None


def list_cases_for_dropdown():
    with get_conn() as conn:
        rows = conn.execute("SELECT case_id, case_title FROM cases ORDER BY id DESC;").fetchall()
        return [dict(r) for r in rows]


def get_suspects_for_case(case_id: str):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM suspects WHERE case_id = ? ORDER BY id DESC;",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def search_suspects(q: str):
    sql = """
        SELECT *
        FROM suspects
        WHERE 1=1
    """
    params = []
    if q:
        like = f"%{q}%"
        sql += """
            AND (
                suspect_id LIKE ?
                OR name LIKE ?
                OR case_id LIKE ?
                OR phone LIKE ?
                OR email LIKE ?
            )
        """
        params.extend([like, like, like, like, like])
    sql += " ORDER BY id DESC"
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def get_suspect_by_suspect_id(suspect_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM suspects WHERE suspect_id = ? LIMIT 1;", (suspect_id,)).fetchone()
        return dict(row) if row else None


def get_suspect_summary_cards():
    with get_conn() as conn:
        total = int(conn.execute("SELECT COUNT(1) AS c FROM suspects;").fetchone()["c"])
        active_cases = int(
            conn.execute("SELECT COUNT(DISTINCT case_id) AS c FROM suspects;").fetchone()["c"]
        )
        return {"total": total, "active_cases_with_suspects": active_cases}


def get_case_status_distribution():
    with get_conn() as conn:
        rows = conn.execute("SELECT status, COUNT(1) AS c FROM cases GROUP BY status;").fetchall()
        dist = {"Open": 0, "Closed": 0, "Pending": 0, "Under Investigation": 0}
        for r in rows:
            if r["status"] in dist:
                dist[r["status"]] = int(r["c"])
        return dist


def get_monthly_case_counts():
    """Return last 6 months labels and counts from cases.created_at."""
    from collections import OrderedDict
    months = OrderedDict()
    now = datetime.now(timezone.utc)
    for i in range(5, -1, -1):
        m = now.month - i
        y = now.year
        while m <= 0:
            m += 12
            y -= 1
        key = f"{y}-{m:02d}"
        label = datetime(y, m, 1).strftime("%b")
        months[label] = 0
    with get_conn() as conn:
        rows = conn.execute("SELECT created_at FROM cases;").fetchall()
        for r in rows:
            ts = r["created_at"] or ""
            try:
                dt = datetime.strptime(ts[:10], "%Y-%m-%d")
                label = dt.strftime("%b")
                if label in months:
                    months[label] += 1
            except Exception:
                pass
    return {"labels": list(months.keys()), "values": list(months.values())}


def case_report_filename(case_id: str) -> str:
    return f"{case_id}_Investigation_Report.pdf"


def get_case_report_path(case_id: str):
    """Return the on-disk PDF path for this case_id only (never another case's file)."""
    if not case_id:
        return None
    filename = case_report_filename(case_id)
    path = os.path.join(config.REPORTS_DIR, filename)
    if os.path.isfile(path):
        return path
    with get_conn() as conn:
        row = conn.execute(
            "SELECT report_filename FROM case_reports WHERE case_id = ? ORDER BY id DESC LIMIT 1;",
            (case_id,),
        ).fetchone()
        if not row:
            return None
        stored = (row["report_filename"] or "").strip()
        if stored != filename:
            return None
        stored_path = os.path.join(config.REPORTS_DIR, stored)
        return stored_path if os.path.isfile(stored_path) else None


def save_case_report_record(case_id: str, filename: str, investigator: dict):
    with get_conn() as conn:
        conn.execute("DELETE FROM case_reports WHERE case_id = ?;", (case_id,))
        conn.execute(
            "INSERT INTO case_reports (case_id, report_filename, generated_by, generated_at) VALUES (?, ?, ?, ?);",
            (case_id, filename, investigator["investigator_name"], now_utc_str()),
        )
        conn.commit()


def ensure_demo_investigator():
    with get_conn() as conn:
        row = conn.execute("SELECT COUNT(1) AS c FROM investigators;").fetchone()
        if row and int(row["c"]) > 0:
            return

        password_hash = generate_password_hash("admin123")
        conn.execute(
            """
            INSERT INTO investigators
            (username, password, investigator_id, investigator_name, department, rank, cases_solved, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "admin",
                password_hash,
                "CCSI-001",
                "Admin Investigator",
                "Cybercrime Division",
                "Chief Investigator",
                16,
                None,
            ),
        )
        conn.commit()


def get_investigator_by_credentials(username: str, investigator_id: str):
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM investigators
            WHERE username = ? AND investigator_id = ?
            LIMIT 1;
            """,
            (username, investigator_id),
        ).fetchone()
        return dict(row) if row else None


def update_last_login(investigator_pk: int):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_conn() as conn:
        conn.execute(
            "UPDATE investigators SET last_login = ? WHERE id = ?;",
            (ts, investigator_pk),
        )
        conn.commit()


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)

