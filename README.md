## Cybercrime Scene Investigator (CCSI)

**Technology:** Python (Flask), HTML, CSS, Vanilla JavaScript, SQLite

### Setup (Windows)

1. Open **CMD**
2. Go to the project folder:

   `cd /d E:\CCSI`

3. Create a virtual environment:

   `python -m venv .venv`

4. Activate the virtual environment:

   `.venv\Scripts\activate`

5. Install requirements:

   `pip install -r requirements.txt`

6. Run the app:

   `python app.py`

7. Open in browser:

   `http://127.0.0.1:5000`

### Demo Login (Step 1)

- Username: `admin`
- Password: `admin123`
- Investigator ID: `CCSI-001`

### Modules

- **Cases** — Create, view, edit, delete, search cases
- **Suspects** — Add, view, edit, delete suspects linked to cases
- **Evidence** — Upload digital evidence, SHA-256 hashing, integrity verification
- **Analysis** — Rule-based risk assessment and metadata review
- **Chain of Custody** — Append-only forensic action log
- **Reports** — Generate investigation PDF reports per case

