# Handoff: Project Status

Gmail add-on that scores how malicious an opened email is and explains why.

## Architecture
| Part | Tech | Role |
|---|---|---|
| Add-on (`addon/`) | Google Apps Script + CardService | Reads the opened email, calls the backend, shows the result |
| Backend (`backend/`) | Python + FastAPI (Cloud Run planned) | Analyzes the email and returns `{score, verdict, findings[]}` |

The backend must be on public HTTPS, because Apps Script runs on Google's servers.

## Status
- [x] **Step 1: Add-on skeleton.** Opening an email shows a card with the sender and subject. Email text is HTML-escaped (CardService renders basic HTML).
- [x] **Step 2a: Backend, local.** `POST /analyze` with five checks (authentication, sender, links, content, attachments). 16 tests pass.
- [ ] **Step 2b: Deploy the backend to Cloud Run.** Dockerfile ready (non-root user); `.gcloudignore` keeps `.env` out of the upload.
- [ ] **Step 3: Connect.** The add-on sends email data to the backend (`X-API-Key` header) and renders the score, verdict and findings.
- [ ] **README.md**

## Backend layout
```
backend/app/
  main.py        HTTP layer: routes + API-key auth
  analyzer.py    runs all checks, computes score (capped at 100) and verdict
  parsing.py     normalizes the request once (sender, links from HTML, text)
  models.py      request/response schemas with size limits
  checks/        one module per signal; register new ones in checks/__init__.py
```
Verdict: 0-29 Safe, 30-69 Suspicious, 70+ Malicious.

## Running the backend locally
```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
cp .env.example .env   # then set API_KEY to a long random value
.venv/Scripts/python -m pytest
.venv/Scripts/python -m uvicorn app.main:app --reload
```
Interactive docs: http://127.0.0.1:8000/docs

## Deploying the add-on
No CLI tooling. Copy the files from `addon/` into a script.google.com project, enable "Show appsscript.json" in Project Settings, then **Deploy > Test deployments > Install**.

## Next step
Step 2b: deploy the backend to Cloud Run.
