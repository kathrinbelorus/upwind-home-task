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
- [x] **Step 2b: Backend on Cloud Run** (`me-west1`). API key comes from Secret Manager, `/docs` is disabled in production, max 2 instances.
- [x] **Step 3: Connect.** The add-on extracts the email, calls `/analyze` with `X-API-Key`, validates the response and renders the verdict, score and findings. Working live in Gmail.
- [x] **README.md** (short version, with a screenshot slot at `docs/screenshot.png`)
- [x] **Gemini AI opinion** (`backend/app/ai.py`, model `gemini-3.5-flash-lite`). Adds +0/10/20 points, never negative. Fail-open, with one retry on 429/5xx. Live on Cloud Run, and 27 tests pass.

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

## Deploying the backend (Cloud Run)
One-time setup: a GCP project with billing, the Cloud Run, Cloud Build, Artifact Registry and Secret Manager APIs enabled, a secret `mail-scorer-api-key`, and the Secret Accessor role granted to the Compute default service account.
```bash
cd backend
gcloud run deploy mail-scorer --source . --region me-west1 --allow-unauthenticated --set-secrets API_KEY=mail-scorer-api-key:latest,GEMINI_API_KEY=gemini-api-key:latest --set-env-vars ENABLE_DOCS=false --max-instances 2 --memory 512Mi
```
`--allow-unauthenticated` is intentional: the add-on authenticates with the `X-API-Key` header.

## Add-on layout
```
addon/
  appsscript.json  scopes, triggers, urlFetchWhitelist (backend URL only)
  Main.js          entry points: extract -> analyze -> render
  Email.js         builds the /analyze payload; picks Gmail's own Authentication-Results header
  Api.js           calls the backend, validates and trims the response
  Cards.js         result / error / homepage cards
  Config.js        backend URL; reads API_KEY from Script Properties
  Utils.js         escapeHtml, truncate
```

## Deploying the add-on
No CLI tooling. Copy the files from `addon/` into a script.google.com project, enable "Show appsscript.json" in Project Settings, and add the Script Property `API_KEY`. Then **Deploy > Test deployments > Install**.

## Next step
Test against phishing-like emails, then write the README.

Note: when a scope is added to the manifest, Gmail may not re-prompt for consent. Revoke the add-on at myaccount.google.com/connections and reopen an email.
