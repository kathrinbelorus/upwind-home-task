# Handoff: Project Status

Gmail add-on that scores how malicious an opened email is and explains why.

## Architecture
| Part | Tech | Role |
|---|---|---|
| Add-on (`addon/`) | Google Apps Script + CardService | Reads the opened email, calls the backend, shows the result |
| Backend (`backend/`) | Python + FastAPI on Google Cloud Run | Analyzes the email and returns `{score, verdict, reasons[]}` |

The backend must be on public HTTPS, because Apps Script runs on Google's servers.

## Status
- [x] **Step 1: Add-on skeleton.** Opening an email shows a card with the sender and subject. Email text is HTML-escaped (CardService renders basic HTML).
- [ ] **Step 2: Backend.** `POST /analyze` with basic rules: SPF/DKIM/DMARC, display-name spoofing, link-text vs. real-URL mismatch, urgency language, risky attachments.
- [ ] **Step 3: Connect.** The add-on sends email data to the backend (shared-secret header) and renders the score, verdict and reasons.
- [ ] **README.md**

## Deploying the add-on
No CLI tooling. Copy the files from `addon/` into a script.google.com project, enable "Show appsscript.json" in Project Settings, then **Deploy > Test deployments > Install**.

## Next step
Step 2: build the backend locally, then deploy it to Cloud Run.
