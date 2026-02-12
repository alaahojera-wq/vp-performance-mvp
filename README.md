# VP Performance System (MVP)

A lightweight BambooHR-style web app that implements your VP Performance Management Framework (3 pillars, 60/20/20 weighting),
collects evidence, and auto-computes scores where possible.

## Quick start (local)
1) Install Python 3.10+
2) In this folder:
   - `pip install -r requirements.txt`
3) Run:
   - `uvicorn app.main:app --reload --port 8000`
4) Open:
   - http://127.0.0.1:8000

## Demo accounts
- Admin: admin@local / admin123
- Principal: principal@local / principal123
- VP: vp@local / vp123

## Notes
- Auto-scoring currently only works reliably for percentage-style metrics.
- Principal/Admin can override scores (1-4) with a reason.
- Evidence can be uploaded (file), added as a link, or saved as a note.

## Production notes
- Set environment variable `VP_APP_SECRET` before deploying.
- Replace demo users and enforce stronger password policies.
