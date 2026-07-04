"""Web-UI service layer: background managers and query helpers behind the API.

No templates live here — the UI itself is the React SPA under ``frontend/``.
This package holds the server-side machinery that backs it: background run
managers (hunts, hunt console, chat, auto-triage, backtests), alert/detection
query helpers, connectivity probes, timeline labels, and shared dependencies.
"""
