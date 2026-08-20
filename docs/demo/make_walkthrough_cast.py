#!/usr/bin/env python3
"""Generate the soc-ai install walkthrough asciicast (asciinema v2).

Reproducible + public-safe: no live environment, no real hosts/creds. Renders the
documented flow — clone -> ./setup.sh (Wave-1 local/cloud route fork, day-1
automation prompts, doctor preflight, starter-pack install) -> healthz -> sign in
-> triage first alert.

    python3 docs/demo/make_walkthrough_cast.py            # writes the .cast
    agg --font-size 16 docs/demo/install-walkthrough.cast docs/img/install-walkthrough.gif

Every setup.sh prompt string below is transcribed VERBATIM from the script (see
the line references in the comments) — if a prompt's wording, default, or
Y/n-vs-y/N shape changes in setup.sh, this file drifts and must be updated
alongside it. Same for the doctor's check names (soc_ai/doctor.py) and the
`soc-ai triage` event rendering (soc_ai/cli.py's _render_event) — keep this in
sync with all three if they change.
"""
from __future__ import annotations

import json
from pathlib import Path

WIDTH, HEIGHT = 112, 32
CAST = Path(__file__).parent / "install-walkthrough.cast"

# ── ANSI ─────────────────────────────────────────────────────────────────────
R = "\x1b[0m"
DIM = "\x1b[38;5;245m"
GRN = "\x1b[38;5;78m"
CYN = "\x1b[38;5;81m"
BLU = "\x1b[38;5;75m"
YEL = "\x1b[38;5;221m"
RED = "\x1b[38;5;210m"
MAG = "\x1b[38;5;176m"
BOLD = "\x1b[1m"
PROMPT = f"{GRN}analyst@workstation{R}:{BLU}~/soc-ai{R}$ "
HR = f"{DIM}{'─' * 60}{R}"  # setup.sh's hr() — 60 box-drawing dashes, dimmed

events: list[list] = []
t = 0.0


def emit(data: str) -> None:
    events.append([round(t, 3), "o", data])


def sleep(dt: float) -> None:
    global t
    t += dt


def type_cmd(cmd: str, first: bool = False) -> None:
    """Render the prompt, then 'type' the command char-by-char, then Enter."""
    emit(PROMPT if not first else f"{GRN}analyst@workstation{R}:{BLU}~{R}$ ")
    sleep(0.35)
    for ch in cmd:
        emit(ch)
        sleep(0.032)
    sleep(0.45)
    emit("\r\n")


def out(line: str = "", dt: float = 0.10) -> None:
    emit(line + "\r\n")
    sleep(dt)


def beat(dt: float = 1.1) -> None:
    sleep(dt)


def comment(text: str) -> None:
    emit(f"{DIM}# {text}{R}\r\n")
    sleep(0.5)


def field(prompt: str, value: str, cps: float = 0.03, pre: float = 0.4) -> None:
    """An ask()-style prompt (already ending in ': ') — 'type' the value + Enter."""
    emit(prompt)
    sleep(pre)
    for ch in value:
        emit(ch)
        sleep(cps)
    out("", 0.25)


def secret(prompt: str, dots: int = 10, pre: float = 0.4) -> None:
    """An asksecret()-style prompt — read -rsp echoes nothing; dim bullets stand
    in for the keystrokes so the recording stays legible."""
    emit(prompt)
    sleep(pre)
    for _ in range(dots):
        emit(f"{DIM}•{R}")
        sleep(0.045)
    out("", 0.25)


def accept_default(prompt: str, pre: float = 0.6) -> None:
    """A prompt where the operator just presses Enter to take the bracketed default."""
    out(f"{prompt}{DIM}↵{R}", pre)


# ── 1. clone ─────────────────────────────────────────────────────────────────
comment("1 — Grab soc-ai from GitHub")
type_cmd("git clone https://github.com/nuk3s/soc-ai.git && cd soc-ai", first=True)
out("Cloning into 'soc-ai'...", 0.25)
out("remote: Enumerating objects: 1283, done.", 0.18)
out("remote: Counting objects: 100% (1283/1283), done.", 0.12)
out("Receiving objects: 100% (1283/1283), 2.41 MiB | 9.8 MiB/s, done.", 0.18)
out("Resolving deltas: 100% (612/612), done.", 0.15)
beat()

# ── 2. setup ─────────────────────────────────────────────────────────────────
# Every prompt string from here to the "done" banner is copied verbatim out of
# setup.sh (checked against the copy in this repo — grep the quoted text there
# before changing anything here). ask()/yesno() always prefix a caller's own
# message with two more spaces, so a message already written with a leading
# "  " renders four spaces deep; the raw `read -rp` calls (model pick) and the
# doctor's own table are exactly as wide as their own source line, no more.
comment("2 — Guided setup (builds + starts the Docker stack)")
type_cmd("./setup.sh")
out(f"{BOLD}soc-ai setup{R} — guided Docker install", 0.2)
out(HR, 0.2)
out(f"{CYN}›{R} Interactive mode — press Enter to accept [defaults].", 0.3)
out(HR, 0.2)

# --- 1. prerequisites --------------------------------------------------------
out(f"{CYN}›{R} Checking prerequisites…", 0.4)
out(f"{GRN}✓{R} Docker ready — Docker version 27.2.0, build 3ab5b0d", 0.5)
out(HR, 0.2)

# --- 2. configuration (.env) -------------------------------------------------
out(f"{CYN}›{R} Security Onion connection:", 0.3)
field("    Security Onion URL [https://your-so-grid]: ", "https://soc.example.com")
field(
    "    Verify the grid's TLS cert? (No for a self-signed SO) (y/N): ",
    "n",
    cps=0.06,
    pre=0.5,
)
field("    SO analyst username: ", "analyst@example.com")
secret("    SO analyst password: ")
# Detected from SO_HOST just entered — operator just accepts it.
accept_default("    Elasticsearch URL [https://soc.example.com:9200]: ", pre=0.3)
out(f"{CYN}›{R} Checking the grid…", 0.5)
out(f"{GRN}✓{R} Security Onion reachable (HTTP 200).", 0.4)
out(f"{GRN}✓{R} Elasticsearch credentials OK.", 0.5)
beat(0.4)

out("", 0.15)
out(f"{CYN}›{R} AI model — how will soc-ai reach one?", 0.4)
out(
    "      1) Local / self-hosted endpoint you run (LiteLLM gateway, vLLM, Ollama) "
    "— nothing leaves your network",
    0.2,
)
out(
    "      2) Cloud API key (OpenRouter or another OpenAI-compatible provider) "
    "— no local infra, redacted egress",
    0.3,
)
field("    Route [1]: ", "1", cps=0.06, pre=0.5)

out(
    f"{CYN}›{R} LLM gateway (local / self-hosted; no backend yet? see "
    "docs/LESSER_MODELS.md → 'Standing one up'):",
    0.4,
)
field("    Gateway URL [http://localhost:4000]: ", "https://llm.example.com:8000")
secret("    Gateway API key (blank if none): ")
field(
    "    Verify the gateway's TLS cert? (No for a self-signed gateway) (Y/n): ",
    "n",
    cps=0.06,
    pre=0.5,
)
beat(0.4)

out(f"{GRN}✓{R} Gateway serves 6 models.", 0.4)
out("    Pick the analyst model (used for every hunt):", 0.3)
out(f"       1) llama-3.3-70b-instruct   {DIM}← suggested{R}", 0.15)
out("       2) qwen2.5-72b-instruct", 0.15)
out("       3) mixtral-8x22b-instruct", 0.2)
accept_default("  Number or model name [llama-3.3-70b-instruct]: ")
out(f"{GRN}✓{R} Analyst model: {BOLD}llama-3.3-70b-instruct{R}", 0.5)
beat(0.4)

out("", 0.15)
out(f"{CYN}›{R} Day-1 automation:", 0.3)
field(
    "    Auto-triage the alert backlog on a schedule? (every 5 min, "
    "≤25 targets/sweep, high-severity+) (Y/n): ",
    "y",
    cps=0.06,
    pre=0.5,
)
field(
    "    Install the 10-runbook starter pack after start? (grounds verdicts; "
    "idempotent) (Y/n): ",
    "y",
    cps=0.06,
    pre=0.5,
)
out(f"{GRN}✓{R} Wrote .env", 0.5)
out(HR, 0.2)
beat(0.4)

# --- 4. build + start ---------------------------------------------------------
out(
    f"{CYN}›{R} Building and starting the stack "
    f"{DIM}(first build pulls deps — ~3 min)…{R}",
    0.6,
)
out(f"{DIM}[+] Building 184.6s (13/13) FINISHED{R}", 0.5)
out(f"[+] Running 1/1  {GRN}✓{R} Container soc-ai  Started", 0.5)
out(f"{CYN}›{R} Waiting for the service to report healthy…", 0.7)
out(
    f'{GRN}✓{R} Healthy — {{"status":"ok","version":"1.2.8",'
    '"so_auth":"kratos","misp_configured":false}',
    0.5,
)
out(HR, 0.2)
beat(0.4)

# --- doctor preflight (soc_ai/doctor.py check names, soc_ai/cli.py's table) --
out(
    f"{CYN}›{R} Preflight — the doctor checks every dependency, the "
    "model's fitness, and the audit grant…",
    0.6,
)
_doctor_rows = [
    ("config", "settings loaded from env/.env"),
    ("SO reachability", "soc.example.com reachable"),
    ("ES reachability", "soc.example.com:9200 reachable"),
    ("audit write grant", "soc-ai-audit-* is writable by the ES identity"),
    ("gateway", "https://llm.example.com:8000 serves 6 models"),
    ("analyst model", "'llama-3.3-70b-instruct' is served by the gateway"),
]
_name_w = max(len(name) for name, _ in _doctor_rows)
for name, detail in _doctor_rows:
    out(f"{GRN}PASS{R}  {name:<{_name_w}}  {detail}", 0.15)
out(f"\r\n{GRN}{len(_doctor_rows)} passed, 0 warning(s), 0 failure(s){R}", 0.3)
out(f"{GRN}✓{R} Preflight clean.", 0.5)
beat(0.4)

# --- starter pack -------------------------------------------------------------
out(f"{CYN}›{R} Installing the runbook starter pack (idempotent)…", 0.5)
out(f'{GRN}✓{R} Runbook starter pack: {{"created":10,"skipped":0}}', 0.5)
out(HR, 0.2)
beat(0.5)

# --- 6. done -------------------------------------------------------------------
out("", 0.15)
out(f"{GRN}{BOLD}✓ soc-ai is running.{R}", 0.3)
out(
    f"    Open:     {CYN}https://192.0.2.10:8443/app{R}   (accept the self-signed "
    "cert on first visit)",
    0.25,
)
out("    Sign in:  admin", 0.25)
out(
    f"    Password: {BOLD}{YEL}Kx7mR9pQ2wL4nF{R}    ← save this now; change it "
    "after first login",
    0.3,
)
out("", 0.15)
out(
    "    Logs:   docker compose logs -f soc-ai      Stop: docker compose down      "
    "Update: git pull && docker compose up -d --build",
    0.25,
)
out("", 0.15)
out(f"    {BOLD}Recommended next steps:{R}", 0.2)
out(
    "      • Auto-triage is ON — a sweep runs every 5 min "
    "(≤25 alerts, high-severity+).",
    0.18,
)
out(
    "        Turn it off in Config → Triage automation, or set "
    "AUTO_TRIAGE_SCHEDULE_ENABLED=false in .env.",
    0.2,
)
out(
    "      • Back up before every upgrade:  docker compose exec soc-ai "
    "python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz",
    0.25,
)
out(HR, 0.2)
beat()

# ── 3. healthz ───────────────────────────────────────────────────────────────
comment("3 — Confirm it's up")
type_cmd("curl -sk https://192.0.2.10:8443/healthz | jq")
out("{", 0.12)
out('  "status": "ok",', 0.08)
out('  "version": "1.2.8",', 0.08)
out('  "so_auth": "kratos",', 0.08)
out('  "misp_configured": false', 0.08)
out("}", 0.1)
beat()

# ── 4. sign in ───────────────────────────────────────────────────────────────
comment("4 — Sign in (the web UI does this for you; here it is from the CLI)")
type_cmd("curl -sk -c soc.cookies -X POST https://192.0.2.10:8443/api/v1/login \\")
out("       -H 'content-type: application/json' \\", 0.08)
out('       -d \'{"username":"admin","password":"Kx7mR9pQ2wL4nF"}\' | jq', 0.2)
out('{"ok": true, "username": "admin", "role": "admin"}', 0.2)
out(f"{DIM}# Or just open https://192.0.2.10:8443/app and sign in.{R}", 0.3)
beat()

# ── 5. triage ────────────────────────────────────────────────────────────────
# Event shapes copied from soc_ai/cli.py's _render_event (one line per SSE
# `event:`/`data:` pair; investigation_transcript's summary is a second,
# 3-space-indented line embedded in the SAME print, not a separate event).
comment("5 — Triage your first alert")
type_cmd("soc-ai triage KDG7CZ4BVBs3R9hXQbPY")
out(f"{DIM}session_start{R} alert_id='KDG7CZ4BVBs3R9hXQbPY'", 0.5)
out(
    f"{CYN}alert_context{R} low 'ET INFO CMS Hosting Domain in DNS Lookup "
    "(storyblok.com)' community_id=1:EJY2WE2Pxxxxxxxxxxxxxxxxxx "
    "pivots=[src:192.0.2.50, dst:203.0.113.10]",
    0.5,
)
out(f"{BLU}tool_call{R}   query_zeek_logs(community_id=1:EJY2WE2P…)", 0.7)
out(
    f"{DIM}tool_result{R} query_zeek_logs → 1 conn: pc-012 → "
    "a-us.storyblok.com  (443/tcp, 6.1 KB)",
    0.6,
)
out(f"{BLU}tool_call{R}   enrich_ip(203.0.113.10)", 0.7)
out(
    f"{DIM}tool_result{R} enrich_ip → ASN 15169 Google LLC · cloud · "
    "urlhaus:no abuse.ch:no",
    0.6,
)
out(f"{CYN}investigation_transcript{R} round=1 evidence=2 open_questions=0", 0.18)
out(
    f"   {DIM}A low-severity DNS informational alert for a CMS/CDN hosting domain; "
    f"the lookup resolves to Google Cloud with no threat-intel hits.{R}",
    0.5,
)
out(f"{DIM}usage{R} phase=investigate round=1 tools=2 reqs=3 tokens=18420/2146", 0.6)
beat(0.5)
out(f"{BOLD}{GRN}triage_report{R} FALSE_POSITIVE  confidence=0.7", 0.18)
out(
    "   Benign CDN/CMS DNS lookup (storyblok.com → Google Cloud), no malicious "
    "indicators. Safe to acknowledge after a glance.",
    0.18,
)
out(f"   {DIM}citations: alert-KDG7CZ4B…, event-lTG7CZ4B…{R}", 0.3)
out(
    f"   {YEL}→ ack_alert (Benign CDN/CMS lookup with no threat-intel hits "
    f"— safe to acknowledge.){R}",
    0.5,
)
out(f"{DIM}done{R} recommended_count=1 rounds=1", 0.4)
beat(0.6)
emit(f"{GRN}analyst@workstation{R}:{BLU}~/soc-ai{R}$ ")
sleep(2.5)

# ── write cast ───────────────────────────────────────────────────────────────
header = {"version": 2, "width": WIDTH, "height": HEIGHT,
          "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
          "title": "soc-ai — install & triage your first alert"}
with CAST.open("w", encoding="utf-8") as f:
    f.write(json.dumps(header) + "\n")
    for ev in events:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
print(f"wrote {CAST}  ({len(events)} events, {events[-1][0]:.1f}s)")
