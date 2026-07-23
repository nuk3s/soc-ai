#!/usr/bin/env python3
"""Generate the soc-ai install walkthrough asciicast (asciinema v2).

Reproducible + public-safe: no live environment, no real hosts/creds. Renders the
documented flow — clone -> ./setup.sh -> healthz -> sign in -> triage first alert.

    python3 docs/demo/make_walkthrough_cast.py            # writes the .cast
    agg --font-size 16 docs/demo/install-walkthrough.cast docs/img/install-walkthrough.gif

Keep this in sync with setup.sh's banner and `soc-ai triage` output if they change.
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
comment("2 — Guided setup (builds + starts the Docker stack)")
type_cmd("./setup.sh")
out(f"{BOLD}soc-ai setup{R} — guided Docker install", 0.2)
out(f"{DIM}──────────────────────────────────────────{R}", 0.2)
out(f"{CYN}›{R} Checking prerequisites…", 0.5)
out(f"  {GRN}✓{R} Docker ready — version 27.2.0", 0.5)
beat(0.5)
out(f"{CYN}›{R} Security Onion connection:", 0.3)
emit("  Security Onion URL: ")
sleep(0.5)
for ch in "https://soc.example.com":
    emit(ch); sleep(0.03)
out("", 0.3)
emit("  SO analyst username: ")
sleep(0.4)
for ch in "analyst@example.com":
    emit(ch); sleep(0.03)
out("", 0.3)
out(f"  SO analyst password: {DIM}••••••••••{R}", 0.6)
out(f"  {GRN}✓{R} Security Onion reachable (HTTP 200).   {GRN}✓{R} Elasticsearch OK.", 0.6)
beat(0.5)
out(f"{CYN}›{R} LLM gateway (LiteLLM):", 0.3)
emit("  Gateway URL: ")
sleep(0.4)
for ch in "https://llm.example.com:8000":
    emit(ch); sleep(0.03)
out("", 0.3)
emit("  Gateway API key (blank if none): ")
sleep(0.4)
for ch in "••••••••••":
    emit(ch); sleep(0.04)
out("", 0.3)
out(f"  Verify the gateway's TLS cert? (No for a self-signed gateway) {DIM}[y/N]{R}: n", 0.5)
out(f"  {GRN}✓{R} Gateway serves 6 models.", 0.4)
out(f"  Pick the analyst model (used for every hunt):", 0.3)
out(f"     1) llama-3.3-70b-instruct   {DIM}← suggested{R}", 0.15)
out(f"     2) qwen2.5-72b-instruct", 0.15)
out(f"     3) mixtral-8x22b-instruct", 0.2)
out(f"  Number or model name {DIM}[1]{R}: {DIM}↵{R}", 0.6)
out(f"  {GRN}✓{R} Analyst model: llama-3.3-70b-instruct", 0.4)
out(f"  Require login/token for the API? (recommended) {DIM}[Y/n]{R}: y", 0.5)
out(f"{GRN}✓{R} Wrote .env", 0.5)
beat(0.5)
out(f"{CYN}›{R} Building and starting the stack {DIM}(first build pulls deps — ~3 min)…{R}", 0.6)
out(f"{DIM}[+] Building 184.6s (13/13) FINISHED{R}", 0.5)
out(f"[+] Running 1/1  {GRN}✓{R} soc-ai  Started", 0.5)
out(f"{CYN}›{R} Waiting for the service to report healthy…", 0.7)
out(f'  {GRN}✓{R} Healthy — {{"status":"ok","version":"1.2.2"}}', 0.5)
beat(0.6)
out(f"{DIM}──────────────────────────────────────────{R}", 0.2)
out(f"{GRN}{BOLD}✓ soc-ai is running.{R}", 0.3)
out(f"    Open:     {CYN}https://soc.example.com:8443/app{R}  {DIM}(accept the self-signed cert){R}", 0.25)
out(f"    Sign in:  {BOLD}admin{R}", 0.25)
out(f"    Password: {YEL}Kx7mR9pQ2wL4nF{R}  {DIM}← save this; change it after first login{R}", 0.3)
out(f"{DIM}──────────────────────────────────────────{R}", 0.2)
beat()

# ── 3. healthz ───────────────────────────────────────────────────────────────
comment("3 — Confirm it's up")
type_cmd("curl -sk https://soc.example.com:8443/healthz | jq")
out("{", 0.12)
out('  "status": "ok",', 0.08)
out('  "version": "1.2.2",', 0.08)
out('  "so_auth": "kratos",', 0.08)
out('  "misp_configured": false', 0.08)
out("}", 0.1)
beat()

# ── 4. sign in ───────────────────────────────────────────────────────────────
comment("4 — Sign in (the web UI does this for you; here it is from the CLI)")
type_cmd("curl -sk -c soc.cookies -X POST https://soc.example.com:8443/api/v1/login \\")
out("       -H 'content-type: application/json' \\", 0.08)
out('       -d \'{"username":"admin","password":"Kx7mR9pQ2wL4nF"}\' | jq', 0.2)
out(f'{{"ok": true, "username": "admin", "role": "admin"}}', 0.2)
out(f"{DIM}# Or just open https://soc.example.com:8443/app and sign in.{R}", 0.3)
beat()

# ── 5. triage ────────────────────────────────────────────────────────────────
comment("5 — Triage your first alert")
type_cmd("soc-ai triage KDG7CZ4BVBs3R9hXQbPY")
out(f"{DIM}session_start{R} alert_id=KDG7CZ4BVBs3R9hXQbPY", 0.5)
out(f"{CYN}alert_context{R} {DIM}low{R} 'ET INFO CMS Hosting Domain in DNS Lookup (storyblok.com)'", 0.5)
out(f"               pivots=[src:192.0.2.50, dst:203.0.113.10]", 0.4)
out(f"{DIM}tool_call{R}   query_zeek_logs(community_id=1:EJY2WE2P…)", 0.7)
out(f"{DIM}tool_result{R} → 1 conn: pc-012 → a-us.storyblok.com  (443/tcp, 6.1 KB)", 0.6)
out(f"{DIM}tool_call{R}   enrich_ip(203.0.113.10)", 0.7)
out(f"{DIM}tool_result{R} → ASN 15169 Google LLC · cloud · urlhaus:no abuse.ch:no", 0.6)
out(f"{DIM}investigation_transcript{R} round=1 evidence=2", 0.5)
out(f"   A low-severity DNS informational alert for a CMS/CDN hosting domain;", 0.18)
out(f"   the lookup resolves to Google Cloud with no threat-intel hits.", 0.5)
out(f"{DIM}usage{R} tokens=24,566 · 3 tools · 1 round", 0.6)
beat(0.5)
out(f"{BOLD}{GRN}triage_report  FALSE_POSITIVE  confidence 0.70{R}", 0.4)
out(f"   Benign CDN/CMS DNS lookup (storyblok.com → Google Cloud), no malicious", 0.18)
out(f"   indicators. Safe to acknowledge after a glance.", 0.3)
out(f"   {DIM}citations: alert-KDG7CZ4B…, event-lTG7CZ4B…{R}", 0.3)
out(f"   {YEL}→ recommends:{R} ack_alert  {DIM}(execute it from the report in the UI){R}", 0.5)
out(f"{GRN}done{R} recommended_count=1 rounds=1", 0.4)
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
