---
name: Bug report
about: Something isn't working as documented
labels: bug
---

**What happened**
A clear description of the bug and what you expected instead.

**Repro**
Steps to reproduce. If it's triage-related, include the detection/rule name.

**Environment**
- soc-ai version (`/healthz` reports it, or `git rev-parse --short HEAD`):
- Security Onion version:
- Deployment: Docker / manual
- Which model `ANALYST_MODEL` points at:

**Logs**
Relevant `docker compose logs soc-ai` output. **Scrub real host IPs, hostnames,
and alert data first** — never paste secrets or grid data into a public issue.
