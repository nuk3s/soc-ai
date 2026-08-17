"""Shared credential-detection DATA for the Oracle egress guard.

The redacter (:mod:`soc_ai.oracle.redact`) and the independent residue net
(:mod:`soc_ai.oracle.sanitize`) each compile their OWN regex from this data — the
two ENGINES stay independent so a bug in one cannot blind the other — but they
MUST agree on WHICH keys and WHICH stopwords define a credential.  When the data
was re-declared in each module, a token added to one net (a new service account
in the redacter's stopset, say) silently diverged from the other: the redacter
would pass that token verbatim while the residue net still flagged it, so every
alert carrying it refused Oracle escalation permanently — a silent feature outage
with one log line (finding oracle-cred-twin-nets).

Sharing the DATA (not the engine) keeps the invariant checkable: a parity test
asserts the residue net never fires on the redacter's own output across a corpus
of credential shapes, and both modules assert they reference the objects here.

This module intentionally has NO dependency on ``redact``/``sanitize`` so it can
be imported by both without a cycle.
"""

from __future__ import annotations

# Credential-context keys, longest-first so the alternation prefers ``username``
# over ``user``.  The winlog/EVTX compound field names (``TargetUserName`` /
# ``SubjectUserName`` / ``AccountName``; ``SamAccountName`` already covered) are
# spelled explicitly; ``user[_ .-]?name`` also covers the agent's own OQL echoed
# back as ``user.name:<val>``.  Each net embeds this in its OWN KV regex (the
# redacter with named groups; the residue net with json-escape-quote tolerance).
CRED_KEYS: str = (
    r"targetusername|subjectusername|samaccountname|accountname|"
    r"username|user[_ .-]?name|account|acct|logon|user|usr"
)

# Tokens that are NOT internal-identifying usernames — never tokenise these, and
# (mirror-side) never flag them as residue.  Booleans / status words that can
# follow ``account=`` / ``logon=`` in logs, plus the universal built-in accounts
# every host has.
CRED_VALUE_STOPSET: frozenset[str] = frozenset(
    {
        # booleans / status words that can follow ``account=`` / ``logon=`` in logs
        "true",
        "false",
        "null",
        "none",
        "nil",
        "yes",
        "no",
        "unknown",
        "na",
        "success",
        "successful",
        "failure",
        "failed",
        "fail",
        "denied",
        "allowed",
        "enabled",
        "disabled",
        "active",
        "inactive",
        "valid",
        "invalid",
        "error",
        "ok",
        "expired",
        "locked",
        "unlocked",
        # universal built-in accounts (every host has them — not identifying)
        "root",
        "system",
        "localsystem",
        "administrator",
        "admin",
        "guest",
        "nobody",
        "daemon",
        "bin",
        "sys",
        "sync",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "backup",
        "list",
        "irc",
        "gnats",
        "www-data",
        "sshd",
        "postfix",
        "anonymous",
        "ftp",
        "operator",
        "service",
        "localservice",
        "networkservice",
        "everyone",
        "self",
    }
)
