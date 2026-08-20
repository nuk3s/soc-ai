"""Harness for setup.sh: runs the real script under bash with a stubbed PATH.

Each test's docstring names the regression it pins, not just the behavior it
asserts (house style adopted during the doctor preflight work).

Lesson learned twice now — once on .env content, once on stdout: a substring
assertion over a WHOLE blob is only as strong as how unique that substring is.
A generic word ("disclosure") can be satisfied by an unrelated teaser line even
after the block it was meant to pin is deleted outright. Positive assertions
must target text unique to the code path under test; every .env assertion goes
through env_values() (the effective-value parser below) rather than a raw
substring over env_text, for the same reason.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parent.parent

# ANALYST_MODEL is set to a value that does NOT match .env.example's shipped
# default (soc-ai-analyst) — see env_values() below for why a matching value
# would let a broken override go undetected.
BASE_CONF = """
SO_HOST=https://so.test.lan
SO_VERIFY_SSL=false
SO_USERNAME=analyst
SO_PASSWORD=hunter2
ES_HOSTS=https://so.test.lan:9200
LITELLM_BASE_URL=http://llm.test.lan:4000
ANALYST_MODEL=soc-ai-analyst-test
EVENTS_INDEX_PATTERN=logs-*
API_AUTH_REQUIRED=true
"""

STUBS = {
    "curl": "#!/bin/sh\necho 000\nexit 0\n",
    "docker": "#!/bin/sh\nexit 0\n",
    "openssl": "#!/bin/sh\necho stubsecret\nexit 0\n",
}

_KV_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class SetupRun(NamedTuple):
    proc: subprocess.CompletedProcess[str]
    env_text: str
    workdir: Path


def env_values(text: str) -> dict[str, str]:
    """Effective .env: the appended setup.sh overrides win over the .env.example base
    (the generated file INTENTIONALLY contains duplicate keys; last wins for dotenv).
    """
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _hermetic_env(tmp_path: Path) -> dict[str, str]:
    """Minimal PATH-only env pointed at the stub bin dir — not a full os.environ
    inheritance. setup.sh's load_conf() only sets a var if it ISN'T already in the
    environment (ambient env beats setup.conf), so inheriting the dev's shell would
    let an exported ANALYST_MODEL/SO_HOST/etc. leak in and silently mask what the
    conf file actually produced.
    """
    return {"PATH": f"{tmp_path / 'stubbin'}:{os.environ['PATH']}", "HOME": str(tmp_path)}


def run_setup(tmp_path: Path, conf: str) -> SetupRun:
    """Copy the script + its inputs into a scratch dir and run it non-interactively."""
    workdir = tmp_path / "repo"
    workdir.mkdir()
    for name in ("setup.sh", ".env.example", "pyproject.toml"):
        (workdir / name).write_text((REPO / name).read_text())
    (workdir / "setup.sh").chmod(0o755)
    (workdir / "setup.conf").write_text(conf)
    stubbin = tmp_path / "stubbin"
    stubbin.mkdir()
    for tool, body in STUBS.items():
        p = stubbin / tool
        p.write_text(body)
        p.chmod(0o755)
    proc = subprocess.run(
        ["bash", "setup.sh", "--auto", "--env-only"],
        cwd=workdir,
        env=_hermetic_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    env_text = (workdir / ".env").read_text() if (workdir / ".env").exists() else ""
    return SetupRun(proc, env_text, workdir)


def test_env_only_writes_env_and_stops_before_docker(tmp_path: Path) -> None:
    """Pins: --env-only must produce a complete .env yet never reach the Docker/build path

    (the regression would be the flag silently falling through to `docker compose up`).
    Also pins the effective values (not raw substrings — .env.example's own defaults
    can otherwise satisfy a naive substring check even when the override is broken).
    """
    run = run_setup(tmp_path, BASE_CONF)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    values = env_values(run.env_text)
    assert values["SO_HOST"] == "https://so.test.lan"
    assert values["ANALYST_MODEL"] == "soc-ai-analyst-test"
    assert "env-only" in run.proc.stdout
    assert "Building and starting" not in run.proc.stdout
    # Cheap guard against a future quoting/heredoc mistake in the .env writer block:
    # every live line must still be a plain KEY=value pair.
    for raw_line in run.env_text.splitlines():
        stripped = raw_line.strip()
        if stripped and not stripped.startswith("#"):
            assert _KV_LINE.match(stripped), f"not KEY=value shaped: {stripped!r}"


def test_env_only_rejects_unknown_option(tmp_path: Path) -> None:
    """Pins: arg parsing still rejects unrecognized flags (the `*)` catch-all in the
    while loop) once --env-only is added — a copy/paste of the new case arm landing
    in the wrong spot could otherwise swallow bad flags silently instead of exit 2.
    """
    workdir = tmp_path / "repo"
    workdir.mkdir()
    (workdir / "setup.sh").write_text((REPO / "setup.sh").read_text())
    (workdir / "setup.sh").chmod(0o755)
    proc = subprocess.run(
        ["bash", "setup.sh", "--not-a-real-flag"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 2
    assert "unknown option" in proc.stderr


def test_env_only_second_run_keeps_existing_env_on_recfg_no(tmp_path: Path) -> None:
    """Pins: on a re-run against a host that already has a .env, answering "no" to
    reconfigure (the --auto default) must still hit the new env-only exit cleanly
    instead of falling through into cert/build/start — the RECFG=n branch skips the
    whole `if [[ $RECFG == y ]]; then … fi` block, so the env-only gate right after
    it must not assume RECFG was ever set to y.
    """
    first = run_setup(tmp_path, BASE_CONF)
    assert first.proc.returncode == 0, first.proc.stderr + first.proc.stdout
    assert env_values(first.env_text)["SO_HOST"] == "https://so.test.lan"

    # Second run, same workdir: setup.conf still present, .env now exists too, so
    # RECFG defaults to n in --auto mode — setup.sh has
    # `yesno RECFG ".env already exists — reconfigure it?" n`.
    proc2 = subprocess.run(
        ["bash", "setup.sh", "--auto", "--env-only"],
        cwd=first.workdir,
        env=_hermetic_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc2.returncode == 0, proc2.stderr + proc2.stdout
    assert "Keeping the existing .env." in proc2.stdout
    assert "env-only" in proc2.stdout
    assert "Building and starting" not in proc2.stdout
    # Unchanged from the first run — reconfigure was declined.
    assert (first.workdir / ".env").read_text() == first.env_text


def test_cloud_route_sets_redaction_and_base_url(tmp_path: Path) -> None:
    """Pins: picking route 2 (`ask LLM_ROUTE ...` then `if [[ $LLM_ROUTE == 2 ]]`) must
    set `ANALYST_CLOUD_REDACTION=true`, must resolve `LLM_TLS` via
    `yesno LLM_TLS ... "$(b2yn "${LITELLM_VERIFY_SSL:-true}")"` — the same
    conf-driven-default mechanism the local route already uses, defaulting to
    verify-on when the conf doesn't set LITELLM_VERIFY_SSL — and must print the
    cloud egress disclosure.

    The disclosure pin targets "NOT SENT:" and the docs pointer — text unique to
    the disclosure block — rather than the bare word "disclosure": that word also
    appears in the route-2 teaser line printed before the model picker ("triage
    prompts leave this box... disclosure below"), so a naive
    `"disclosure" in stdout.lower()` check stayed green even with the whole
    disclosure block deleted outright.
    """
    conf = (
        BASE_CONF.replace(
            "LITELLM_BASE_URL=http://llm.test.lan:4000",
            "LITELLM_BASE_URL=https://openrouter.ai/api/v1",
        )
        + "LLM_ROUTE=2\n"
    )
    run = run_setup(tmp_path, conf)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    values = env_values(run.env_text)
    assert values.get("ANALYST_CLOUD_REDACTION") == "true"
    assert values.get("LITELLM_BASE_URL") == "https://openrouter.ai/api/v1"
    assert values.get("LITELLM_VERIFY_SSL") == "true"
    assert "NOT SENT:" in run.proc.stdout
    assert "docs/SAFETY_MODEL.md" in run.proc.stdout


def test_cloud_route_without_analyst_model_defaults_to_curated_first(tmp_path: Path) -> None:
    """Pins the --auto default for the cloud route's curated model shortlist
    (final-review I1): with no ANALYST_MODEL in the conf at all,
    `ANALYST_MODEL="${ANALYST_MODEL:-${CLOUD_MODELS[0]}}"` must resolve to the
    FIRST curated id — route 2 no longer falls through to the local route's
    live-list enumeration (which this harness's stubbed curl would answer
    with an unusable "000" anyway, so a regression back to the old shared
    fetch-then-ask flow would leave ANALYST_MODEL empty here, not merely
    wrong).

    Removes the ANALYST_MODEL line from BASE_CONF outright rather than
    replacing its value — env_values() must see NO conf-provided value at
    all for the CLOUD_MODELS[0] fallback arm (`${ANALYST_MODEL:-...}`) to
    trigger; a blank-but-present value would exercise the same arm today,
    but relying on that would stop pinning the "absent" case if the bash
    default-substitution operator ever changed.
    """
    conf = BASE_CONF.replace("ANALYST_MODEL=soc-ai-analyst-test\n", "").replace(
        "LITELLM_BASE_URL=http://llm.test.lan:4000",
        "LITELLM_BASE_URL=https://openrouter.ai/api/v1",
    )
    conf += "LLM_ROUTE=2\n"
    run = run_setup(tmp_path, conf)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("ANALYST_MODEL") == "anthropic/claude-sonnet-5"


def test_cloud_models_array_has_four_pinned_entries() -> None:
    """Static pin (final-review I1): setup.sh's CLOUD_MODELS curated shortlist
    must carry exactly 4 ids, none a floating/alias id. OpenRouter's own
    catalog marks "-latest" aliases with a leading ``~`` (e.g.
    ``~openai/gpt-latest``) — exactly the moving-target shape the rest of
    this repo pins away from for Docker image tags (tests/
    test_supply_chain_pins.py); the same discipline applies to a hardcoded
    cloud model id.
    """
    text = (REPO / "setup.sh").read_text()
    match = re.search(r"CLOUD_MODELS=\((.*?)\n\s*\)", text, re.DOTALL)
    assert match, "couldn't find the CLOUD_MODELS=( ... ) array literal in setup.sh"
    ids = re.findall(r'"([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*)"', match.group(1))
    assert len(ids) == 4, f"expected exactly 4 curated cloud model ids in setup.sh, found {ids}"
    for model_id in ids:
        assert "latest" not in model_id.lower(), (
            f"unpinned/floating id in setup.sh's CLOUD_MODELS: {model_id!r}"
        )
        assert not model_id.startswith("~"), (
            f"alias-shaped id in setup.sh's CLOUD_MODELS: {model_id!r}"
        )


def test_local_route_never_writes_redaction_flag(tmp_path: Path) -> None:
    """Pins: explicit route 1 (the fork's `else` arm sets `ANALYST_CLOUD_REDACTION=""`)
    must never write ANALYST_CLOUD_REDACTION to .env — the writer's
    `[[ -n ${ANALYST_CLOUD_REDACTION:-} ]] && echo ...` guard must actually suppress
    the line, not emit an empty-valued one — and must not print the cloud egress
    disclosure block ("NOT SENT:" is unique to it), which only applies to route 2.
    """
    run = run_setup(tmp_path, BASE_CONF + "LLM_ROUTE=1\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert "ANALYST_CLOUD_REDACTION" not in env_values(run.env_text)
    assert "NOT SENT:" not in run.proc.stdout


def test_route_default_is_local(tmp_path: Path) -> None:
    """Pins: `ask LLM_ROUTE "  Route" "${LLM_ROUTE:-1}"` defaults to "1" (local) when
    a conf file carries no LLM_ROUTE at all — BASE_CONF has none. The regression this
    guards against is the default silently flipping to the cloud route, which would
    start sending redacted-but-real triage traffic to a cloud provider nobody chose.
    Same assertions as the explicit-route-1 case: no redaction flag, no disclosure.
    """
    run = run_setup(tmp_path, BASE_CONF)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert "ANALYST_CLOUD_REDACTION" not in env_values(run.env_text)
    assert "NOT SENT:" not in run.proc.stdout


def test_invalid_llm_route_dies_before_writing_env(tmp_path: Path) -> None:
    """Pins: junk in LLM_ROUTE (anything but "1" or "2") must hard-fail via the new
    `case $LLM_ROUTE in 1|2) ;; *) die ... ;; esac` guard, not silently fall through.
    Before this guard, `LLM_ROUTE=cloud` skipped the `[[ $LLM_ROUTE == 2 ]]` branch
    (string "cloud" != "2") and landed in the `else` (local) arm's logic while a conf
    file could still carry a cloud-shaped LITELLM_BASE_URL through untouched — a
    cloud-bound endpoint with ANALYST_CLOUD_REDACTION left unset, at exit 0.

    The case/esac sits immediately after `ask LLM_ROUTE`, well before
    `[[ -f .env ]] || cp .env.example .env` — so a rejected run never creates .env
    at all in a fresh workdir (run_setup's scratch workdir starts with only
    .env.example, never .env, until the script itself copies one). That makes
    "no .env write" checkable two ways here: the file plain doesn't exist, and
    env_values() of the empty text is trivially empty.
    """
    run = run_setup(tmp_path, BASE_CONF + "LLM_ROUTE=cloud\n")
    assert run.proc.returncode != 0
    assert "must be 1 (local) or 2 (cloud)" in (run.proc.stderr + run.proc.stdout)
    assert not (run.workdir / ".env").exists()
    assert "ANALYST_CLOUD_REDACTION" not in env_values(run.env_text)


def test_llm_route_in_saved_conf_key_list(tmp_path: Path) -> None:
    """Pins: LLM_ROUTE stays in the SAVE block's `for k in ...; do` key list (setup.sh,
    `for k in SO_HOST ... LLM_ROUTE LITELLM_BASE_URL ...`) — a future reflow of that
    list could drop it silently, since nothing in this suite exercises the
    interactive, no-`--config` SAVE prompt the list feeds (the harness only ever runs
    `--auto`, which skips the `if [[ $AUTO -eq 0 && -z $CONF ]]` SAVE gate entirely).

    This is a static text pin over setup.sh's source, not a runtime check of a
    written setup.conf's contents — the runtime half (LLM_ROUTE actually lands
    correctly in a saved conf file) was verified by hand, not by this suite.
    """
    text = (REPO / "setup.sh").read_text()
    match = re.search(r"for k in (.*?); do", text, re.DOTALL)
    assert match, "couldn't find the saved-conf `for k in ...; do` key list in setup.sh"
    assert "LLM_ROUTE" in match.group(1)


def test_auto_triage_opt_in_written(tmp_path: Path) -> None:
    """Pins: accepting the day-1 prompt (`yesno AUTO_TRIAGE "  Auto-triage the alert
    backlog on a schedule?..." "${AUTO_TRIAGE:-y}"`) must reach `.env` as
    `AUTO_TRIAGE_SCHEDULE_ENABLED=true` via the write block's
    `[[ ${AUTO_TRIAGE:-n} == y ]] && echo "AUTO_TRIAGE_SCHEDULE_ENABLED=true"` —
    the flag `soc_ai/config.py`'s `auto_triage_schedule_enabled` reads to turn the
    background sweep on.
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=y\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("AUTO_TRIAGE_SCHEDULE_ENABLED") == "true"


def test_auto_triage_decline_leaves_default_off(tmp_path: Path) -> None:
    """Pins: declining (`AUTO_TRIAGE=n`) must leave `AUTO_TRIAGE_SCHEDULE_ENABLED`
    out of `.env` entirely — the write block's `== y` guard fires only on an exact
    "y" — so `soc_ai/config.py`'s `auto_triage_schedule_enabled: bool = False`
    default rules and the scheduler stays off.
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=n\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert "AUTO_TRIAGE_SCHEDULE_ENABLED" not in env_values(run.env_text)


def test_auto_triage_defaults_to_on(tmp_path: Path) -> None:
    """Pins the day-1 default: with no AUTO_TRIAGE at all in the conf, `yesno
    AUTO_TRIAGE ... "${AUTO_TRIAGE:-y}"` falls back to "y", so a fresh install
    still writes `AUTO_TRIAGE_SCHEDULE_ENABLED=true`. The regression this guards
    against is the default silently flipping to off, which would leave every
    fresh install's alert backlog undrained until an analyst finds the toggle.
    """
    run = run_setup(tmp_path, BASE_CONF)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("AUTO_TRIAGE_SCHEDULE_ENABLED") == "true"


def test_auto_triage_junk_degrades_to_off(tmp_path: Path) -> None:
    """Pins: junk in AUTO_TRIAGE (anything but a literal "y") must degrade to "off",
    never silently enable the scheduler. Unlike LLM_ROUTE — validated by a hard
    `case $LLM_ROUTE in 1|2) ;; *) die ... ;; esac` gate right after `ask LLM_ROUTE`
    — AUTO_TRIAGE has no such validation; it relies on `yesno`'s own coercion plus
    the write block's exact-match guard instead.

    `yesno`'s default is now coerced exactly ONCE, up front, through
    `[[ $__d =~ ^([Yy]|[Tt][Rr][Uu][Ee]$|1$|[Oo][Nn]$) ]]` (hardened as part of
    Task 6 — it previously assigned the raw default string verbatim in --auto
    mode, so AUTO_TRIAGE would end up literally "absolutely" instead of being
    coerced to "n" — then widened in Task 7 past a bare `^[Yy]` to also accept
    true/1/on spellings; see test_auto_triage_yes_word_enables_schedule et al.
    below). "absolutely" matches none of those alternatives (its first
    character isn't y/Y, t/T, "1", or o/O), so it still degrades to "n" either
    way. Either way, the write block's exact `[[ ${AUTO_TRIAGE:-n} == y ]]`
    comparison was already safe against junk (only a literal "y" matches), so
    this test's observable outcome — nothing written — holds across both
    hardening passes. The fix closes the gap for any FUTURE consumer of the raw
    AUTO_TRIAGE/STARTER_PACK variables that doesn't use an exact `== y`
    comparison (e.g. Task 7's STARTER_PACK consumption).
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=absolutely\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert "AUTO_TRIAGE_SCHEDULE_ENABLED" not in env_values(run.env_text)


def test_auto_triage_yes_word_enables_schedule(tmp_path: Path) -> None:
    """Pins: yesno()'s widened default-coercion (Task 7) accepts "yes" as
    truthy for a conf-driven default, not just a bare "y". Before the widening,
    --auto's default coercion and the interactive branch's typed-answer check
    used the identical `^[Yy]` test — "yes" already passed THAT (it starts with
    "y"), so this specific case was not itself broken. What Task 7 actually
    changes is documented by the sibling true/off tests below; this test pins
    that the widening didn't regress the pre-existing "yes" behavior.
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=yes\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("AUTO_TRIAGE_SCHEDULE_ENABLED") == "true"


def test_auto_triage_true_word_enables_schedule(tmp_path: Path) -> None:
    """Pins: "true" (and, via the same per-letter `[Tt][Rr][Uu][Ee]` character
    classes, "True"/"TRUE") is accepted as a truthy AUTO_TRIAGE default —
    NEW in Task 7. Before the widening this would have failed `^[Yy]` (its
    first character is "t", not "y") and silently degraded to "n", the same
    junk-collapse behavior as "absolutely" above — a plausible trap for anyone
    hand-editing setup.conf who thinks of the flag as a boolean.
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=true\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("AUTO_TRIAGE_SCHEDULE_ENABLED") == "true"


def test_auto_triage_off_word_stays_disabled(tmp_path: Path) -> None:
    """Pins: "off" stays falsy after the widened-truthy-forms change — the
    widening only ADDED true/1/on as truthy spellings; it must not have also
    widened the falsy side via an under-anchored pattern (e.g. an `[Oo]n`
    without a trailing `$` would incorrectly match the "o"+"n"-shaped prefix
    trap words share, though "off" itself doesn't collide — the real regression
    this guards is a future edit loosening the anchors).
    """
    run = run_setup(tmp_path, BASE_CONF + "AUTO_TRIAGE=off\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert "AUTO_TRIAGE_SCHEDULE_ENABLED" not in env_values(run.env_text)


def test_maxmind_key_written_when_provided(tmp_path: Path) -> None:
    """Pins: a MaxMind key in the conf (`ask MAXMIND_LICENSE_KEY "  MaxMind GeoLite2
    license key..." "${MAXMIND_LICENSE_KEY:-}"`) reaches `.env` verbatim via the
    write block's `[[ -n ${MAXMIND_LICENSE_KEY:-} ]] && echo
    "MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}"`.
    """
    run = run_setup(tmp_path, BASE_CONF + "MAXMIND_LICENSE_KEY=abc123\n")
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("MAXMIND_LICENSE_KEY") == "abc123"


def test_maxmind_blank_stays_empty(tmp_path: Path) -> None:
    """Pins: with no MAXMIND_LICENSE_KEY in the conf, the effective value stays
    empty — GeoIP/ASN enrichment silently no-ops rather than picking up a stray
    value.

    NOTE: `.env.example` ships a bare `MAXMIND_LICENSE_KEY=` line (added
    alongside this prompt), so the key is ALWAYS present in `env_values()` of a
    generated `.env` — the negative assertion here has to check the value is
    empty, not that the key is absent (`"MAXMIND_LICENSE_KEY" not in values`
    would be wrong here and would never fail, since .env.example's own blank
    line satisfies membership).
    """
    run = run_setup(tmp_path, BASE_CONF)
    assert run.proc.returncode == 0, run.proc.stderr + run.proc.stdout
    assert env_values(run.env_text).get("MAXMIND_LICENSE_KEY", "") == ""


def test_env_example_documents_maxmind_and_redaction() -> None:
    """Pins: `.env.example` documents both gaps closed by this task — MaxMind (only
    documented in docs/DOCKER.md before this, absent from the file analysts
    actually copy to build `.env`) and `ANALYST_CLOUD_REDACTION` (Task 5 added the
    code path and the setup.sh prompt but never an `.env.example` entry).

    Reads the repo's real `.env.example` directly rather than a generated `.env`,
    since setup.sh only ever COPIES this file verbatim as the base of a fresh one
    (`[[ -f .env ]] || cp .env.example .env`) — the documentation gap lives in the
    source file itself, not in anything setup.sh writes.
    """
    lines = (REPO / ".env.example").read_text().splitlines()
    assert any(line.startswith("MAXMIND_LICENSE_KEY=") for line in lines)
    assert any("ANALYST_CLOUD_REDACTION" in line for line in lines)


# ── post-start glue (Task 7): doctor preflight, starter pack, summary ──────────
#
# The post-start path (doctor exec, starter-pack curl calls, the printed
# summary) all run AFTER `$DC up -d [--build]` — a code path --env-only
# deliberately never reaches (it exits at `[[ $ENVONLY -eq 1 ]]`, well before
# section 3's cert generation, let alone section 4's build+start). This
# harness only ever drives `--auto --env-only`, so the three tests below are
# static source pins, not runtime exercises of the real Docker/curl calls —
# those were verified by hand against a hermetic instance (see the review
# notes for this task) rather than by this suite.


def test_setup_runs_doctor_after_start(tmp_path: Path) -> None:
    """Pins: setup.sh ALWAYS runs the extended doctor inside the container after
    the health poll — regardless of whether /healthz reported healthy — so
    every install path (source build or --prebuilt, healthy or not) ends in
    the same live fitness probe (doctor includes check_model_fitness plus the
    audit-grant / index-pattern / layered-reachability checks from Tasks 1-3).

    Pins the CONSISTENT compose-exec form: `$DC exec -T soc-ai ...` (`-T` —
    no TTY, since setup.sh's own stdout may be piped/captured). The
    failed-health-check hint a few lines above no longer prints its own
    copy-paste `${DC/ compose/} exec soc-ai ...` suggestion — a review pass on
    this task found that stale once the doctor started running unconditionally
    right after it, so it was reworded to just point forward at this run.

    Regex rather than a plain substring so incidental reflow of the
    surrounding bash (spacing, line wrap) doesn't false-fail the pin — the
    semantics being pinned are the exact invocation form, not the byte-exact
    line.
    """
    text = (REPO / "setup.sh").read_text()
    assert re.search(r"\$DC exec -T soc-ai python -m soc_ai doctor", text)
    # The old copy-paste hint is gone, not just reworded around — a stale
    # ${DC/ compose/} suggestion left behind would tell an operator to run the
    # doctor a SECOND time by hand right after setup.sh already ran it once.
    # Scoped to the specific stale invocation, not the bare `${DC/ compose/}`
    # idiom file-wide — that idiom is legitimate wherever setup.sh needs a
    # plain (non-compose) command name, e.g. deriving `docker` from `$DC`.
    assert "${DC/ compose/} exec soc-ai python -m soc_ai doctor" not in text


def test_setup_installs_starter_pack_via_api(tmp_path: Path) -> None:
    """Pins: the post-start path installs the runbook starter pack through the
    admin API, gated on the STARTER_PACK day-1 prompt from Task 6 — both the
    endpoint path and the opt-out gate must survive future refactors.

    Static source pin only (see module note above): the real call needs a
    live container plus a real admin login/session cookie, exercised instead
    by a hand-run verification against the hermetic `verify` harness for this
    task, not by this suite.

    The endpoint path is pinned via `re.search` (not `in`) for consistency
    with the other two source pins in this group, even though a bare path
    string has no internal whitespace for a reflow to disturb. The
    STARTER_PACK gate condition stays a plain substring check deliberately —
    it's bash conditional syntax (`${STARTER_PACK:-y}`) full of regex
    metacharacters that would need `re.escape` to search safely, and its
    spacing is bash-syntax-significant so it isn't at realistic reflow risk.
    """
    text = (REPO / "setup.sh").read_text()
    assert "if [[ ${STARTER_PACK:-y} == y ]]; then" in text
    assert re.search(r"/api/v1/runbooks/starter-pack", text)


def test_summary_mentions_auto_triage_when_enabled(tmp_path: Path) -> None:
    """Pins: the final summary makes auto-triage's enabled state visible
    (carryover Important from Task 6's review — accepting the day-1 opt-in
    left no confirmation anywhere in the printed summary, so an analyst had no
    way to learn a background sweep was now running short of reading .env).

    Static text pin ONLY — see the module note above for why a runtime
    exercise isn't possible through this harness (the summary block is well
    past --env-only's exit point). Also pins the specific Config-console
    section label (verified against `soc_ai/store/config_overrides.py`'s
    SECTION_ORDER/SECTION_PARENTS: the auto-triage settings live in the
    "Triage automation" section, nested under the "Triage & Workflow" parent
    header) — a generic "in Config" pointer would send an analyst hunting
    across six parent headers instead of straight to the right one.

    Regex rather than a plain substring for both lines (consistent with the
    other two source pins in this group) so a future rewrap of the summary
    bullet's punctuation/spacing doesn't false-fail the pin — the arrow in
    particular tolerates its surrounding spacing changing (`\\s*`) while still
    requiring the literal "Config" / "Triage automation" text and the arrow
    between them.
    """
    text = (REPO / "setup.sh").read_text()
    assert re.search(r"Auto-triage is ON", text)
    assert re.search(r"Config\s*→\s*Triage automation", text)


# ── optional local-LLM profile (Task 8): docker-compose.llm.yml + litellm.llm.yaml ──


def test_llm_compose_profile_is_wellformed() -> None:
    """Pins the optional local-LLM profile: both services pinned (never :latest),
    the litellm config carries the soc-ai-analyst alias the app expects, and the
    profile joins the main stack's network by its real derived name."""
    import yaml

    compose = yaml.safe_load((REPO / "docker-compose.llm.yml").read_text())
    assert set(compose["services"]) == {"ollama", "litellm"}
    for svc in compose["services"].values():
        assert ":latest" not in svc["image"]
        # rpartition, not a bare count(":") == 1 — a lab-registry re-pin
        # (registry.lan:5000/ollama/ollama:0.32.14) puts a second colon in
        # the host:port before the tag separator, which count() can't tell
        # apart from a missing tag.
        _, sep, tag = svc["image"].rpartition(":")
        assert sep and tag and "/" not in tag, f"no pinned tag: {svc['image']!r}"
    assert compose["networks"]["default"]["name"] == "soc-ai_default"
    assert compose["networks"]["default"]["external"] is True
    proxy_cfg = yaml.safe_load((REPO / "litellm.llm.yaml").read_text())
    names = [m["model_name"] for m in proxy_cfg["model_list"]]
    assert "soc-ai-analyst" in names


def test_lesser_models_doc_has_standing_one_up_heading() -> None:
    """Pins the setup.sh pointer's target heading: setup.sh's LLM-gateway prompt
    reads 'no backend yet? see docs/LESSER_MODELS.md → "Standing one up"'
    verbatim, so docs/LESSER_MODELS.md must carry that exact H2 heading or the
    pointer sends an operator to a page with nothing to find.
    """
    lines = (REPO / "docs" / "LESSER_MODELS.md").read_text().splitlines()
    assert any(line.strip() == "## Standing one up" for line in lines)
