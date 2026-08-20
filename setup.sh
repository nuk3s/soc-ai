#!/usr/bin/env bash
#
# soc-ai guided installer — get from a fresh box to a running triage console.
#
#   Interactive (default):   ./setup.sh
#   Automated from a file:    cp setup.conf.example setup.conf   # then edit it
#                             ./setup.sh --auto
#   Automated, named file:    ./setup.sh --auto myhost.conf
#   Pre-seed interactive:     ./setup.sh --config myhost.conf
#   Prebuilt image (no build): ./setup.sh --prebuilt   # pulls ghcr.io/nuk3s/soc-ai
#   Test/CI mode:              ./setup.sh --auto --env-only   # write .env, then stop
#
# It installs Docker if missing, collects connection settings (validating them
# before the build), generates the encryption key + admin password + a TLS cert,
# writes .env, brings the stack up, seeds enrichment, and prints the URL + login.
# Re-running is safe.
set -euo pipefail
cd "$(dirname "$0")"

# ── args ──────────────────────────────────────────────────────────────────────
AUTO=0; CONF=""; SHOW_HELP=0; PREBUILT=0; ENVONLY=0
DEFAULT_CONF="setup.conf"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--auto|-y|--yes) AUTO=1 ;;
    -c|--config|--file) CONF="${2:-}"; shift ;;
    -p|--prebuilt) PREBUILT=1 ;;
    -h|--help) SHOW_HELP=1 ;;
    --env-only) ENVONLY=1 ;;
    *.conf|*.txt|*.env) CONF="$1" ;;     # bare filename → config file
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

if [[ $SHOW_HELP -eq 1 ]]; then
  sed -n '3,16p' "$0" | sed 's/^#\s\{0,1\}//; s/^#$//'
  exit 0
fi

# ── pretty output ─────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
else B=''; G=''; Y=''; R=''; C=''; N=''; fi
info(){ printf '%s %s\n' "${C}›${N}" "$*"; }
ok(){   printf '%s %s\n' "${G}✓${N}" "$*"; }
warn(){ printf '%s %s\n' "${Y}!${N}" "$*"; }
die(){  printf '%s %s\n' "${R}✗${N}" "$*" >&2; exit 1; }
hr(){ printf '%s\n' "────────────────────────────────────────────────────────────"; }

genfernet(){ head -c32 /dev/urandom | base64 | tr '+/' '-_'; }   # 44-char urlsafe = valid Fernet key
genpw(){ openssl rand -base64 15 2>/dev/null | tr -d '/+=' || head -c12 /dev/urandom | base64 | tr -d '/+='; }
b2yn(){ [[ ${1:-} == true ]] && echo y || echo n; }
trim(){ local s=$1; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# Load a KEY=value config file. Only sets vars that aren't already in the
# environment, so an explicit `FOO=bar ./setup.sh` still wins over the file.
load_conf(){ local f=$1 line k v
  [[ -r $f ]] || return 1
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line == *=* ]] || continue
    k=$(trim "${line%%=*}"); v=$(trim "${line#*=}")
    [[ $v == \"*\" && $v == *\" ]] && v=${v:1:-1}
    [[ $v == \'*\' && $v == *\' ]] && v=${v:1:-1}
    [[ -n $k && -z ${!k+x} ]] && export "$k=$v"
  done < "$f"
  return 0
}

# Prompt helpers — in --auto mode they take the default with no prompt.
ask(){ local __v=$1 __p=$2 __d=${3:-} __cur=${!1:-} def ans; def=${__cur:-$__d}
  if [[ $AUTO -eq 1 ]]; then printf -v "$__v" '%s' "$def"; return; fi
  if [[ -n $def ]]; then read -rp "  $__p [$def]: " ans || true; else read -rp "  $__p: " ans || true; fi
  printf -v "$__v" '%s' "${ans:-$def}"; }
asksecret(){ local __v=$1 __p=$2 __cur=${!1:-} ans
  if [[ $AUTO -eq 1 || -n $__cur ]]; then printf -v "$__v" '%s' "$__cur"; return; fi
  read -rsp "  $__p: " ans || true; echo; printf -v "$__v" '%s' "$ans"; }
yesno(){ local __v=$1 __p=$2 __d=${3:-y} ans
  # The default can be a raw, unvalidated conf-file value (e.g. AUTO_TRIAGE=yes
  # or STARTER_PACK=true), not just the clean y/n every existing caller passes
  # (literals, or b2yn()'s always-y/n output) — coerce ONCE, up front, so
  # --auto and the interactive Enter-takes-default fallback agree on what
  # counts as "yes" instead of each doing its own ad hoc test.
  #
  # Widened past a bare ^[Yy] so common truthy spellings in a hand-edited
  # setup.conf (true/True/TRUE, 1, on/ON) also read as yes — every alternative
  # except [Yy] is fully anchored (a leading ^ shared by the whole group, and
  # its own trailing $) so it matches the WHOLE default value, not a prefix:
  # "TRUE" isn't missed by a lowercase-only "true" test, and "online"/"1000"
  # can't false-positive off the "on"/"1" arms the way an unanchored substring
  # test would. A default of "" can't reach this test at all — `${3:-y}` above
  # already turned it into "y" (bash's `:-` triggers on unset OR empty).
  [[ $__d =~ ^([Yy]|[Tt][Rr][Uu][Ee]$|1$|[Oo][Nn]$) ]] && __d=y || __d=n
  if [[ $AUTO -eq 1 ]]; then printf -v "$__v" '%s' "$__d"; return; fi
  read -rp "  $__p ($([[ $__d == y ]] && echo 'Y/n' || echo 'y/N')): " ans || true
  ans=${ans:-$__d}; [[ $ans =~ ^[Yy] ]] && printf -v "$__v" '%s' y || printf -v "$__v" '%s' n; }

httpcode(){ curl -k -s -o /dev/null -w '%{http_code}' -m "${2:-8}" "$1" 2>/dev/null || echo 000; }

# Fetch a gateway/provider's /v1/models ids, sorted, one per line. Silent on
# any failure (empty output) — callers tell "reachable but empty" from
# "fetch failed" via `${#MODELS[@]}`. Shared by both LLM_ROUTE branches below.
fetch_gateway_models(){
  local base=$1 key=$2 insecure=$3 vflag=""
  local hdr=()
  [[ $insecure == n ]] && vflag="-k"
  [[ -n $key ]] && hdr=(-H "Authorization: Bearer ${key}")
  curl -fsS $vflag -m 12 "${hdr[@]}" "${base%/}/v1/models" 2>/dev/null \
    | grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' | sort
}

# Resolve the release version to pin the prebuilt GHCR image to, so --prebuilt
# never rides the mutable `:latest` tag (an unaudited moving target — every pull
# would be a silent upgrade). Prefer the repo VERSION in pyproject.toml; fall
# back to the newest `v*` git tag. Prints nothing if neither is resolvable.
resolve_release_version(){
  local v=""
  if [[ -r pyproject.toml ]]; then
    v=$(grep -m1 -E '^version[[:space:]]*=' pyproject.toml | sed -E 's/.*"([^"]+)".*/\1/')
  fi
  if [[ -z $v ]] && command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    v=$(git tag --list 'v*' --sort=-v:refname 2>/dev/null | head -1 | sed 's/^v//')
  fi
  printf '%s' "$v"
}

# Detect the events index pattern that actually matches THIS grid, so it's right
# on a single-node grid (local `logs-*` data streams) AND a multi-node one
# (reached cross-cluster as `*:logs-*`). Counts Suricata alerts under each
# prefix and picks the one with hits — querying both and unioning would
# double-count on a grid that registers a self-remote cluster.
detect_events_pattern(){
  local pfx cnt
  for pfx in '' '*:'; do
    cnt=$(curl -k -s -m 8 -u "${SO_USERNAME}:${SO_PASSWORD}" \
      "${ES_HOSTS%/}/${pfx}logs-*/_search?ignore_unavailable=true&allow_no_indices=true" \
      -H 'Content-Type: application/json' \
      -d '{"size":0,"track_total_hits":1,"query":{"term":{"event.dataset":"suricata.alert"}}}' 2>/dev/null \
      | grep -oE '"value"[[:space:]]*:[[:space:]]*[0-9]+' | head -1 | grep -oE '[0-9]+$')
    [[ -n ${cnt:-} && $cnt -gt 0 ]] && { printf '%slogs-*' "$pfx"; return 0; }
  done
  printf 'logs-*'   # fallback: the single-node form
}

echo
printf '%s\n' "${B}soc-ai setup${N} — guided Docker install"
# Resolve the config file: explicit --config, else setup.conf if it exists.
[[ -z $CONF && -r $DEFAULT_CONF ]] && CONF="$DEFAULT_CONF"
if [[ -n $CONF ]]; then
  [[ -r $CONF ]] || die "config file not found: $CONF"
  load_conf "$CONF" && ok "Loaded settings from ${B}${CONF}${N}"
fi
[[ $AUTO -eq 1 ]] && info "Automated mode (no prompts)." || info "Interactive mode — press Enter to accept [defaults]."
# --auto with nothing to go on would silently fall through to placeholder
# defaults and fail later — stop with a clear instruction instead.
if [[ $AUTO -eq 1 && -z $CONF && ! -f .env && -z ${SO_HOST:-} ]]; then
  die "--auto needs settings but found none. Run:  cp setup.conf.example setup.conf  → edit it → ./setup.sh --auto"
fi
hr

# ── 1. prerequisites ──────────────────────────────────────────────────────────
info "Checking prerequisites…"
for t in curl openssl; do command -v "$t" >/dev/null 2>&1 || die "'$t' is required but not installed (try: sudo dnf install -y $t  /  sudo apt install -y $t)"; done

if [[ $ENVONLY -eq 0 ]]; then
need_docker=0
command -v docker >/dev/null 2>&1 || need_docker=1
if [[ $need_docker -eq 0 ]] && ! docker compose version >/dev/null 2>&1; then
  warn "docker is present but the 'compose' plugin is missing"; need_docker=1; fi
if [[ $need_docker -eq 1 ]]; then
  warn "Docker (with the compose plugin) is not installed."
  yesno DOIT "Install Docker now, using Docker's official installer? (needs sudo)" y
  [[ $DOIT == y ]] || die "Install Docker + the compose plugin, then re-run ./setup.sh"
  # Docker's get.docker.com detects the distro (Debian / Ubuntu / Fedora /
  # RHEL / Rocky / Alma / CentOS …) and installs docker-ce + the compose and
  # buildx plugins from the right repo. One path instead of per-distro logic.
  info "Installing Docker (Docker's installer detects your distro)…"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh \
    || die "couldn't download get.docker.com — check the network, or install Docker yourself"
  if ! sudo sh /tmp/get-docker.sh 2>/tmp/get-docker.err; then
    # get.docker.com has no packages for some fresh EL10 distros — it points the
    # repo at e.g. download.docker.com/linux/rocky/$releasever (rocky/10), which
    # doesn't exist yet. Docker's centos/<ver> packages are EL-compatible; write a
    # CLEAN repo for them and retry. (Note: the gpgkey is .../linux/centos/gpg —
    # a fixed key path, NOT a version dir — so we can't just sed the broken repo.)
    ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID%%.*}")
    if [[ -n ${ver:-} ]] && command -v dnf >/dev/null 2>&1; then
      warn "get.docker.com has no packages for this EL${ver} distro; retrying with Docker's centos/${ver} packages…"
      sudo tee /etc/yum.repos.d/docker-ce.repo >/dev/null <<EOF
[docker-ce-stable]
name=Docker CE Stable - centos ${ver}
baseurl=https://download.docker.com/linux/centos/${ver}/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=https://download.docker.com/linux/centos/gpg
EOF
      sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
        || die "Docker install failed even via the centos/${ver} repo (see /tmp/get-docker.err) — install Docker yourself, then re-run"
    else
      die "Docker install failed (see /tmp/get-docker.err) — install Docker yourself, then re-run"
    fi
  fi
  rm -f /tmp/get-docker.sh /tmp/get-docker.err
  sudo systemctl enable --now docker 2>/dev/null || true
  # Let this user run docker without sudo from next login on.
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  docker compose version >/dev/null 2>&1 || sudo docker compose version >/dev/null 2>&1 \
    || die "Docker installed but 'docker compose' isn't working — check the install output above"
fi
if docker info >/dev/null 2>&1; then DC="docker compose"
else DC="sudo docker compose"; warn "Using sudo for docker this run — log out/in (or run 'newgrp docker') to use docker without sudo."; fi
ok "Docker ready — $(docker --version 2>/dev/null | cut -d, -f1)"
fi

# ── 2. configuration (.env) ───────────────────────────────────────────────────
hr
RECFG=y
if [[ -f .env ]]; then yesno RECFG ".env already exists — reconfigure it?" n
  [[ $RECFG == n ]] && info "Keeping the existing .env."; fi

if [[ $RECFG == y ]]; then
  info "Security Onion connection:"
  ask SO_HOST "  Security Onion URL" "${SO_HOST:-https://your-so-grid}"
  yesno SO_TLS "  Verify the grid's TLS cert? (No for a self-signed SO)" "$(b2yn "${SO_VERIFY_SSL:-false}")"
  ask SO_USERNAME "  SO analyst username" "${SO_USERNAME:-}"
  asksecret SO_PASSWORD "  SO analyst password"
  ask ES_HOSTS "  Elasticsearch URL" "${ES_HOSTS:-${SO_HOST%/}:9200}"
  [[ -n ${SO_HOST:-} && -n ${SO_USERNAME:-} && -n ${SO_PASSWORD:-} ]] \
    || die "SO_HOST, SO_USERNAME and SO_PASSWORD are required."

  # Validate SO + ES BEFORE the long build, so a typo'd host/password fails in
  # seconds instead of after a 3-minute build and a first hunt.
  info "Checking the grid…"
  code=$(httpcode "$SO_HOST")
  [[ $code == 000 ]] && warn "Can't reach SO at $SO_HOST (no response) — check the URL/network." \
                     || ok "Security Onion reachable (HTTP $code)."
  ecode=$(curl -k -s -o /dev/null -w '%{http_code}' -m 8 -u "${SO_USERNAME}:${SO_PASSWORD}" "$ES_HOSTS" 2>/dev/null || echo 000)
  case "$ecode" in
    200|201) ok "Elasticsearch credentials OK." ;;
    401|403) warn "Elasticsearch rejected those credentials (HTTP $ecode) — double-check the username/password." ;;
    000)     warn "Can't reach Elasticsearch at $ES_HOSTS — check the URL/network." ;;
    *)       ok  "Elasticsearch reachable (HTTP $ecode)." ;;
  esac

  echo
  info "AI model — how will soc-ai reach one?"
  echo "      1) Local / self-hosted endpoint you run (LiteLLM gateway, vLLM, Ollama) — nothing leaves your network"
  echo "      2) Cloud API key (OpenRouter or another OpenAI-compatible provider) — no local infra, redacted egress"
  ask LLM_ROUTE "  Route" "${LLM_ROUTE:-1}"
  case $LLM_ROUTE in
    1|2) ;;
    *) die "LLM_ROUTE must be 1 (local) or 2 (cloud) — got '${LLM_ROUTE}'" ;;
  esac
  if [[ $LLM_ROUTE == 2 ]]; then
    info "Cloud route — triage prompts leave this box, redacted first (disclosure below)."
    ask LITELLM_BASE_URL "  Provider base URL" "${LITELLM_BASE_URL:-https://openrouter.ai/api/v1}"
    asksecret LITELLM_API_KEY "  Provider API key"
    yesno LLM_TLS "  Verify the provider's TLS cert? (Yes for real cloud providers; No only behind a TLS-inspecting proxy)" "$(b2yn "${LITELLM_VERIFY_SSL:-true}")"
    ANALYST_CLOUD_REDACTION=true
  else
    info "LLM gateway (local / self-hosted; no backend yet? see docs/LESSER_MODELS.md → 'Standing one up'):"
    ask LITELLM_BASE_URL "  Gateway URL" "${LITELLM_BASE_URL:-http://localhost:4000}"
    asksecret LITELLM_API_KEY "  Gateway API key (blank if none)"
    yesno LLM_TLS "  Verify the gateway's TLS cert? (No for a self-signed gateway)" "$(b2yn "${LITELLM_VERIFY_SSL:-true}")"
    ANALYST_CLOUD_REDACTION=""
  fi

  # HEAVY_MODEL is the old name for ANALYST_MODEL — honor it if a config file
  # still uses it, so upgrades don't silently lose the setting.
  ANALYST_MODEL="${ANALYST_MODEL:-${HEAVY_MODEL:-}}"

  if [[ $LLM_ROUTE == 2 ]]; then
    # A cloud provider's /v1/models is a public catalog hundreds of ids long
    # (OpenRouter's alone runs 400+) — enumerating it here the way the local
    # route does below would bury a first-timer in irrelevant choices. Curated
    # shortlist instead, with an escape hatch for any other id the provider
    # serves.
    #
    # Curated cloud defaults — verified against openrouter.ai 2026-08-19
    # (curl -s https://openrouter.ai/api/v1/models | python3 -c "import
    # json,sys; [print(m['id']) for m in json.load(sys.stdin)['data']]" |
    # sort): one id per family, the newest stable (non-preview, non-free-tier)
    # release, each confirmed to advertise tools/tool_choice support. Any
    # other OpenAI-compatible id works too — qualify it first with:
    #   soc-ai model-probe --model <id>
    CLOUD_MODELS=(
      "anthropic/claude-sonnet-5"          # Anthropic — Sonnet-class
      "openai/gpt-5.4-mini"                # OpenAI — flagship-mini, tool-calling
      "deepseek/deepseek-v4-flash"         # DeepSeek — chat-class, non-reasoning
      "qwen/qwen3-next-80b-a3b-instruct"   # Qwen — large instruct
    )
    if [[ $AUTO -eq 1 ]]; then
      ANALYST_MODEL="${ANALYST_MODEL:-${CLOUD_MODELS[0]}}"
    else
      echo "    Known-good cloud models (tool-calling verified classes):"
      i=1; for m in "${CLOUD_MODELS[@]}"; do printf '      %2d) %s\n' "$i" "$m"; i=$((i+1)); done
      read -rp "  Number, or any model id from your provider [1]: " sel || true
      sel=${sel:-1}
      if [[ $sel =~ ^[0-9]+$ ]] && (( sel>=1 && sel<=${#CLOUD_MODELS[@]} )); then
        ANALYST_MODEL="${CLOUD_MODELS[$((sel-1))]}"
      else
        ANALYST_MODEL="$sel"
      fi
    fi
    # Best-effort, silent validation against the provider's real list — same
    # fetch the local route uses below, just not rendered as a picker.
    mapfile -t MODELS < <(fetch_gateway_models "$LITELLM_BASE_URL" "${LITELLM_API_KEY:-}" "$LLM_TLS")
    if [[ ${#MODELS[@]} -gt 0 ]]; then
      printf '%s\n' " ${MODELS[*]} " | grep -q " ${ANALYST_MODEL} " \
        && ok "Analyst model: ${B}${ANALYST_MODEL}${N}" \
        || warn "ANALYST_MODEL '${ANALYST_MODEL}' isn't in the gateway list — hunts will fail until it is."
    else
      warn "Couldn't list gateway models (unreachable / wrong key / TLS mismatch)."
    fi
  else
    # Fetch the gateway's model list so ANALYST_MODEL can't be silently wrong (a
    # wrong value answers /v1/models fine but 400s every hunt). No python needed.
    mapfile -t MODELS < <(fetch_gateway_models "$LITELLM_BASE_URL" "${LITELLM_API_KEY:-}" "$LLM_TLS")
    if [[ ${#MODELS[@]} -gt 0 ]]; then
      ok "Gateway serves ${#MODELS[@]} models."
      # default: existing value, else a sensible reasoning model if present
      hv="${ANALYST_MODEL:-}"
      if [[ -z $hv ]]; then for m in "${MODELS[@]}"; do [[ $m == *deepseek* || $m == *70b* || $m == *qwen*reason* ]] && { hv=$m; break; }; done; fi
      if [[ $AUTO -eq 1 ]]; then
        ANALYST_MODEL="${ANALYST_MODEL:-$hv}"
      else
        echo "    Pick the analyst model (used for every hunt):"
        i=1; for m in "${MODELS[@]}"; do printf '      %2d) %s%s\n' "$i" "$m" "$([[ $m == "$hv" ]] && echo '   ← suggested')"; i=$((i+1)); done
        read -rp "  Number or model name [${hv:-1}]: " sel || true
        sel=${sel:-$hv}
        if [[ $sel =~ ^[0-9]+$ ]] && (( sel>=1 && sel<=${#MODELS[@]} )); then ANALYST_MODEL="${MODELS[$((sel-1))]}"
        else ANALYST_MODEL="$sel"; fi
      fi
      printf '%s\n' " ${MODELS[*]} " | grep -q " ${ANALYST_MODEL} " \
        && ok "Analyst model: ${B}${ANALYST_MODEL}${N}" \
        || warn "ANALYST_MODEL '${ANALYST_MODEL}' isn't in the gateway list — hunts will fail until it is."
    else
      warn "Couldn't list gateway models (unreachable / wrong key / TLS mismatch)."
      ask ANALYST_MODEL "  Analyst model your gateway serves" "${ANALYST_MODEL:-soc-ai-analyst}"
    fi
  fi

  if [[ $LLM_ROUTE == 2 ]]; then
    echo
    info "Cloud egress disclosure — per investigation/hunt/chat turn, the provider sees:"
    echo "      SENT:     the triage prompts — alert fields, related-event summaries, enrichment"
    echo "                results, runbook excerpts — with internal IPs, hostnames, usernames,"
    echo "                MACs, and internal-domain emails replaced by opaque tokens (the"
    echo "                reversal map never leaves this box)."
    echo "      NOT SENT: raw pcap files, credentials or .env contents, the audit trail."
    echo "      Details:  docs/SAFETY_MODEL.md (redaction — Oracle + cloud analyst models)."
  fi

  echo
  info "Grid-specific tuning:"
  ask WEBUI_ALERTS_QUERY "  Alerts OQL filter" "${WEBUI_ALERTS_QUERY:-tags:alert}"
  # Auto-detect the events index pattern unless the operator pinned one. `logs-*`
  # for a single-node grid; `*:logs-*` when the data is only reachable
  # cross-cluster (multi-node). Either way the alerts console + agent searches
  # find the data — the old `*:so-*` default matched the wrong index family and
  # left the console empty.
  if [[ -z ${EVENTS_INDEX_PATTERN:-} && -n ${SO_USERNAME:-} && -n ${SO_PASSWORD:-} && -n ${ES_HOSTS:-} ]]; then
    info "  Detecting the events index pattern from the grid…"
    EVENTS_INDEX_PATTERN=$(detect_events_pattern)
    if [[ ${EVENTS_INDEX_PATTERN} == \*:* ]]; then
      ok "  Multi-node / cross-cluster grid → ${B}${EVENTS_INDEX_PATTERN}${N}"
    else
      ok "  Single-node grid → ${B}${EVENTS_INDEX_PATTERN}${N}"
    fi
  fi
  ask EVENTS_INDEX_PATTERN "  Events index pattern (single-node: logs-*  ·  multi-node: *:logs-*)" "${EVENTS_INDEX_PATTERN:-logs-*}"
  # Carry the same cross-cluster prefix to the cases/detections/playbooks indices.
  EIDX_PFX=""; [[ ${EVENTS_INDEX_PATTERN} == \*:* ]] && EIDX_PFX="*:"
  yesno APIAUTH "  Require login/token for the API? (recommended)" "$(b2yn "${API_AUTH_REQUIRED:-true}")"
  if [[ $APIAUTH == n ]]; then
    warn "API auth OFF — admin endpoints answer ANY caller that can reach the port."
    warn "  Not just writes (secret edits, user/token creation) but admin READS:"
    warn "  the user table, config, and which connection secrets are set. Safe only"
    warn "  on a loopback-bound dev box — choose 'yes' for any host reachable on the LAN."
  fi

  echo
  info "Enrichment feeds (optional):"
  # abuse.ch (URLhaus / ThreatFox / Feodo) now requires a free Auth-Key. Without
  # it those three feeds are skipped on every `blocklists refresh` (Tor + cloud
  # prefixes still work). Blank = skip. Register at https://auth.abuse.ch/ .
  ask ABUSE_CH_AUTH_KEY "  abuse.ch Auth-Key (blank to skip URLhaus/ThreatFox/Feodo)" "${ABUSE_CH_AUTH_KEY:-}"
  # MaxMind GeoLite2 (GeoIP/ASN enrichment). Free key: https://www.maxmind.com/en/geolite2/signup
  # Documented in docs/DOCKER.md but previously missing here — GeoIP silently
  # no-ops without it.
  ask MAXMIND_LICENSE_KEY "  MaxMind GeoLite2 license key (blank to skip GeoIP/ASN)" "${MAXMIND_LICENSE_KEY:-}"

  echo
  info "Day-1 automation:"
  # Plain yesno, no `case`/die validation like LLM_ROUTE's — deliberate. yesno's
  # --auto branch coerces its default through the same ^[Yy] test the interactive
  # branch uses (see yesno() above), so a junk conf value (e.g. AUTO_TRIAGE=maybe)
  # degrades to "n", never an unsafe state; a hard validation gate would be
  # redundant here.
  yesno AUTO_TRIAGE "  Auto-triage the alert backlog on a schedule? (every 5 min, ≤25 targets/sweep, high-severity+)" "${AUTO_TRIAGE:-y}"
  yesno STARTER_PACK "  Install the 10-runbook starter pack after start? (grounds verdicts; idempotent)" "${STARTER_PACK:-y}"

  CONFIG_SECRET_KEY=${CONFIG_SECRET_KEY:-$(genfernet)}
  BOOTSTRAP_ADMIN_PASSWORD=${BOOTSTRAP_ADMIN_PASSWORD:-$(genpw)}
  # Pin the prebuilt image to the release version, so --prebuilt never rides the
  # mutable :latest tag. Resolved from pyproject.toml (fallback: newest v* tag).
  SOC_AI_IMAGE_TAG=${SOC_AI_IMAGE_TAG:-$(resolve_release_version)}

  [[ -f .env ]] || cp .env.example .env
  sed -i '/# >>> soc-ai setup.sh >>>/,/# <<< soc-ai setup.sh <<</d' .env 2>/dev/null || true
  {
    echo "# >>> soc-ai setup.sh >>>   (this block wins — dotenv last value applies)"
    echo "SO_HOST=${SO_HOST%/}"
    echo "SO_VERIFY_SSL=$([[ $SO_TLS == y ]] && echo true || echo false)"
    echo "SO_USERNAME=${SO_USERNAME}"
    echo "SO_PASSWORD=${SO_PASSWORD}"
    echo "ES_HOSTS=${ES_HOSTS}"
    echo "ES_USERNAME=${SO_USERNAME}"
    echo "ES_PASSWORD=${SO_PASSWORD}"
    echo "ES_VERIFY_SSL=$([[ $SO_TLS == y ]] && echo true || echo false)"
    echo "LITELLM_BASE_URL=${LITELLM_BASE_URL%/}"
    echo "LITELLM_API_KEY=${LITELLM_API_KEY}"
    echo "LITELLM_VERIFY_SSL=$([[ $LLM_TLS == y ]] && echo true || echo false)"
    echo "ANALYST_MODEL=${ANALYST_MODEL}"
    [[ -n ${ANALYST_CLOUD_REDACTION:-} ]] && echo "ANALYST_CLOUD_REDACTION=true"
    [[ -n ${MAXMIND_LICENSE_KEY:-} ]] && echo "MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}"
    [[ ${AUTO_TRIAGE:-n} == y ]] && echo "AUTO_TRIAGE_SCHEDULE_ENABLED=true"
    [[ -n ${ABUSE_CH_AUTH_KEY:-} ]] && echo "ABUSE_CH_AUTH_KEY=${ABUSE_CH_AUTH_KEY}"
    # Prebuilt installs pin the image to a specific release rather than :latest
    # (an unaudited moving target). Source builds don't pull, so no pin is written.
    if [[ $PREBUILT -eq 1 ]]; then
      if [[ -n ${SOC_AI_IMAGE_TAG:-} ]]; then
        echo "SOC_AI_IMAGE_TAG=${SOC_AI_IMAGE_TAG}"
      else
        echo "# SOC_AI_IMAGE_TAG=   # PIN THIS to a release (e.g. 1.1.0); :latest is an unaudited moving target"
      fi
    fi
    echo "WEBUI_ALERTS_QUERY=${WEBUI_ALERTS_QUERY}"
    echo "EVENTS_INDEX_PATTERN=${EVENTS_INDEX_PATTERN}"
    echo "CASES_INDEX_PATTERN=${EIDX_PFX}so-case*"
    echo "DETECTIONS_INDEX_PATTERN=${EIDX_PFX}so-detection*"
    echo "PLAYBOOKS_INDEX_PATTERN=${EIDX_PFX}so-playbook*"
    echo "API_AUTH_REQUIRED=$([[ $APIAUTH == y ]] && echo true || echo false)"
    echo "CONFIG_SECRET_KEY=${CONFIG_SECRET_KEY}"
    echo "BOOTSTRAP_ADMIN_PASSWORD=${BOOTSTRAP_ADMIN_PASSWORD}"
    echo "SOC_AI_HOST=0.0.0.0"
    echo "SOC_AI_PORT=8443"
    echo "SOC_AI_TLS_CERT=/etc/soc-ai/cert.pem"
    echo "SOC_AI_TLS_KEY=/etc/soc-ai/key.pem"
    echo "SOC_AI_DATA_DIR=/var/lib/soc-ai/data"
    echo "# <<< soc-ai setup.sh <<<"
  } >> .env
  chmod 600 .env
  ok "Wrote .env"

  # Offer to save a reusable config (for automating the next host).
  if [[ $AUTO -eq 0 && -z $CONF ]]; then
    yesno SAVE "Save these answers to ${DEFAULT_CONF} for reuse (./setup.sh --auto)?" n
    if [[ $SAVE == y ]]; then
      umask 077
      {
        echo "# soc-ai automated-install settings — consumed by ./setup.sh --auto"
        echo "# Contains secrets; keep private (chmod 600, gitignored)."
        for k in SO_HOST SO_VERIFY_SSL SO_USERNAME SO_PASSWORD ES_HOSTS ES_VERIFY_SSL \
                 LLM_ROUTE LITELLM_BASE_URL LITELLM_API_KEY LITELLM_VERIFY_SSL ANALYST_MODEL \
                 WEBUI_ALERTS_QUERY EVENTS_INDEX_PATTERN API_AUTH_REQUIRED \
                 MAXMIND_LICENSE_KEY AUTO_TRIAGE STARTER_PACK \
                 CONFIG_SECRET_KEY BOOTSTRAP_ADMIN_PASSWORD; do
          case $k in
            SO_VERIFY_SSL|ES_VERIFY_SSL) v=$([[ $SO_TLS == y ]] && echo true || echo false) ;;
            LITELLM_VERIFY_SSL)          v=$([[ $LLM_TLS == y ]] && echo true || echo false) ;;
            API_AUTH_REQUIRED)           v=$([[ $APIAUTH == y ]] && echo true || echo false) ;;
            *)                           v="${!k:-}" ;;
          esac
          echo "$k=$v"
        done
      } > "$DEFAULT_CONF"
      ok "Saved ${DEFAULT_CONF} (chmod 600). Reuse it on another host with: ./setup.sh --auto"
    fi
  fi
fi

if [[ $ENVONLY -eq 1 ]]; then
  ok "env-only run: .env written; skipping cert generation, build, and start."
  exit 0
fi

# ── 3. TLS certificate ────────────────────────────────────────────────────────
hr
if [[ -f certs/cert.pem && -f certs/key.pem ]]; then ok "Reusing existing certs/."
else
  ipdef=$(hostname -I 2>/dev/null | awk '{print $1}'); ipdef=${ipdef:-127.0.0.1}
  ask CERT_HOST "Host IP/DNS for the TLS cert" "${CERT_HOST:-$ipdef}"
  mkdir -p certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=soc-ai" \
    -addext "subjectAltName=IP:${CERT_HOST},DNS:soc-ai.local" \
    -keyout certs/key.pem -out certs/cert.pem 2>/dev/null \
    || openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=soc-ai" \
         -keyout certs/key.pem -out certs/cert.pem 2>/dev/null
  chmod 644 certs/cert.pem; chmod 640 certs/key.pem   # cert is public; key not world-readable
  ok "Generated self-signed certs/ (your browser warns once — accept it)."
fi

# ── 4. build + start ──────────────────────────────────────────────────────────
hr
if [[ $PREBUILT -eq 1 ]]; then
  # Pull the published release image, pinned to SOC_AI_IMAGE_TAG from .env (never
  # the mutable :latest). With the image in the local store, `up` uses it instead
  # of building. If .env carries no pin yet (e.g. the operator kept an existing
  # .env), append one now so this pull — and every future `docker compose pull` —
  # is a deliberate, versioned upgrade rather than a silent :latest ride.
  if [[ -f .env ]] && ! grep -qE '^[[:space:]]*SOC_AI_IMAGE_TAG=' .env; then
    _pin=$(resolve_release_version)
    if [[ -n $_pin ]]; then
      printf 'SOC_AI_IMAGE_TAG=%s\n' "$_pin" >> .env
      ok "Pinned SOC_AI_IMAGE_TAG=${_pin} in .env (prebuilt image; :latest is an unaudited moving target)."
    else
      warn "Couldn't resolve a release version to pin — this pull will use :latest. Set SOC_AI_IMAGE_TAG in .env to pin it."
    fi
  fi
  info "Pulling the prebuilt image (ghcr.io/nuk3s/soc-ai) and starting the stack…"
  # If the image isn't published yet (no release tag), the registry answers
  # `denied` — catch that and offer to build from source in the same run, so a
  # stranger who copy-pasted --prebuilt still gets to a running stack. Everything
  # up to here (config, cert) is already done, so there's nothing to redo.
  if ! $DC pull soc-ai; then
    echo
    warn "Couldn't pull the prebuilt image ghcr.io/nuk3s/soc-ai:${SOC_AI_IMAGE_TAG:-<unpinned>}."
    warn "No tagged release is published yet, so there's no image to pull — this is expected right now."
    yesno BUILD_NOW "Build the image from source instead? (~3 min)" y
    if [[ $BUILD_NOW == y ]]; then
      info "Building and starting the stack (first build pulls deps — ~3 min)…"
      $DC up -d --build
    else
      info "Nothing built. When you're ready, run:  ${B}./setup.sh${N}  (no --prebuilt) to build from source."
      die "no image to run yet."
    fi
  else
    $DC up -d
  fi
else
  info "Building and starting the stack (first build pulls deps — ~3 min)…"
  $DC up -d --build
fi
info "Waiting for the service to report healthy…"
healthy=0
for _ in $(seq 1 60); do
  out=$(curl -fsk -m5 "https://localhost:8443/healthz" 2>/dev/null || true)
  if [[ -n $out ]]; then ok "Healthy — ${out}"; healthy=1; break; fi
  sleep 3
done
if [[ $healthy -ne 1 ]]; then
  warn "Health check timed out. Two things to try, in order:"
  warn "  1. The doctor runs next — read its FAIL lines, each carries a fix."
  warn "  2. Read the container logs:"
  printf '          %s\n' "${B}${DC} logs soc-ai${N}"
fi

# Run the doctor either way — healthy or not. /healthz is a liveness probe
# (process up, DB reachable); the doctor is the fitness probe (config, store,
# SO/ES reachability, the audit-write grant, AND check_model_fitness — a real
# structured-output call against the configured analyst model). Both the
# --prebuilt and source-build routes land here, so this is the one place every
# install path ends in the same live check.
hr
info "Preflight — the doctor checks every dependency, the model's fitness, and the audit grant…"
if $DC exec -T soc-ai python -m soc_ai doctor; then
  ok "Preflight clean."
elif [[ -z $($DC ps -q soc-ai 2>/dev/null) ]]; then
  # `ps -q` (no -a) lists only currently-RUNNING containers for the service —
  # empty means the exec above never reached the doctor at all (build/start
  # failed, or the container crashed after the health poll), a compose-level
  # problem, not a doctor finding. Narrating that as "doctor FAIL lines" would
  # send the operator chasing fixes for checks that never ran.
  warn "Couldn't run the doctor — the soc-ai container isn't up."
  printf '        %s\n' "${B}${DC} ps${N}   /   ${B}${DC} logs soc-ai${N}"
else
  warn "Doctor reported FAIL lines above — each carries its fix."
  warn "The audit-grant one is the classic: without it every ack/escalate/comment silently aborts."
  printf '        %s\n' "${B}ssh <admin>@<so-manager> 'sudo bash -s' < scripts/setup-audit-index.sh${N}"
fi

# ── seed the runbook starter pack ─────────────────────────────────────────────
if [[ ${STARTER_PACK:-y} == y ]]; then
  # BOOTSTRAP_ADMIN_PASSWORD is set in this shell on a fresh configure; on a
  # keep-existing-.env run, read it back from .env. .env is written as
  # `.env.example` (which ships BOOTSTRAP_ADMIN_PASSWORD= empty and
  # SOC_AI_PORT=8443) with the real managed block APPENDED after it, so the
  # file INTENTIONALLY carries duplicate keys — dotenv semantics are
  # last-value-wins, so any shell read-back has to take the LAST occurrence
  # too, same as the app itself and the test harness's env_values() helper
  # (tests/test_setup_script.py). A first-match read silently returns
  # .env.example's placeholder/default instead of the real value.
  if [[ -z ${BOOTSTRAP_ADMIN_PASSWORD:-} && -f .env ]]; then
    BOOTSTRAP_ADMIN_PASSWORD=$(grep '^BOOTSTRAP_ADMIN_PASSWORD=' .env | tail -1 | cut -d= -f2- | tr -d '\r') || true
  fi
  # The managed block always writes SOC_AI_PORT=8443, but a keep-existing .env
  # (RECFG=n) can carry a different port — read it back the same last-wins way
  # as the password instead of assuming 8443. (The earlier health poll
  # predates this task and stays hardcoded to 8443 — out of scope here.)
  _port=$(grep '^SOC_AI_PORT=' .env | tail -1 | cut -d= -f2- | tr -d '\r') || true
  _port=${_port:-8443}
  # genpw() (base64, tr -d '/+=') only ever emits alphanumerics, so naive JSON
  # interpolation is safe for a freshly generated password — but a
  # keep-existing .env can carry a user-set password with a quote or backslash
  # in it. Escape both before they go inside the JSON string literal.
  _pw_json=${BOOTSTRAP_ADMIN_PASSWORD//\\/\\\\}
  _pw_json=${_pw_json//\"/\\\"}
  info "Installing the runbook starter pack (idempotent)…"
  jar=$(mktemp)
  # The starter-pack route sits behind require_csrf_safe (soc_ai/api/security.py):
  # ANY cookie-authenticated mutating request with no Origin/Referer matching the
  # app's own origin is rejected 403 bad_origin — curl sends neither by default.
  # Send an Origin that matches this exact request's scheme+host+port (verified
  # live against the hermetic harness: the bare call 403s without this header).
  if curl -fsk -c "$jar" -m 10 -X POST "https://localhost:${_port}/api/v1/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"${_pw_json}\"}" >/dev/null 2>&1 \
     && out=$(curl -fsk -b "$jar" -m 30 -X POST "https://localhost:${_port}/api/v1/runbooks/starter-pack" \
        -H "Origin: https://localhost:${_port}" 2>/dev/null); then
    ok "Runbook starter pack: ${out}"
  else
    warn "Couldn't install the pack automatically (changed admin password?) —"
    warn "  click 'Load starter pack' on the Runbooks page instead."
  fi
  rm -f "$jar"
fi

# ── 5. seed enrichment ────────────────────────────────────────────────────────
hr
if [[ -n ${ABUSE_CH_AUTH_KEY:-} ]]; then _seed_q="Seed enrichment data now (Tor + AWS/GCP/Cloudflare + abuse.ch)?"
else _seed_q="Seed enrichment data now (Tor + AWS/GCP/Cloudflare; abuse.ch skipped — no key)?"; fi
yesno SEED "$_seed_q" y
[[ $SEED == y ]] && { info "Seeding…"; $DC run --rm soc-ai python -m soc_ai blocklists refresh \
  || warn "Some optional feeds were skipped (see above) — non-fatal."; }

# ── 6. done ───────────────────────────────────────────────────────────────────
hr; ipshow=$(hostname -I 2>/dev/null | awk '{print $1}'); ipshow=${ipshow:-localhost}
echo
ok "${B}soc-ai is running.${N}"
echo "    Open:     ${C}https://${ipshow}:8443/app${N}   (accept the self-signed cert on first visit)"
echo "    Sign in:  admin"
if [[ $RECFG == y ]]; then
  echo "    Password: ${B}${BOOTSTRAP_ADMIN_PASSWORD}${N}    ← save this now; change it after first login"
else
  echo "    Password: unchanged (your existing .env, or the first-boot logs)"
fi
echo
if [[ $PREBUILT -eq 1 ]]; then
  echo "    Logs:   ${DC} logs -f soc-ai      Stop: ${DC} down      Update: git pull && ${DC} pull soc-ai && ${DC} up -d"
else
  echo "    Logs:   ${DC} logs -f soc-ai      Stop: ${DC} down      Update: git pull && ${DC} up -d --build"
fi
echo
echo "    ${B}Recommended next steps:${N}"
if [[ ${AUTO_TRIAGE:-n} == y ]]; then
  echo "      • Auto-triage is ON — a sweep runs every 5 min (≤25 alerts, high-severity+)."
  echo "        Turn it off in Config → Triage automation, or set AUTO_TRIAGE_SCHEDULE_ENABLED=false in .env."
  if [[ ${LLM_ROUTE:-} == 2 ]]; then
    echo "        Each sweep calls your cloud provider — metered spend starts now; cap or"
    echo "        disable in Config → Triage automation."
  fi
fi
echo "      • Back up before every upgrade:  ${DC} exec soc-ai python -m soc_ai backup --out /var/lib/soc-ai/data/backup.tar.gz"
echo "      • Schedule the blocklist refresh (feeds go stale without it):"
echo "          cp scripts/cron.d/soc-ai-blocklists.example /etc/cron.d/soc-ai-blocklists   # edit the path first"
echo "      • Schedule backups with retention — see docs/DOCKER.md → Backup and restore."
hr
