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
#
# It installs Docker if missing, collects connection settings (validating them
# before the build), generates the encryption key + admin password + a TLS cert,
# writes .env, brings the stack up, seeds enrichment, and prints the URL + login.
# Re-running is safe.
set -euo pipefail
cd "$(dirname "$0")"

# ── args ──────────────────────────────────────────────────────────────────────
AUTO=0; CONF=""; SHOW_HELP=0; PREBUILT=0
DEFAULT_CONF="setup.conf"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--auto|-y|--yes) AUTO=1 ;;
    -c|--config|--file) CONF="${2:-}"; shift ;;
    -p|--prebuilt) PREBUILT=1 ;;
    -h|--help) SHOW_HELP=1 ;;
    *.conf|*.txt|*.env) CONF="$1" ;;     # bare filename → config file
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

if [[ $SHOW_HELP -eq 1 ]]; then
  sed -n '3,15p' "$0" | sed 's/^#\s\{0,1\}//; s/^#$//'
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
  if [[ $AUTO -eq 1 ]]; then printf -v "$__v" '%s' "$__d"; return; fi
  read -rp "  $__p ($([[ $__d == y ]] && echo 'Y/n' || echo 'y/N')): " ans || true
  ans=${ans:-$__d}; [[ $ans =~ ^[Yy] ]] && printf -v "$__v" '%s' y || printf -v "$__v" '%s' n; }

httpcode(){ curl -k -s -o /dev/null -w '%{http_code}' -m "${2:-8}" "$1" 2>/dev/null || echo 000; }

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
  info "LLM gateway (LiteLLM):"
  ask LITELLM_BASE_URL "  Gateway URL" "${LITELLM_BASE_URL:-http://localhost:4000}"
  asksecret LITELLM_API_KEY "  Gateway API key (blank if none)"
  yesno LLM_TLS "  Verify the gateway's TLS cert? (No for a self-signed gateway)" "$(b2yn "${LITELLM_VERIFY_SSL:-true}")"

  # Fetch the gateway's model list so ANALYST_MODEL can't be silently wrong (a
  # wrong value answers /v1/models fine but 400s every hunt). No python needed.
  vflag=""; [[ $LLM_TLS == n ]] && vflag="-k"
  hdr=(); [[ -n ${LITELLM_API_KEY:-} ]] && hdr=(-H "Authorization: Bearer ${LITELLM_API_KEY}")
  mapfile -t MODELS < <(curl -fsS $vflag -m 12 "${hdr[@]}" "${LITELLM_BASE_URL%/}/v1/models" 2>/dev/null \
    | grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' | sort)
  # HEAVY_MODEL is the old name for ANALYST_MODEL — honor it if a config file
  # still uses it, so upgrades don't silently lose the setting.
  ANALYST_MODEL="${ANALYST_MODEL:-${HEAVY_MODEL:-}}"
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

  CONFIG_SECRET_KEY=${CONFIG_SECRET_KEY:-$(genfernet)}
  BOOTSTRAP_ADMIN_PASSWORD=${BOOTSTRAP_ADMIN_PASSWORD:-$(genpw)}

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
                 LITELLM_BASE_URL LITELLM_API_KEY LITELLM_VERIFY_SSL ANALYST_MODEL \
                 WEBUI_ALERTS_QUERY EVENTS_INDEX_PATTERN API_AUTH_REQUIRED \
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
  # Pull the published release image (SOC_AI_IMAGE_TAG pins a version; default
  # latest). With the image in the local store, `up` uses it instead of building.
  info "Pulling the prebuilt image (ghcr.io/nuk3s/soc-ai) and starting the stack…"
  # If the image isn't published yet (no release tag), the registry answers
  # `denied` — catch that and offer to build from source in the same run, so a
  # stranger who copy-pasted --prebuilt still gets to a running stack. Everything
  # up to here (config, cert) is already done, so there's nothing to redo.
  if ! $DC pull soc-ai; then
    echo
    warn "Couldn't pull the prebuilt image ghcr.io/nuk3s/soc-ai:${SOC_AI_IMAGE_TAG:-latest}."
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
  warn "  1. Run the doctor — it pinpoints which dependency is unhappy (config, store, SO, ES, gateway, model):"
  printf '          %s\n' "${B}${DC/ compose/} exec soc-ai python -m soc_ai doctor${N}"
  warn "  2. Read the container logs:"
  printf '          %s\n' "${B}${DC} logs soc-ai${N}"
fi

# ── 5. seed enrichment ────────────────────────────────────────────────────────
hr
yesno SEED "Seed enrichment data now (Tor + AWS/GCP/Cloudflare; abuse.ch needs a free key)?" y
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
hr
