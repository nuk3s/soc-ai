#!/usr/bin/env bash
# scripts/tls-proxy.sh: the proxy path in one command.
#
# Caddy terminates TLS in front of soc-ai and renews the certificate. soc-ai
# serves plain HTTP on the compose network. This script writes the proxy
# settings to .env, starts Caddy through the compose "proxy" profile, waits
# for the certificate and reports the result. It backs .env up first.
#
#   scripts/tls-proxy.sh enable <domain> [auto|internal|<cert.pem> <key.pem>]
#   scripts/tls-proxy.sh enable <domain> acme <directory-url> <root.pem>
#   scripts/tls-proxy.sh disable
#   scripts/tls-proxy.sh status
#   scripts/tls-proxy.sh --dry-run enable <domain> [...]
#
# See docs/DOCKER.md, TLS paths.
set -euo pipefail
cd "$(dirname "$0")/.."

# ── output ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'
else B=''; G=''; Y=''; R=''; C=''; N=''; fi
info(){ printf '%s %s\n' "${C}›${N}" "$*"; }
ok(){   printf '%s %s\n' "${G}✓${N}" "$*"; }
warn(){ printf '%s %s\n' "${Y}!${N}" "$*"; }
die(){  printf '%s %s\n' "${R}✗${N}" "$*" >&2; exit 1; }
usage_die(){ printf '%s %s\n' "${R}✗${N}" "$*" >&2; exit 2; }

usage(){ cat <<'USAGE'
Usage:
  scripts/tls-proxy.sh enable <domain> [auto|internal|<cert.pem> <key.pem>]
  scripts/tls-proxy.sh enable <domain> acme <directory-url> <root.pem>
  scripts/tls-proxy.sh disable
  scripts/tls-proxy.sh status
  scripts/tls-proxy.sh --dry-run enable <domain> [...]
  scripts/tls-proxy.sh --dry-run disable

enable    Put Caddy in front of soc-ai on <domain>, ports 80 and 443.
          auto       A certificate from Let's Encrypt. The default. The name
                     must resolve to this host from the internet.
          internal   A certificate from Caddy's own CA. The script exports
                     the root as caddy-root.crt and prints the trust steps.
          <cert.pem> <key.pem>
                     Your own certificate and key. The script copies them
                     into ./certs/.
          acme <directory-url> <root.pem>
                     A certificate from your own ACME CA, for example
                     step-ca or a Caddy acme_server. Caddy obtains and
                     renews it. The URL is the https ACME directory. The
                     root file is the CA root. Caddy trusts it for the
                     connection to the CA. The script copies it into
                     ./certs/acme-ca-root.pem.
disable   Go back to the direct path. soc-ai terminates TLS on port 8443.
status    Print the mode, the domain, the source and one health check.
--dry-run Print the .env changes and the commands. Change nothing.

enable writes these keys to .env: SOC_AI_TLS_CERT and SOC_AI_TLS_KEY blank,
SOC_AI_BIND=127.0.0.1, SOC_AI_DOMAIN, SOC_AI_CADDY_TLS, COMPOSE_PROFILES=proxy
and PROXY_TRUSTED_IPS. Each run backs .env up to .env.bak-<stamp> first.
USAGE
}

# ── .env helpers ──────────────────────────────────────────────────────────────
# Last value wins, the way dotenv and compose read the file. One pair of
# quotes is stripped.
env_get(){ local v
  v=$(grep -E "^[[:space:]]*$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r') || true
  [[ ${#v} -ge 2 && $v == \'*\' ]] && v=${v:1:-1}
  [[ ${#v} -ge 2 && $v == \"*\" ]] && v=${v:1:-1}
  printf '%s' "$v"
}

# Replace the KEY= line. When the file carries the key more than once, the
# last one wins for dotenv, so that line takes the new value and the earlier
# ones go. Append when the key is absent. Every other line stays.
env_set(){ local key=$1 val=$2 tmp n seen=0 line
  n=$(grep -cE "^[[:space:]]*${key}=" .env || true)
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line =~ ^[[:space:]]*${key}= ]]; then
      seen=$((seen + 1))
      [[ $seen -eq $n ]] && printf '%s=%s\n' "$key" "$val"
      continue
    fi
    printf '%s\n' "$line"
  done < .env > "$tmp"
  [[ $n -gt 0 ]] || printf '%s=%s\n' "$key" "$val" >> "$tmp"
  cat "$tmp" > .env; rm -f "$tmp"
}

env_unset(){ local key=$1 tmp line
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*${key}= ]] && continue
    printf '%s\n' "$line"
  done < .env > "$tmp"
  cat "$tmp" > .env; rm -f "$tmp"
}

# COMPOSE_PROFILES is a comma list. The "postgres" profile can sit in it next
# to "proxy", so these two add or remove one name and keep the others. The
# list goes away when the last name does.
profile_list_without(){ local name=$1 out="" p parts=()
  IFS=',' read -ra parts <<< "$(env_get COMPOSE_PROFILES)" || true
  for p in "${parts[@]}"; do
    p=${p//[[:space:]]/}
    [[ -z $p || $p == "$name" ]] && continue
    out+="${out:+,}$p"
  done
  printf '%s' "$out"
}
profile_add(){ local rest; rest=$(profile_list_without "$1")
  env_set COMPOSE_PROFILES "${rest:+$rest,}$1"
}
profile_remove(){ local rest; rest=$(profile_list_without "$1")
  if [[ -n $rest ]]; then env_set COMPOSE_PROFILES "$rest"; else env_unset COMPOSE_PROFILES; fi
}

# One backup per run. A second run in the same second gets a numbered name,
# so no backup overwrites an earlier one.
backup_env(){ local stamp n=1; stamp=$(date +%Y%m%dT%H%M%S)
  BACKUP=".env.bak-${stamp}"
  while [[ -e $BACKUP ]]; do n=$((n + 1)); BACKUP=".env.bak-${stamp}-${n}"; done
  cp -p .env "$BACKUP"
  ok "Backed up .env to ${BACKUP}"
}

# ── docker ────────────────────────────────────────────────────────────────────
DOCKER=(docker)
pick_docker(){
  if docker info >/dev/null 2>&1; then DOCKER=(docker)
  else DOCKER=(sudo docker); warn "Using sudo for docker this run."; fi
}

# Compose names the network after the project. The project is
# COMPOSE_PROJECT_NAME from .env, or the directory name. Compose lowercases
# the name and replaces every other character with an underscore.
project_name(){ local n
  n=$(env_get COMPOSE_PROJECT_NAME)
  [[ -n $n ]] || n=$(basename "$PWD")
  printf '%s' "$n" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]/_/g; s/^[^a-z0-9]+//'
}

network_subnet(){ "${DOCKER[@]}" network inspect "$1" -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null; }

# Polling: 40 tries, TLS_PROXY_POLL_S seconds apart. 3 s by default, 120 s in all.
POLL=${TLS_PROXY_POLL_S:-3}
TRIES=40

health_code(){ curl -sk -m 5 "$@" -o /dev/null -w '%{http_code}' 2>/dev/null || echo 000; }

# ── domain and source ─────────────────────────────────────────────────────────
valid_domain(){
  [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]
}

# An https URL with no space, quote or brace. The value lands in .env and in
# the Caddyfile through SOC_AI_CADDY_TLS, so it must stay one plain token.
valid_acme_url(){
  [[ $1 =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~%/-]*)?$ ]]
}

# The root file holds a certificate and no private key.
check_acme_root(){
  [[ -r $1 ]] || usage_die "Root certificate file not found: $1"
  grep -q -- '-----BEGIN CERTIFICATE-----' "$1" \
    || usage_die "The root file holds no PEM certificate: $1"
  ! grep -q -- 'PRIVATE KEY-----' "$1" \
    || usage_die "The root file holds a private key. Give the CA root certificate only: $1"
}

# The Caddyfile snippet acme_ca takes the directory URL and the root path.
ACME_SNIPPET="import acme_ca"
ACME_ROOT_FILE=certs/acme-ca-root.pem

acme_url_of(){ local rest=${1#"${ACME_SNIPPET} "}; printf '%s' "${rest%% *}"; }

source_label(){
  case "$1" in
    "")                  printf 'auto (Let'"'"'s Encrypt)' ;;
    "tls internal")      printf 'internal (Caddy CA)' ;;
    "${ACME_SNIPPET} "*) printf 'acme (%s)' "$(acme_url_of "$1")" ;;
    *)                   printf 'your files in ./certs/' ;;
  esac
}

print_trust_steps(){
  echo
  info "Trust the Caddy root certificate on each client. The file is ./caddy-root.crt."
  echo "    Fedora, RHEL:    sudo cp caddy-root.crt /etc/pki/ca-trust/source/anchors/soc-ai-caddy.crt && sudo update-ca-trust"
  echo "    Debian, Ubuntu:  sudo install -m644 caddy-root.crt /usr/local/share/ca-certificates/soc-ai-caddy.crt && sudo update-ca-certificates"
  echo "    macOS:           sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt"
  echo "    Windows:         certutil -addstore -f Root caddy-root.crt"
  echo "    Browsers on those hosts trust it after a restart. Firefox needs its own import under Settings, Certificates."
}

# ── enable ────────────────────────────────────────────────────────────────────
cmd_enable(){
  local domain=${1:-} src cert key acme_url acme_root tls_value project net subnet code
  [[ -n $domain ]] || usage_die "enable needs a domain. Usage: scripts/tls-proxy.sh enable <domain> [auto|internal|acme <directory-url> <root.pem>|<cert.pem> <key.pem>]"
  valid_domain "$domain" || usage_die "Domain '${domain}' is not valid. Use letters, digits, dots and hyphens, with at least one dot."
  shift
  if [[ ${1:-} == acme ]]; then
    [[ $# -eq 3 ]] || usage_die "acme needs the directory URL and the root certificate file. Usage: scripts/tls-proxy.sh enable <domain> acme <directory-url> <root.pem>"
    src=acme; acme_url=$2; acme_root=$3
    valid_acme_url "$acme_url" \
      || usage_die "The ACME directory URL must be one https URL with no space, quote or brace. Got '${acme_url}'."
    check_acme_root "$acme_root"
  else
    case $# in
      0) src=auto ;;
      1) src=$1
         [[ $src == auto || $src == internal ]] \
           || usage_die "Source must be auto, internal, acme, or a certificate file and a key file. Got '${src}'." ;;
      2) src=files; cert=$1; key=$2
         [[ -r $cert ]] || usage_die "Certificate file not found: ${cert}"
         [[ -r $key ]]  || usage_die "Key file not found: ${key}" ;;
      *) usage_die "Too many arguments. Usage: scripts/tls-proxy.sh enable <domain> [auto|internal|acme <directory-url> <root.pem>|<cert.pem> <key.pem>]" ;;
    esac
  fi
  [[ -f .env ]] || die ".env not found. Run ./setup.sh first, or copy .env.example to .env."
  # The main stack bind-mounts the two files. Without them Docker creates two
  # directories with those names, and a later disable fails on them.
  [[ -f certs/cert.pem && -f certs/key.pem ]] \
    || die "certs/cert.pem and certs/key.pem are missing. Run ./setup.sh, or create a self-signed pair: openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=soc-ai -keyout certs/key.pem -out certs/cert.pem"

  case $src in
    auto)     tls_value="" ;;
    internal) tls_value="tls internal" ;;
    files)    tls_value="tls /certs/proxy-cert.pem /certs/proxy-key.pem" ;;
    acme)     tls_value="${ACME_SNIPPET} ${acme_url} /${ACME_ROOT_FILE}" ;;
  esac
  project=$(project_name); net="${project}_default"

  echo
  info "${B}The proxy path: Caddy serves https://${domain}/ with a certificate from $(source_label "$tls_value").${N}"
  info ".env changes:"
  echo "    SOC_AI_TLS_CERT="
  echo "    SOC_AI_TLS_KEY="
  echo "    SOC_AI_BIND=127.0.0.1"
  echo "    SOC_AI_DOMAIN=${domain}"
  echo "    SOC_AI_CADDY_TLS=${tls_value}"
  echo "    COMPOSE_PROFILES=proxy"
  if [[ $DRY -eq 1 ]]; then
    echo "    PROXY_TRUSTED_IPS=<the subnet of the ${net} network>"
    info "Commands:"
    [[ $src == files ]] && echo "    cp ${cert} certs/proxy-cert.pem && cp ${key} certs/proxy-key.pem"
    [[ $src == files ]] && echo "    docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile   # when Caddy already runs"
    [[ $src == acme ]] && echo "    cp ${acme_root} ${ACME_ROOT_FILE}"
    echo "    cp .env .env.bak-<stamp>"
    echo "    docker network inspect ${net} -f '{{(index .IPAM.Config 0).Subnet}}'   # after docker compose up --no-start when the network is absent"
    echo "    docker compose up -d"
    if [[ $src == files ]]; then
      echo "    curl -sk --resolve ${domain}:443:127.0.0.1 https://${domain}/healthz   # until it answers"
    else
      echo "    docker compose logs caddy   # until it says: certificate obtained"
    fi
    [[ $src == internal ]] && echo "    docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt"
    [[ $src == acme ]] && echo "    curl --cacert ${ACME_ROOT_FILE} --resolve ${domain}:443:127.0.0.1 https://${domain}/healthz   # the chain check"
    ok "Dry run. Nothing changed."
    return 0
  fi

  pick_docker
  backup_env
  if [[ $src == files ]]; then
    mkdir -p certs
    cp "$cert" certs/proxy-cert.pem; chmod 0644 certs/proxy-cert.pem
    cp "$key"  certs/proxy-key.pem;  chmod 0640 certs/proxy-key.pem
    ok "Copied the certificate and the key into ./certs/ as proxy-cert.pem (0644) and proxy-key.pem (0640)."
  fi
  if [[ $src == acme ]]; then
    mkdir -p certs
    cp "$acme_root" "$ACME_ROOT_FILE"; chmod 0644 "$ACME_ROOT_FILE"
    ok "Copied the ACME CA root into ./${ACME_ROOT_FILE} (0644)."
  fi
  env_set SOC_AI_TLS_CERT ""
  env_set SOC_AI_TLS_KEY ""
  env_set SOC_AI_BIND 127.0.0.1
  env_set SOC_AI_DOMAIN "$domain"
  env_set SOC_AI_CADDY_TLS "$tls_value"
  profile_add proxy
  ok "Wrote the proxy settings to .env."

  # soc-ai trusts the forwarded headers from the compose network. The subnet
  # comes from the network itself, so it matches every address pool.
  subnet=$(network_subnet "$net" || true)
  if [[ -z $subnet ]]; then
    info "The ${net} network does not exist yet. Creating it."
    "${DOCKER[@]}" compose up --no-start >/dev/null 2>&1 || true
    subnet=$(network_subnet "$net" || true)
  fi
  if [[ -z $subnet ]]; then
    subnet=172.16.0.0/12
    warn "Could not read the subnet of ${net}. Wrote Docker's default pool. Confirm with: docker network inspect ${net}"
  fi
  env_set PROXY_TRUSTED_IPS "$subnet"
  ok "PROXY_TRUSTED_IPS=${subnet} (the ${net} network)"

  # Caddy reads certificate files at start and on a reload. A re-run with
  # renewed files on a running proxy needs the reload, because `up -d` does
  # not restart a container whose configuration did not change.
  local caddy_was_running=""
  caddy_was_running=$("${DOCKER[@]}" compose ps -q caddy 2>/dev/null | head -1 || true)
  info "Starting the stack. soc-ai moves to plain HTTP on the loopback. Caddy starts through the proxy profile."
  "${DOCKER[@]}" compose up -d
  if [[ $src == files && -n $caddy_was_running ]]; then
    if "${DOCKER[@]}" compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
      ok "Caddy reloaded the certificate files."
    else
      warn "Caddy did not reload. Run: docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile"
    fi
  fi

  local i found=0
  if [[ $src == files ]]; then
    info "Waiting for Caddy to answer on https://${domain}/ ..."
    for ((i = 0; i < TRIES; i++)); do
      code=$(health_code --resolve "${domain}:443:127.0.0.1" "https://${domain}/healthz")
      [[ $code == 200 ]] && { found=1; break; }
      sleep "$POLL"
    done
    [[ $found -eq 1 ]] || warn "Caddy did not answer within 120 s. Read: docker compose logs caddy"
  else
    info "Waiting for Caddy to obtain the certificate ..."
    for ((i = 0; i < TRIES; i++)); do
      if "${DOCKER[@]}" compose logs --no-color caddy 2>&1 | grep -q "certificate obtained"; then found=1; break; fi
      sleep "$POLL"
    done
    [[ $found -eq 1 ]] || warn "Caddy did not report a certificate within 120 s. Read: docker compose logs caddy"
  fi
  # soc-ai restarts behind Caddy and answers after its own start period, so
  # the first probe can meet a 502 from Caddy. Poll until it answers.
  info "Waiting for soc-ai to answer through Caddy ..."
  code=000
  for ((i = 0; i < TRIES; i++)); do
    code=$(health_code --resolve "${domain}:443:127.0.0.1" "https://${domain}/healthz")
    [[ $code == 200 ]] && break
    sleep "$POLL"
  done
  if [[ $code == 200 ]]; then ok "Health check: HTTP ${code} from https://${domain}/healthz"
  else warn "Health check: HTTP ${code} from https://${domain}/healthz. Read: docker compose logs caddy soc-ai"; fi

  # The health check skips the certificate check. For ACME, check that the
  # served chain ends at the root the operator gave.
  if [[ $src == acme ]]; then
    code=$(curl -s -m 5 --cacert "$ACME_ROOT_FILE" --resolve "${domain}:443:127.0.0.1" \
      "https://${domain}/healthz" -o /dev/null -w '%{http_code}' 2>/dev/null || echo 000)
    if [[ $code == 200 ]]; then ok "Chain check: the certificate for ${domain} chains to ./${ACME_ROOT_FILE}."
    else warn "Chain check failed: the served certificate does not chain to ./${ACME_ROOT_FILE}. Read: docker compose logs caddy"; fi
    info "Caddy renews the certificate from ${acme_url}. Clients need the same root in their trust store."
  fi

  if [[ $src == internal ]]; then
    if "${DOCKER[@]}" compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt; then
      [[ ${DOCKER[0]} == sudo ]] && sudo chown "$(id -u):$(id -g)" ./caddy-root.crt
      chmod 0644 ./caddy-root.crt
      ok "Exported the Caddy root certificate to ./caddy-root.crt"
      print_trust_steps
    else
      warn "Could not copy the root certificate. Try again: docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt"
    fi
  fi

  echo
  ok "${B}soc-ai is behind Caddy.${N}"
  echo "    URL:      ${C}https://${domain}/${N}"
  echo "    Source:   $(source_label "$tls_value")"
  echo "    Settings: SOC_AI_TLS_CERT= SOC_AI_TLS_KEY= SOC_AI_BIND=127.0.0.1 SOC_AI_DOMAIN=${domain} SOC_AI_CADDY_TLS=${tls_value} COMPOSE_PROFILES=proxy PROXY_TRUSTED_IPS=${subnet}"
  echo "    Backup:   ${BACKUP}"
  echo "    Run scripts/tls-proxy.sh disable to go back to the direct path."
}

# ── disable ───────────────────────────────────────────────────────────────────
cmd_disable(){
  local port code
  [[ -f .env ]] || die ".env not found. Nothing to disable."
  port=$(env_get SOC_AI_PORT); port=${port:-8443}
  echo
  info "${B}The direct path: soc-ai terminates TLS on port ${port}.${N}"
  info ".env changes:"
  echo "    SOC_AI_TLS_CERT=/etc/soc-ai/cert.pem"
  echo "    SOC_AI_TLS_KEY=/etc/soc-ai/key.pem"
  echo "    remove SOC_AI_BIND, SOC_AI_DOMAIN, SOC_AI_CADDY_TLS, COMPOSE_PROFILES, PROXY_TRUSTED_IPS"
  if [[ $DRY -eq 1 ]]; then
    info "Commands:"
    echo "    cp .env .env.bak-<stamp>"
    echo "    docker compose --profile proxy stop caddy"
    echo "    docker compose --profile proxy rm -f caddy"
    echo "    docker compose up -d"
    echo "    curl -ksf https://127.0.0.1:${port}/healthz"
    ok "Dry run. Nothing changed."
    return 0
  fi
  pick_docker
  backup_env
  env_set SOC_AI_TLS_CERT /etc/soc-ai/cert.pem
  env_set SOC_AI_TLS_KEY /etc/soc-ai/key.pem
  env_unset SOC_AI_BIND
  env_unset SOC_AI_DOMAIN
  env_unset SOC_AI_CADDY_TLS
  profile_remove proxy
  env_unset PROXY_TRUSTED_IPS
  ok "Wrote the direct path settings to .env."
  info "Stopping and removing Caddy."
  "${DOCKER[@]}" compose --profile proxy stop caddy || true
  "${DOCKER[@]}" compose --profile proxy rm -f caddy || true
  info "Starting soc-ai with TLS on port ${port}."
  "${DOCKER[@]}" compose up -d
  local i found=0
  for ((i = 0; i < TRIES; i++)); do
    code=$(health_code "https://127.0.0.1:${port}/healthz")
    [[ $code == 200 ]] && { found=1; break; }
    sleep "$POLL"
  done
  if [[ $found -eq 1 ]]; then ok "Health check: HTTP ${code} from https://127.0.0.1:${port}/healthz"
  else warn "Health check: HTTP ${code} from https://127.0.0.1:${port}/healthz. Read: docker compose logs soc-ai"; fi
  echo
  ok "${B}soc-ai terminates TLS itself.${N}"
  echo "    URL:      ${C}https://<this host>:${port}/${N}"
  echo "    Backup:   ${BACKUP}"
  echo "    Caddy's data volume stays, with its CA. Remove it with: docker volume rm $(project_name)_caddy_data"
}

# ── status ────────────────────────────────────────────────────────────────────
cmd_status(){
  local domain profiles tls_value port code
  [[ -f .env ]] || die ".env not found."
  domain=$(env_get SOC_AI_DOMAIN); profiles=$(env_get COMPOSE_PROFILES); tls_value=$(env_get SOC_AI_CADDY_TLS)
  port=$(env_get SOC_AI_PORT); port=${port:-8443}
  if [[ $profiles == *proxy* && -n $domain ]]; then
    echo "Mode:    proxy (Caddy in front of soc-ai)"
    echo "Domain:  ${domain}"
    echo "Source:  $(source_label "$tls_value")"
    echo "Trusted: $(env_get PROXY_TRUSTED_IPS)"
    code=$(health_code --resolve "${domain}:443:127.0.0.1" "https://${domain}/healthz")
    echo "Health:  HTTP ${code} from https://${domain}/healthz"
  else
    echo "Mode:    direct (soc-ai terminates TLS on port ${port})"
    echo "Cert:    $(env_get SOC_AI_TLS_CERT)"
    code=$(health_code "https://127.0.0.1:${port}/healthz")
    echo "Health:  HTTP ${code} from https://127.0.0.1:${port}/healthz"
  fi
  [[ $code == 200 ]]
}

# ── main ──────────────────────────────────────────────────────────────────────
DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-n) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done
VERB=${1:-}
[[ -n $VERB ]] || { usage; exit 2; }
shift
case "$VERB" in
  enable)  cmd_enable "$@" ;;
  disable) [[ $# -eq 0 ]] || usage_die "disable takes no argument."; cmd_disable ;;
  status)  [[ $# -eq 0 ]] || usage_die "status takes no argument."; cmd_status ;;
  *) usage_die "Unknown command '${VERB}'. Use enable, disable or status. Run with --help for the usage." ;;
esac
