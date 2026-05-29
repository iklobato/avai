#!/usr/bin/env bash
#
# tests/local.sh — unattended local test driver for phases 0-3 of the
# test plan in the README. Costs $0, needs no LLM or threat-intel keys.
#
# Usage:
#   tests/local.sh                    # run all four phases
#   tests/local.sh 0                  # just phase N (0, 1, 2, or 3)
#   tests/local.sh --help             # show this header
#
# Environment:
#   AVAI_IMAGE   image tag to test against (default: iklob1/avai:latest)
#                if absent locally, the script builds it from the repo.
#
# Phases:
#   0 — pytest in a fresh venv (22 unit tests)
#   1 — Docker CLI surface: --version, --help, --no-enrich present
#   2 — Cold smoke: monitor --once --no-judge --no-enrich --no-streaming
#   3 — Keyless enrichment smoke: registry gates 9 keyless / 9 keyed
#
# Exits non-zero on any failure (CI-friendly).

set -euo pipefail

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

AVAI_IMAGE="${AVAI_IMAGE:-iklob1/avai:latest}"
DATA_DIR="$(mktemp -d -t avai-localtest-XXXXXX)"
trap 'rm -rf "$DATA_DIR"' EXIT

# Colour if stdout is a TTY (skip codes in CI / piped runs).
if [[ -t 1 ]]; then
  G=$'\033[0;32m'; R=$'\033[0;31m'; Y=$'\033[0;33m'
  B=$'\033[1m';    X=$'\033[0m'
else
  G=''; R=''; Y=''; B=''; X=''
fi

pass_count=0
fail_count=0
skip_count=0

log()  { printf '\n%s%s%s\n' "$B"   "→ $*" "$X"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$X" "$*"; pass_count=$((pass_count + 1)); }
bad()  { printf '  %s✗%s %s\n' "$R" "$X" "$*"; fail_count=$((fail_count + 1)); }
skip() { printf '  %s…%s %s\n' "$Y" "$X" "$*"; skip_count=$((skip_count + 1)); }

# ---------------------------------------------------------------------------
# Prereqs
# ---------------------------------------------------------------------------

ensure_docker() {
  if ! command -v docker >/dev/null; then
    bad "docker not on PATH; cannot continue"
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    bad "docker daemon not reachable; start Docker Desktop and retry"
    exit 1
  fi
}

ensure_image() {
  if ! docker image inspect "$AVAI_IMAGE" >/dev/null 2>&1; then
    log "image $AVAI_IMAGE not present locally; building"
    docker build -t "$AVAI_IMAGE" "$REPO_ROOT"
  fi
}

# ---------------------------------------------------------------------------
# Phase 0 — pytest in a fresh venv
# ---------------------------------------------------------------------------

phase_0() {
  log "Phase 0 — unit tests (pytest in fresh venv)"

  if ! command -v python3 >/dev/null; then
    skip "Phase 0: python3 not on PATH"
    return 0
  fi

  local venv="$DATA_DIR/.venv"
  printf '  preparing venv + installing -e . pytest ...\n'
  python3 -m venv "$venv" >/dev/null
  "$venv/bin/pip" install --quiet --upgrade pip
  if ! "$venv/bin/pip" install --quiet -e . pytest >/dev/null 2>&1; then
    bad "Phase 0: pip install failed (likely sandbox without network)"
    return 0
  fi
  local out
  if out="$("$venv/bin/python" -m pytest tests/test_enrichers.py -x -q 2>&1)"; then
    local n
    n="$(grep -oE '[0-9]+ passed' <<< "$out" | head -1 || echo 'tests')"
    ok "Phase 0: pytest green ($n)"
  else
    bad "Phase 0: pytest failed — rerun with: $venv/bin/python -m pytest tests/test_enrichers.py -x -v"
  fi
}

# ---------------------------------------------------------------------------
# Phase 1 — Docker CLI surface
# ---------------------------------------------------------------------------

phase_1() {
  log "Phase 1 — CLI surface"

  # Capture each docker run's output once into a variable, then grep
  # against the var. Avoids piping into `grep -q`, which exits early
  # on the first match and broken-pipes the upstream `docker run`
  # (Python sees the closed FD, raises BrokenPipeError on flush at
  # exit, docker exits non-zero, pipefail trips the `if` even though
  # the match was found).
  local v help mhelp dhelp
  v="$(docker run --rm "$AVAI_IMAGE" avai --version 2>/dev/null || echo '?')"
  help="$(docker run --rm "$AVAI_IMAGE" avai --help 2>&1 || true)"
  mhelp="$(docker run --rm "$AVAI_IMAGE" avai monitor --help 2>&1 || true)"
  dhelp="$(docker run --rm "$AVAI_IMAGE" avai dashboard --help 2>&1 || true)"

  if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ok "Phase 1a: avai --version → $v"
  else
    bad "Phase 1a: avai --version returned '$v' (expected semver)"
  fi

  if [[ "$help" == *"avai monitor"* ]]; then
    ok "Phase 1b: avai --help mentions the monitor subcommand"
  else
    bad "Phase 1b: avai --help is missing the monitor subcommand"
  fi

  if [[ "$mhelp" == *"--no-enrich"* ]]; then
    ok "Phase 1c: avai monitor --help advertises --no-enrich"
  else
    bad "Phase 1c: --no-enrich flag missing from monitor --help"
  fi

  if [[ "$dhelp" == *"--host"* ]]; then
    ok "Phase 1d: avai dashboard --help advertises --host"
  else
    bad "Phase 1d: dashboard --help missing"
  fi
}

# ---------------------------------------------------------------------------
# Phase 2 — Cold smoke
# ---------------------------------------------------------------------------

phase_2() {
  log "Phase 2 — cold smoke (collectors only, no judge / enrich / streaming)"

  # Fresh DB for this phase only.
  rm -f "$DATA_DIR/avai.db" "$DATA_DIR/avai.db-wal" "$DATA_DIR/avai.db-shm"

  local out
  out="$(docker run --rm -v "$DATA_DIR:/data" "$AVAI_IMAGE" \
    avai monitor --once --no-streaming --no-judge --no-enrich \
    --db /data/avai.db 2>&1)" || true

  if grep -q 'run complete' <<< "$out" \
     && grep -qE 'ok=[1-9][0-9]* failed=0' <<< "$out"; then
    ok "Phase 2a: monitor cycle completed, no collector errors"
  else
    bad "Phase 2a: monitor cycle failed; tail follows:"
    tail -8 <<< "$out" | sed 's/^/    /'
  fi

  if grep -qE 'judged=[1-9]' <<< "$out"; then
    bad "Phase 2b: judged>0 reported with --no-judge — regression"
  else
    ok "Phase 2b: judged=0 everywhere (judge correctly disabled)"
  fi

  if grep -qE 'enriched=[1-9]' <<< "$out"; then
    bad "Phase 2c: enriched>0 reported with --no-enrich — regression"
  else
    ok "Phase 2c: enriched=0 everywhere (chain correctly disabled)"
  fi

  if [[ -s "$DATA_DIR/avai.db" ]]; then
    local size
    size="$(du -h "$DATA_DIR/avai.db" | awk '{print $1}')"
    ok "Phase 2d: DB file populated ($size)"
  else
    bad "Phase 2d: DB file is empty / missing"
  fi
}

# ---------------------------------------------------------------------------
# Phase 3 — Keyless enrichment smoke
# ---------------------------------------------------------------------------

phase_3() {
  log "Phase 3 — keyless enrichment smoke (no tokens set)"

  rm -f "$DATA_DIR/avai.db" "$DATA_DIR/avai.db-wal" "$DATA_DIR/avai.db-shm"

  # Force every keyed enricher's token to be empty so the registry
  # consistently disables them, regardless of the caller's shell.
  local env_args=()
  local v
  for v in ABUSE_CH_AUTH_KEY VT_API_KEY ABUSEIPDB_API_KEY GREYNOISE_API_KEY \
           GOOGLE_SAFE_BROWSING_API_KEY PHISHTANK_API_KEY GITHUB_TOKEN; do
    env_args+=("-e" "${v}=")
  done

  local out
  out="$(docker run --rm "${env_args[@]}" -v "$DATA_DIR:/data" "$AVAI_IMAGE" \
    avai monitor --once --no-streaming --no-judge \
    --db /data/avai.db 2>&1)" || true

  if grep -q 'run complete' <<< "$out"; then
    ok "Phase 3a: cycle completed with keyless enrichers active"
  else
    bad "Phase 3a: cycle failed; tail follows:"
    tail -10 <<< "$out" | sed 's/^/    /'
  fi

  local expected_keyless=(circl_hashlookup shodan_internetdb feodo_tracker
                          osv cisa_kev nvd endoflife crtsh ipwhois_geo)
  local missing=()
  local src
  for src in "${expected_keyless[@]}"; do
    grep -q "enricher enabled: $src" <<< "$out" || missing+=("$src")
  done
  if (( ${#missing[@]} == 0 )); then
    ok "Phase 3b: all 9 keyless enrichers reported enabled"
  else
    bad "Phase 3b: missing enrichers: ${missing[*]}"
  fi

  local gated=(malware_bazaar urlhaus threatfox virustotal abuseipdb
               greynoise safe_browsing phishtank github_advisory)
  local wrong=()
  for src in "${gated[@]}"; do
    grep -q "enricher enabled: $src" <<< "$out" && wrong+=("$src") || true
  done
  if (( ${#wrong[@]} == 0 )); then
    ok "Phase 3c: all 9 keyed enrichers disabled (tokens cleared)"
  else
    bad "Phase 3c: keyed enrichers wrongly active: ${wrong[*]}"
  fi

  local rows
  rows="$(docker run --rm -v "$DATA_DIR:/data" "$AVAI_IMAGE" python -c "
import sqlite3
c = sqlite3.connect('/data/avai.db')
print(c.execute('select count(*) from enrichment_evidence').fetchone()[0])
" 2>/dev/null || echo ERR)"

  if [[ "$rows" == "ERR" ]]; then
    bad "Phase 3d: enrichment_evidence table not queryable"
  else
    ok "Phase 3d: enrichment_evidence table OK (rows=$rows)"
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

show_help() {
  sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

run_all() {
  ensure_image
  phase_0
  phase_1
  phase_2
  phase_3
}

main() {
  case "${1:-all}" in
    all)             ensure_docker; run_all ;;
    0|phase0)        ensure_docker; ensure_image; phase_0 ;;
    1|phase1)        ensure_docker; ensure_image; phase_1 ;;
    2|phase2)        ensure_docker; ensure_image; phase_2 ;;
    3|phase3)        ensure_docker; ensure_image; phase_3 ;;
    -h|--help|help)  show_help; exit 0 ;;
    *)
      printf '%sunknown phase: %s%s\n' "$R" "$1" "$X" >&2
      printf 'try: %s --help\n' "$0" >&2
      exit 2
      ;;
  esac

  printf '\n%ssummary%s: %d passed, %d failed, %d skipped\n' \
    "$B" "$X" "$pass_count" "$fail_count" "$skip_count"

  (( fail_count == 0 ))
}

main "$@"
