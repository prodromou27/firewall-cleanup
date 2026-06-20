#!/usr/bin/env bash
#
# Install the PolicyInsight unattended self-update timer on this host.
# After this, pushing to the host's branch (dev_red on the DEV box, PROD on the
# PROD box) auto-deploys within the poll interval — no inbound access needed,
# so it works on private LANs where GitHub runners can't reach the host.
#
# Usage (from the repo root):
#   sudo bash deploy/install-autoupdate.sh
#   sudo bash deploy/install-autoupdate.sh --uninstall
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
UNIT_DIR="/etc/systemd/system"

log()  { printf '\033[1;32m[autoupdate]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Run with sudo/root."

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now policyinsight-update.timer 2>/dev/null || true
  rm -f "$UNIT_DIR/policyinsight-update.timer" "$UNIT_DIR/policyinsight-update.service"
  systemctl daemon-reload
  log "Removed self-update timer."
  exit 0
fi

[ -f "$REPO_DIR/deploy/update.sh" ] || die "Run from the cloned repo (deploy/update.sh missing)."

# Let root operate the repo regardless of who owns it.
git config --system --add safe.directory "$REPO_DIR" 2>/dev/null || true

log "Installing systemd units (repo: $REPO_DIR)…"
sed "s#__REPO_DIR__#${REPO_DIR}#g" "$SCRIPT_DIR/systemd/policyinsight-update.service" > "$UNIT_DIR/policyinsight-update.service"
cp "$SCRIPT_DIR/systemd/policyinsight-update.timer" "$UNIT_DIR/policyinsight-update.timer"

systemctl daemon-reload
systemctl enable --now policyinsight-update.timer

log "Done. The host now polls its branch every ~2 min and redeploys on change."
log "  Status:  systemctl status policyinsight-update.timer"
log "  Logs:    journalctl -u policyinsight-update.service -f"
log "  Run now: systemctl start policyinsight-update.service"
