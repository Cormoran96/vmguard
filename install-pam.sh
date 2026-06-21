#!/usr/bin/env bash
#
# install-pam.sh — add (or remove) fingerprint user-verification via pam-u2f
# to a PAM service, with an automatic timestamped backup.
#
# The VeriMark Guard is a FIDO2 key: pam_u2f gates auth on it, and the
# enrolled fingerprint satisfies user-verification. The pam_u2f line is added
# as `sufficient` BEFORE the existing auth rules, so a successful touch lets
# you in while a missing/failed key falls through to your normal password.
# You cannot lock yourself out of password auth this way.
#
# Usage:
#   sudo ./install-pam.sh [SERVICE] [--authfile PATH]   # default SERVICE: sudo
#   sudo ./install-pam.sh --revert [SERVICE]
#
# Examples:
#   sudo ./install-pam.sh                # protect `sudo` (test here first!)
#   sudo ./install-pam.sh --revert sudo  # restore newest backup for `sudo`
#   # graphical login with an ENCRYPTED home (~/.config not yet mounted at the
#   # GDM prompt) — use a system-wide authfile outside $HOME:
#   sudo cp ~/.config/Yubico/u2f_keys /etc/u2f_mappings && sudo chmod 644 /etc/u2f_mappings
#   sudo ./install-pam.sh gdm-password --authfile /etc/u2f_mappings
#
# SAFETY: keep a separate root shell open (`sudo -s`) while testing, so you can
# revert if anything misbehaves.

set -euo pipefail

PAM_DIR=/etc/pam.d
MODULE=/usr/lib/x86_64-linux-gnu/security/pam_u2f.so

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# --- parse args ---------------------------------------------------------------
REVERT=0
SERVICE=sudo
AUTHFILE=""          # system-wide authfile, for services that run before $HOME
                     # is available (e.g. GDM with an encrypted home directory).
while [ $# -gt 0 ]; do
  case "$1" in
    --revert)       REVERT=1 ;;
    --authfile)     shift; [ $# -gt 0 ] || die "--authfile needs a path"; AUTHFILE="$1" ;;
    --authfile=*)   AUTHFILE="${1#*=}" ;;
    -*)             die "unknown option: $1" ;;
    *)              SERVICE="$1" ;;
  esac
  shift
done
TARGET="$PAM_DIR/$SERVICE"

# Build the auth rule. With --authfile, pam_u2f reads the named system file
# (the credential id / public key it contains are not secret) instead of the
# per-user ~/.config/Yubico/u2f_keys.
u2f_opts="pam_u2f.so"
[ -n "$AUTHFILE" ] && u2f_opts="$u2f_opts authfile=$AUTHFILE"
u2f_opts="$u2f_opts userverification=1 cue [cue_prompt=Touch the VeriMark sensor]"
PAM_LINE="auth  sufficient  $u2f_opts"

# --- preconditions ------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run with sudo (need to edit $PAM_DIR)."
[ -f "$TARGET" ]     || die "PAM service file not found: $TARGET"

# --- revert mode --------------------------------------------------------------
if [ "$REVERT" -eq 1 ]; then
  backup=$(ls -1t "$TARGET".u2f-bak.* 2>/dev/null | head -1 || true)
  [ -n "$backup" ] || die "no backup found for $SERVICE (looked for $TARGET.u2f-bak.*)"
  info "Restoring $backup -> $TARGET"
  cp -a -- "$backup" "$TARGET"
  info "Reverted. Current auth lines:"
  grep -nE 'pam_u2f\.so|^(auth[[:space:]]|@include[[:space:]]+common-auth)' "$TARGET" || true
  exit 0
fi

# --- install mode -------------------------------------------------------------
[ -f "$MODULE" ] || die "pam_u2f.so not found at $MODULE — install libpam-u2f."

# Warn (don't block) if no credential mapping exists yet.
if [ -n "$AUTHFILE" ]; then
  check_file="$AUTHFILE"
  reg_hint="create it as root, e.g.:  sudo cp ~/.config/Yubico/u2f_keys $AUTHFILE && sudo chmod 644 $AUTHFILE"
else
  real_user="${SUDO_USER:-$USER}"
  real_home=$(getent passwd "$real_user" | cut -d: -f6)
  check_file="$real_home/.config/Yubico/u2f_keys"
  reg_hint="register first as $real_user:  mkdir -p ~/.config/Yubico && pamu2fcfg -V > ~/.config/Yubico/u2f_keys"
fi
if [ ! -s "$check_file" ]; then
  echo "warning: $check_file is missing or empty." >&2
  echo "         $reg_hint" >&2
  read -r -p "Continue anyway? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || die "aborted; create the credential mapping first."
fi

# Idempotency: bail if a pam_u2f rule is already present.
if grep -qE '^[^#]*pam_u2f\.so' "$TARGET"; then
  info "pam_u2f is already configured in $TARGET — nothing to do."
  grep -nE 'pam_u2f\.so' "$TARGET"
  exit 0
fi

# Backup.
stamp=$(date +%Y%m%d-%H%M%S)
backup="$TARGET.u2f-bak.$stamp"
cp -a -- "$TARGET" "$backup"
info "Backed up $TARGET -> $backup"

# Where to insert: prefer immediately before `@include common-auth` (the distro
# password stack). That way any auth preamble a service runs first — e.g.
# pam_nologin / pam_faildelay in /etc/pam.d/login — still executes before our
# rule. Fall back to the first literal `auth` line, then to prepending.
if grep -qE '@include[[:space:]]+common-auth' "$TARGET"; then
  anchor='@include[[:space:]]+common-auth'
elif grep -qE '^auth[[:space:]]' "$TARGET"; then
  anchor='^auth[[:space:]]'
else
  anchor=''
fi
tmp=$(mktemp)
if [ -n "$anchor" ]; then
  awk -v line="$PAM_LINE" -v anchor="$anchor" '
    !done && $0 ~ anchor { print line; done=1 }
    { print }
  ' "$TARGET" > "$tmp"
else
  { printf '%s\n' "$PAM_LINE"; cat "$TARGET"; } > "$tmp"
fi
cat -- "$tmp" > "$TARGET"
rm -f -- "$tmp"

info "Added pam_u2f to $TARGET. Auth section is now:"
grep -nE 'pam_u2f\.so|^auth[[:space:]]|@include[[:space:]]+common-auth' "$TARGET"

cat <<EOF

Next:
  1. Keep THIS root shell open as a safety net.
  2. In a NEW terminal, test:   sudo -k && sudo true
     The key should blink — touch your enrolled finger.
  3. If anything is wrong, revert:   sudo $0 --revert $SERVICE
EOF
