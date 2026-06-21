#!/usr/bin/env bash
#
# install-pam.sh — interactive setup wizard for fingerprint login on Linux with
# the Kensington VeriMark Guard (a FIDO2 match-on-chip key), via pam-u2f.
#
# Run it as your normal user (NOT with sudo); it escalates with `sudo` only for
# the steps that edit /etc/pam.d. It walks you through, in order:
#
#   1. locating (or building) the `vmguard` binary
#   2. checking pam_u2f / pamu2fcfg are installed
#   3. confirming the key is plugged in
#   4. setting a device PIN (if not set)
#   5. enrolling a fingerprint (if none)
#   6. registering the key's credential for PAM (pamu2fcfg)
#   7. handling an encrypted home (system-wide authfile)
#   8. enabling the PAM services you choose, each with a timestamped backup
#
# Every pam_u2f line is added as `sufficient` BEFORE the existing auth rules, so
# a successful touch logs you in while a missing/failed key falls through to your
# normal password. You cannot lock yourself out of password auth this way.
#
# Usage:
#   ./install-pam.sh                 # run the wizard
#   ./install-pam.sh --revert [SVC]  # restore newest backup for a service
#   ./install-pam.sh --help
#
# SAFETY: keep a separate root shell open (`sudo -s`) while testing, so you can
# revert if anything misbehaves.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PAM_DIR=/etc/pam.d
AUTHFILE_SYS=/etc/u2f_mappings
USER_AUTHFILE="$HOME/.config/Yubico/u2f_keys"
CUE_PROMPT="Touch the VeriMark sensor"

# Services the wizard can offer, with a human label and whether they run before
# $HOME is mounted (i.e. need a system-wide authfile on an encrypted home).
SERVICES=(sudo sudo-i gdm-password login)
declare -A SVC_LABEL=(
  [sudo]="sudo / sudo -s"
  [sudo-i]="sudo -i (login shell)"
  [gdm-password]="Graphical login (GNOME/GDM)"
  [login]="Console login (TTY)"
)
declare -A SVC_PREHOME=(
  [sudo]=0 [sudo-i]=0 [gdm-password]=1 [login]=1
)

# --- pretty output ------------------------------------------------------------
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD=$(tput bold); DIM=$(tput dim); RED=$(tput setaf 1); GRN=$(tput setaf 2)
  YLW=$(tput setaf 3); BLU=$(tput setaf 4); RST=$(tput sgr0)
else
  BOLD=""; DIM=""; RED=""; GRN=""; YLW=""; BLU=""; RST=""
fi

die()  { echo "${RED}error:${RST} $*" >&2; exit 1; }
warn() { echo "${YLW}warning:${RST} $*" >&2; }
ok()   { echo "  ${GRN}✓${RST} $*"; }
step() { echo; echo "${BOLD}${BLU}==>${RST} ${BOLD}$*${RST}"; }
note() { echo "  ${DIM}$*${RST}"; }

ask_yn() {  # ask_yn "question" [default Y|N]
  local q="$1" def="${2:-N}" ans prompt
  if [ "$def" = Y ]; then prompt="[Y/n]"; else prompt="[y/N]"; fi
  read -r -p "$q $prompt " ans || ans=""
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy] ]]
}

# Run a command as root, using sudo only when we are not already root.
run_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

# --- discovery ----------------------------------------------------------------
find_vmguard() {
  if command -v vmguard >/dev/null 2>&1; then command -v vmguard; return 0; fi
  if [ -x "$SCRIPT_DIR/target/release/vmguard" ]; then echo "$SCRIPT_DIR/target/release/vmguard"; return 0; fi
  if [ -x "$SCRIPT_DIR/target/debug/vmguard" ]; then echo "$SCRIPT_DIR/target/debug/vmguard"; return 0; fi
  return 1
}

find_module() {
  local p
  for p in /usr/lib/*/security/pam_u2f.so /lib/*/security/pam_u2f.so /usr/lib/security/pam_u2f.so; do
    [ -f "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

# --- PAM editing (used by wizard and --revert) --------------------------------
build_pam_line() {  # build_pam_line [authfile]
  local authfile="${1:-}" opts="pam_u2f.so"
  [ -n "$authfile" ] && opts="$opts authfile=$authfile"
  opts="$opts userverification=1 cue [cue_prompt=$CUE_PROMPT]"
  echo "auth  sufficient  $opts"
}

install_service() {  # install_service SERVICE [authfile]
  local service="$1" authfile="${2:-}"
  local target="$PAM_DIR/$service"
  if [ ! -f "$target" ]; then
    warn "no PAM service file at $target — skipping '$service'."
    return 1
  fi
  if run_root grep -qE '^[^#]*pam_u2f\.so' "$target"; then
    ok "$service already has a pam_u2f rule — nothing to do."
    return 0
  fi

  local stamp backup; stamp=$(date +%Y%m%d-%H%M%S); backup="$target.u2f-bak.$stamp"
  run_root cp -a -- "$target" "$backup"
  note "backed up $target -> $backup"

  # Insert just before `@include common-auth` (the distro password stack) so any
  # preamble a service runs first (pam_nologin, pam_faildelay) still executes.
  # Fall back to the first literal `auth` line, then to prepending.
  local anchor=""
  if grep -qE '@include[[:space:]]+common-auth' "$target"; then
    anchor='@include[[:space:]]+common-auth'
  elif grep -qE '^auth[[:space:]]' "$target"; then
    anchor='^auth[[:space:]]'
  fi

  local line tmp; line=$(build_pam_line "$authfile"); tmp=$(mktemp)
  if [ -n "$anchor" ]; then
    awk -v line="$line" -v anchor="$anchor" '
      !done && $0 ~ anchor { print line; done=1 }
      { print }
    ' "$target" > "$tmp"
  else
    { printf '%s\n' "$line"; cat "$target"; } > "$tmp"
  fi
  # tee truncates+writes but keeps the file's existing mode/owner.
  run_root tee "$target" < "$tmp" >/dev/null
  rm -f -- "$tmp"
  ok "enabled fingerprint auth for ${BOLD}$service${RST}."
}

revert_service() {  # revert_service SERVICE
  local service="$1" backup
  local target="$PAM_DIR/$service"
  [ -f "$target" ] || die "PAM service file not found: $target"
  backup=$(run_root bash -c "ls -1t '$target'.u2f-bak.* 2>/dev/null | head -1" || true)
  [ -n "$backup" ] || die "no backup found for '$service' (looked for $target.u2f-bak.*)"
  run_root cp -a -- "$backup" "$target"
  ok "restored $backup -> $target"
  run_root grep -nE 'pam_u2f\.so|^auth[[:space:]]|@include[[:space:]]+common-auth' "$target" || true
}

# --- argument handling --------------------------------------------------------
case "${1:-}" in
  -h|--help)
    # Print the leading comment block (skip the shebang, stop at the first
    # non-comment line), stripping the leading "# ".
    awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
    exit 0 ;;
  --revert)
    [ "$(id -u)" -eq 0 ] && die "run --revert as your normal user; it will sudo when needed."
    svc="${2:-}"
    if [ -z "$svc" ]; then
      echo "Which service do you want to revert?"
      select s in "${SERVICES[@]}"; do svc="$s"; [ -n "$svc" ] && break; done
    fi
    revert_service "$svc"
    exit 0 ;;
  "") : ;;  # fall through to wizard
  *) die "unknown argument: $1 (try --help)" ;;
esac

# =============================================================================
# Wizard
# =============================================================================
[ "$(id -u)" -eq 0 ] && die "run the wizard as your normal user (not sudo); it asks for sudo only when editing /etc/pam.d."

echo "${BOLD}VeriMark Guard — fingerprint login setup${RST}"
note "This wizard sets up your fingerprint key for Linux login via pam-u2f."
note "Keep a separate ${BOLD}root shell open (sudo -s)${RST} while testing, as a safety net."

# --- 1. vmguard ---------------------------------------------------------------
step "Locating the vmguard tool"
if VMGUARD=$(find_vmguard); then
  ok "found: $VMGUARD"
else
  warn "vmguard binary not found (not on PATH, not in target/release)."
  if command -v cargo >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
    if ask_yn "Build it now with 'cargo build --release'?" Y; then
      ( cd "$SCRIPT_DIR" && cargo build --release )
      VMGUARD=$(find_vmguard) || die "build finished but vmguard still not found."
      ok "built: $VMGUARD"
    else
      die "build vmguard first (cargo build --release), then re-run."
    fi
  else
    die "cargo not available — build vmguard manually, then re-run."
  fi
fi

# --- 2. pam_u2f / pamu2fcfg ---------------------------------------------------
step "Checking pam-u2f is installed"
if MODULE=$(find_module); then
  ok "pam_u2f.so: $MODULE"
else
  die "pam_u2f.so not found. Install it, e.g.:  sudo apt install libpam-u2f"
fi
if command -v pamu2fcfg >/dev/null 2>&1; then
  ok "pamu2fcfg: $(command -v pamu2fcfg)"
else
  die "pamu2fcfg not found. Install it, e.g.:  sudo apt install libpam-u2f"
fi

# --- 3. device present --------------------------------------------------------
step "Checking the key is plugged in"
while ! "$VMGUARD" info >/dev/null 2>&1; do
  warn "VeriMark Guard not detected."
  ask_yn "Plug it in and retry?" Y || die "no device — aborting."
done
ok "key detected."
note "running 'vmguard wink' — the key's LED should blink."
"$VMGUARD" wink >/dev/null 2>&1 || true

info_out=$("$VMGUARD" info 2>/dev/null || true)
pin_set()      { grep -qiE '^[[:space:]]*clientPin[[:space:]]*:[[:space:]]*yes'  <<<"$info_out"; }
bio_enrolled() { grep -qiE '^[[:space:]]*bioEnroll[[:space:]]*:[[:space:]]*yes' <<<"$info_out"; }

# --- 4. PIN -------------------------------------------------------------------
step "Device PIN"
if pin_set; then
  ok "a PIN is already set on the key."
else
  note "A PIN is required before you can enroll fingerprints."
  if ask_yn "Set a device PIN now?" Y; then
    "$VMGUARD" set-pin
    info_out=$("$VMGUARD" info 2>/dev/null || true)
    ok "PIN set."
  else
    die "a PIN is required to continue — re-run when ready."
  fi
fi

# --- 5. enroll ----------------------------------------------------------------
step "Fingerprint enrollment"
if bio_enrolled; then
  ok "the key already has at least one enrolled fingerprint."
  if ask_yn "Enroll another finger?" N; then
    read -r -p "  Name for this finger [finger]: " fname; fname="${fname:-finger}"
    "$VMGUARD" bio-enroll --name "$fname"
  fi
else
  note "Touch the sensor repeatedly (~7x) when prompted."
  read -r -p "  Name for this finger [right-index]: " fname; fname="${fname:-right-index}"
  "$VMGUARD" bio-enroll --name "$fname"
  ok "fingerprint enrolled."
fi

# --- 6. register credential for PAM ------------------------------------------
step "Registering the key for PAM (pamu2fcfg)"
if [ -s "$USER_AUTHFILE" ]; then
  ok "credential mapping already exists: $USER_AUTHFILE"
  ask_yn "Register an additional credential (append)?" N && \
    { mkdir -p "$(dirname "$USER_AUTHFILE")"; pamu2fcfg -V >> "$USER_AUTHFILE"; ok "appended."; }
else
  note "Touch your enrolled finger when the key blinks."
  mkdir -p "$(dirname "$USER_AUTHFILE")"
  pamu2fcfg -V > "$USER_AUTHFILE"
  [ -s "$USER_AUTHFILE" ] || { rm -f "$USER_AUTHFILE"; die "registration produced no credential."; }
  ok "credential saved to $USER_AUTHFILE"
fi

# --- 7. encrypted home / authfile --------------------------------------------
step "Encrypted home directory?"
note "GDM and console login run BEFORE your \$HOME is mounted, so they can't read"
note "$USER_AUTHFILE. If your home is encrypted, we copy the (non-secret)"
note "credential to a system-wide file: $AUTHFILE_SYS."
ENCRYPTED_HOME=0
if ask_yn "Is your home directory encrypted (or do you want graphical/TTY login support)?" N; then
  ENCRYPTED_HOME=1
  run_root cp "$USER_AUTHFILE" "$AUTHFILE_SYS"
  run_root chmod 644 "$AUTHFILE_SYS"
  ok "system-wide authfile written: $AUTHFILE_SYS"
fi

# --- 8. choose & enable services ---------------------------------------------
step "Which logins should use your fingerprint?"
note "Each is added as 'sufficient' — your password always still works."
echo
chosen=()
for svc in "${SERVICES[@]}"; do
  [ -f "$PAM_DIR/$svc" ] || continue
  default=N; [ "$svc" = sudo ] && default=Y
  if ask_yn "  Enable ${BOLD}${SVC_LABEL[$svc]}${RST}  (${svc})?" "$default"; then
    chosen+=("$svc")
  fi
done

[ "${#chosen[@]}" -gt 0 ] || { warn "no services selected — nothing to install."; exit 0; }

# pre-home services need an authfile; if the user didn't set one up, use per-user
# and warn (works for unencrypted homes only).
for svc in "${chosen[@]}"; do
  af=""
  if [ "${SVC_PREHOME[$svc]}" = 1 ]; then
    if [ "$ENCRYPTED_HOME" = 1 ]; then
      af="$AUTHFILE_SYS"
    else
      warn "$svc runs before \$HOME mounts; using per-user authfile. If your home"
      warn "  is encrypted this will fail at the login screen — re-run and answer"
      warn "  'yes' to the encrypted-home question."
    fi
  fi
  step "Enabling $svc"
  install_service "$svc" "$af" || true
done

# --- done ---------------------------------------------------------------------
step "Done — test before you trust it"
cat <<EOF

  ${BOLD}Keep your root shell open${RST}, then in a NEW session test each service:

EOF
for svc in "${chosen[@]}"; do
  case "$svc" in
    sudo)         echo "    $svc          → ${DIM}sudo -k && sudo true${RST}  (key blinks; touch your finger)";;
    sudo-i)       echo "    $svc        → ${DIM}sudo -k && sudo -i${RST}";;
    gdm-password) echo "    $svc  → ${DIM}log out and back in${RST}";;
    login)        echo "    $svc         → ${DIM}switch to a TTY (Ctrl+Alt+F3)${RST}";;
  esac
done
cat <<EOF

  Revert any service if something's wrong:
    ${DIM}$0 --revert <service>${RST}

  If you later add/remove credentials with pamu2fcfg and use an encrypted home,
  refresh the system authfile:
    ${DIM}sudo cp $USER_AUTHFILE $AUTHFILE_SYS${RST}
EOF
