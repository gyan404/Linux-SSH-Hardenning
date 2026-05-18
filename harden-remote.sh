#!/usr/bin/env bash
#
# harden-remote.sh — Drive secure-vps.sh on a remote VPS from your laptop.
#
# Bootstraps with username+password over SSH, uploads the hardening script
# and your public key, then runs it remotely. After completion it verifies
# you can log in as the new user via key on the new port.
#
# Usage:
#   ./harden-remote.sh -H <vps_ip> -u <new_user> -i <vpn_ip_or_cidr> \
#                      -k <pubkey_file> [-U <bootstrap_user>] \
#                      [-P <bootstrap_port>] [-p <new_ssh_port>]
#
# Flags:
#   -H   target VPS IP/hostname                          (required)
#   -u   new sudo username to create                     (required)
#   -i   VPN IP or CIDR allowed to SSH in                (required)
#   -k   path to your LOCAL public key file              (required)
#   -U   bootstrap username for initial login            (default: root)
#   -P   bootstrap SSH port                              (default: 22)
#   -p   new hardened SSH port                           (default: 7799)
#   -h   show this help
#
# Password is always prompted interactively (hidden input).
#
# Example:
#   ./harden-remote.sh -H 203.0.113.10 -u deploy -i 10.8.0.0/24 \
#                      -k ~/.ssh/id_ed25519.pub

set -euo pipefail

# ---------- pretty output ----------------------------------------------------
BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
CYAN=$'\033[36m'; MAGENTA=$'\033[35m'

STEP=0
TOTAL=6

banner() {
    echo
    echo "${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${MAGENTA}║${RESET} ${BOLD}%-64s${RESET} ${MAGENTA}║${RESET}\n" "$1"
    echo "${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
}
step()  { STEP=$((STEP + 1)); printf "\n${BLUE}[%d/%d]${RESET} ${BOLD}%s${RESET}\n" "$STEP" "$TOTAL" "$1"; }
ok()    { printf "      ${GREEN}✔${RESET} %s\n" "$1"; }
info()  { printf "      ${DIM}• %s${RESET}\n" "$1"; }
warn()  { printf "      ${YELLOW}!${RESET} %s\n" "$1"; }
die()   { printf "      ${RED}✘${RESET} %s\n" "$1"; exit 1; }

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------- argument parsing -------------------------------------------------
VPS_HOST=""
BOOT_USER="root"
BOOT_PORT="22"
NEW_USER=""
VPN_IP=""
PUBKEY_FILE=""
NEW_PORT="7799"

while getopts ":H:U:P:u:i:k:p:h" opt; do
    case "$opt" in
        H) VPS_HOST="$OPTARG" ;;
        U) BOOT_USER="$OPTARG" ;;
        P) BOOT_PORT="$OPTARG" ;;
        u) NEW_USER="$OPTARG" ;;
        i) VPN_IP="$OPTARG" ;;
        k) PUBKEY_FILE="$OPTARG" ;;
        p) NEW_PORT="$OPTARG" ;;
        h) usage 0 ;;
        \?) echo "unknown flag: -$OPTARG" >&2; usage 1 ;;
        :)  echo "flag -$OPTARG requires a value" >&2; usage 1 ;;
    esac
done

banner "Remote VPS Hardening — Controller"

[[ -n "$VPS_HOST"   ]] || { echo "missing -H <vps_ip>"   >&2; usage 1; }
[[ -n "$NEW_USER"   ]] || { echo "missing -u <username>" >&2; usage 1; }
[[ -n "$VPN_IP"     ]] || { echo "missing -i <vpn_ip>"   >&2; usage 1; }
[[ -n "$PUBKEY_FILE" ]] || { echo "missing -k <pubkey_file>" >&2; usage 1; }

# Expand a leading ~ that survived an unquoted shell expansion edge case.
PUBKEY_FILE="${PUBKEY_FILE/#\~/$HOME}"

[[ -r "$PUBKEY_FILE" ]] || die "cannot read public key file: $PUBKEY_FILE"
PUBKEY_CONTENT="$(< "$PUBKEY_FILE")"
[[ "$PUBKEY_CONTENT" =~ ^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521))\  ]] \
    || die "file does not look like an OpenSSH public key: $PUBKEY_FILE"

[[ "$NEW_PORT"  =~ ^[0-9]+$ ]] && (( NEW_PORT  >= 1 && NEW_PORT  <= 65535 )) \
    || die "invalid new SSH port: $NEW_PORT"
[[ "$BOOT_PORT" =~ ^[0-9]+$ ]] && (( BOOT_PORT >= 1 && BOOT_PORT <= 65535 )) \
    || die "invalid bootstrap port: $BOOT_PORT"

LOCAL_SCRIPT="$(dirname "$(realpath "$0")")/secure-vps.sh"
[[ -r "$LOCAL_SCRIPT" ]] || die "remote hardener not found beside this script: $LOCAL_SCRIPT"

info "target           : ${BOLD}${BOOT_USER}@${VPS_HOST}:${BOOT_PORT}${RESET}"
info "new sudo user    : ${BOLD}${NEW_USER}${RESET}"
info "new SSH port     : ${BOLD}${NEW_PORT}${RESET}"
info "allowed source   : ${BOLD}${VPN_IP}${RESET}"
info "public key       : ${PUBKEY_FILE}"

# ---------- dependency check -------------------------------------------------
step "Checking local dependencies"
command -v expect >/dev/null 2>&1 || die "expect not found — ships with macOS; on Linux: apt/dnf install expect"
command -v ssh    >/dev/null 2>&1 || die "ssh not found in PATH"
command -v scp    >/dev/null 2>&1 || die "scp not found in PATH"
ok "expect / ssh / scp present"

# ---------- prompt for bootstrap password ------------------------------------
echo
printf "${BOLD}Bootstrap password for ${BOOT_USER}@${VPS_HOST}:${RESET} "
# read -s suppresses echo so the password never appears on screen or in history
read -rs SSH_PASSWORD
echo
[[ -n "$SSH_PASSWORD" ]] || die "empty password — aborting"
export SSH_PASSWORD

KNOWN_HOSTS="$(mktemp -t harden-remote-known-hosts.XXXXXX)"
EXPECT_HELPER="$(mktemp -t harden-remote-expect.XXXXXX)"
trap 'rm -f "$KNOWN_HOSTS" "$EXPECT_HELPER"' EXIT

# Expect helper: spawns the given ssh/scp command, answers the password prompt,
# then streams remaining output until EOF. Reads password from $SSH_PASSWORD env.
cat > "$EXPECT_HELPER" <<'EXPECT_SCRIPT'
#!/usr/bin/env expect -f
set timeout 60
set password $env(SSH_PASSWORD)
log_user 1
eval spawn -noecho $argv

expect {
    -re "(?i)are you sure you want to continue connecting" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)password:" {
        send -- "$password\r"
        set timeout -1
    }
    -re "(?i)permission denied" {
        puts stderr "\n!! authentication failed"
        exit 1
    }
    -re "(?i)connection refused" {
        puts stderr "\n!! connection refused"
        exit 1
    }
    timeout {
        puts stderr "\n!! connection timed out waiting for password prompt"
        exit 124
    }
    eof {
        # Connection closed before any password prompt — either it succeeded
        # via existing key auth, or it errored out. Fall through to wait.
    }
}

expect eof
catch wait result
exit [lindex $result 3]
EXPECT_SCRIPT
chmod 700 "$EXPECT_HELPER"

SSH_OPTS=(
    -o StrictHostKeyChecking=accept-new
    -o UserKnownHostsFile="$KNOWN_HOSTS"
    -o ConnectTimeout=15
    -o LogLevel=ERROR
    -o PubkeyAuthentication=no
    -o PreferredAuthentications=password
    -o NumberOfPasswordPrompts=1
)

remote_ssh() {
    expect "$EXPECT_HELPER" ssh "${SSH_OPTS[@]}" -p "$BOOT_PORT" "${BOOT_USER}@${VPS_HOST}" "$@"
}
remote_scp() {
    expect "$EXPECT_HELPER" scp "${SSH_OPTS[@]}" -P "$BOOT_PORT" "$@"
}

# ---------- step 1: connectivity check ---------------------------------------
step "Verifying SSH connectivity"
if OUT=$(remote_ssh 'echo CONNECTED && uname -s' 2>&1); then
    [[ "$OUT" == *"CONNECTED"* ]] || die "unexpected response from remote: $OUT"
    ok "authenticated as ${BOOT_USER}@${VPS_HOST}"
    [[ "$OUT" == *"Linux"* ]] && ok "remote OS family: Linux" \
                              || warn "remote OS reports: $(echo "$OUT" | tail -1)"
else
    die "could not connect — check host/port/credentials. Detail: $OUT"
fi

# ---------- step 2: upload payload -------------------------------------------
step "Uploading hardener + public key to ${VPS_HOST}"
REMOTE_TMP="/tmp/harden-$(date +%s)-$$"
remote_ssh "mkdir -p '$REMOTE_TMP' && chmod 700 '$REMOTE_TMP'" >/dev/null
info "remote staging dir: ${DIM}${REMOTE_TMP}${RESET}"

remote_scp "$LOCAL_SCRIPT"  "${BOOT_USER}@${VPS_HOST}:${REMOTE_TMP}/secure-vps.sh" >/dev/null
ok "secure-vps.sh uploaded"
remote_scp "$PUBKEY_FILE"   "${BOOT_USER}@${VPS_HOST}:${REMOTE_TMP}/authorized.pub" >/dev/null
ok "public key uploaded"
remote_ssh "chmod +x '$REMOTE_TMP/secure-vps.sh'" >/dev/null

# ---------- step 3: run remote hardener --------------------------------------
step "Running remote hardener (streaming output)"
echo
SUDO=""
[[ "$BOOT_USER" != "root" ]] && SUDO="sudo "
REMOTE_CMD="${SUDO}bash '${REMOTE_TMP}/secure-vps.sh' -u '${NEW_USER}' -i '${VPN_IP}' -k '${REMOTE_TMP}/authorized.pub' -p '${NEW_PORT}'"

# -tt so the remote script sees a TTY (preserves colours, allows sudo prompts).
if expect "$EXPECT_HELPER" ssh -tt "${SSH_OPTS[@]}" -p "$BOOT_PORT" "${BOOT_USER}@${VPS_HOST}" "$REMOTE_CMD"; then
    echo
    ok "remote hardener finished successfully"
else
    echo
    die "remote hardener exited non-zero — bootstrap session may still be open for rollback"
fi

# ---------- step 4: cleanup remote staging -----------------------------------
step "Cleaning up remote staging directory"
remote_ssh "rm -rf '$REMOTE_TMP'" >/dev/null || warn "could not remove $REMOTE_TMP (non-fatal)"
ok "removed $REMOTE_TMP"

# ---------- step 5: verify new login -----------------------------------------
step "Verifying new login on port ${NEW_PORT} as ${NEW_USER}"
# Find a private key on the local side that matches the uploaded public key.
PUBKEY_FP=$(ssh-keygen -lf "$PUBKEY_FILE" 2>/dev/null | awk '{print $2}') || true
PRIV_KEY=""
for cand in "${PUBKEY_FILE%.pub}" ~/.ssh/id_ed25519 ~/.ssh/id_rsa ~/.ssh/id_ecdsa; do
    [[ -r "$cand" ]] || continue
    if [[ -n "$PUBKEY_FP" ]] && fp=$(ssh-keygen -lf "$cand" 2>/dev/null | awk '{print $2}') \
       && [[ "$fp" == "$PUBKEY_FP" ]]; then
        PRIV_KEY="$cand"; break
    fi
done

if [[ -z "$PRIV_KEY" ]]; then
    warn "could not locate the matching private key locally — skipping live verification"
    info "test it yourself: ${BOLD}ssh -p ${NEW_PORT} ${NEW_USER}@${VPS_HOST}${RESET}"
else
    info "using private key: ${PRIV_KEY}"
    if ssh -i "$PRIV_KEY" \
           -o StrictHostKeyChecking=accept-new \
           -o UserKnownHostsFile="$KNOWN_HOSTS" \
           -o PasswordAuthentication=no \
           -o ConnectTimeout=15 \
           -p "$NEW_PORT" \
           "${NEW_USER}@${VPS_HOST}" \
           'echo NEWLOGIN_OK && id' 2>/dev/null | grep -q NEWLOGIN_OK; then
        ok "new login works: ${BOLD}ssh -p ${NEW_PORT} ${NEW_USER}@${VPS_HOST}${RESET}"
    else
        warn "could not verify new login automatically"
        warn "this may be expected if your laptop's IP is outside ${VPN_IP}"
        info "try manually: ${BOLD}ssh -p ${NEW_PORT} ${NEW_USER}@${VPS_HOST}${RESET}"
    fi
fi

# ---------- step 6: summary --------------------------------------------------
step "Done"
echo
echo "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo "${GREEN}║${RESET}  ${BOLD}Remote hardening complete${RESET}                                       ${GREEN}║${RESET}"
echo "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo
echo "  ${BOLD}Host${RESET}            : ${VPS_HOST}"
echo "  ${BOLD}New sudo user${RESET}   : ${NEW_USER}"
echo "  ${BOLD}New SSH port${RESET}    : ${NEW_PORT}"
echo "  ${BOLD}Allowed from${RESET}    : ${VPN_IP}  (sshd AllowUsers)"
echo "  ${BOLD}Root login${RESET}      : ${RED}disabled${RESET}"
echo "  ${BOLD}Password auth${RESET}   : ${RED}disabled${RESET}"
echo
echo "  ${BOLD}Connect with${RESET}    : ${CYAN}ssh -p ${NEW_PORT} ${NEW_USER}@${VPS_HOST}${RESET}"
echo
