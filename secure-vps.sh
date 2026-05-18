#!/usr/bin/env bash
#
# secure-vps.sh — Harden a freshly provisioned VPS (AlmaLinux or Ubuntu).
#
# Usage:
#   sudo ./secure-vps.sh -u <username> -i <vpn_ip_or_cidr> -k <pubkey> [-p <port>]
#
# Flags:
#   -u   new sudo username (required)
#   -i   VPN IP or CIDR allowed to SSH in, e.g. 10.8.0.0/24 or 203.0.113.5 (required)
#   -k   path to your public-key file OR the key string itself (required)
#   -p   SSH port (optional, default 7799)
#   -h   show this help
#
# Examples:
#   sudo ./secure-vps.sh -u deploy -i 10.8.0.0/24 -k ~/.ssh/id_ed25519.pub
#   sudo ./secure-vps.sh -u admin  -i 203.0.113.5 \
#        -k "ssh-ed25519 AAAAC3Nz... me@laptop" -p 7799
#
# The script will:
#   1. Update & patch the OS
#   2. Enable automatic security updates
#   3. Create the sudo user and install your public key
#   4. Move SSH to the chosen port, disable root + password auth
#   5. Restrict SSH access to the VPN IP via sshd AllowUsers
#   6. Install & configure fail2ban for SSH brute-force protection

set -euo pipefail

# ---------- argument parsing -------------------------------------------------
NEW_USER=""
VPN_IP=""
SSH_PUBKEY=""
SSH_PORT="7799"

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while getopts ":u:i:k:p:h" opt; do
    case "$opt" in
        u) NEW_USER="$OPTARG" ;;
        i) VPN_IP="$OPTARG" ;;
        k) SSH_PUBKEY="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        h) usage 0 ;;
        \?) echo "unknown flag: -$OPTARG" >&2; usage 1 ;;
        :)  echo "flag -$OPTARG requires a value" >&2; usage 1 ;;
    esac
done

# ---------- pretty output helpers --------------------------------------------
BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'; CYAN=$'\033[36m'

LOG="/var/log/secure-vps-$(date +%Y%m%d-%H%M%S).log"
STEP=0
TOTAL=10

banner() {
    echo
    echo "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${CYAN}║${RESET} ${BOLD}%-64s${RESET} ${CYAN}║${RESET}\n" "$1"
    echo "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
}

step() {
    STEP=$((STEP + 1))
    printf "\n${BLUE}[%d/%d]${RESET} ${BOLD}%s${RESET}\n" "$STEP" "$TOTAL" "$1"
}

ok()    { printf "      ${GREEN}✔${RESET} %s\n" "$1"; }
info()  { printf "      ${DIM}• %s${RESET}\n" "$1"; }
warn()  { printf "      ${YELLOW}!${RESET} %s\n" "$1"; }
fail()  { printf "      ${RED}✘${RESET} %s\n" "$1"; exit 1; }

run() {
    # Run a command quietly. Log output. Exit on failure.
    if ! "$@" >>"$LOG" 2>&1; then
        fail "command failed: $*  (see $LOG)"
    fi
}

# ---------- pre-flight -------------------------------------------------------
banner "VPS Hardening Script"

[[ $EUID -eq 0 ]] || fail "must run as root (try: sudo $0 ...)"

[[ -n "$NEW_USER"   ]] || { echo "missing -u <username>" >&2; usage 1; }
[[ -n "$VPN_IP"     ]] || { echo "missing -i <vpn_ip>"   >&2; usage 1; }
[[ -n "$SSH_PUBKEY" ]] || { echo "missing -k <pubkey>"   >&2; usage 1; }

[[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "invalid username: $NEW_USER"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) \
    || fail "invalid SSH port: $SSH_PORT"

# Resolve -k: if it's a readable file, read its contents; otherwise treat as the key string.
if [[ -r "$SSH_PUBKEY" && -f "$SSH_PUBKEY" ]]; then
    SSH_PUBKEY="$(< "$SSH_PUBKEY")"
fi
SSH_PUBKEY="$(printf '%s' "$SSH_PUBKEY" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
[[ "$SSH_PUBKEY" =~ ^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521))\  ]] \
    || fail "SSH_PUBKEY does not look like a valid OpenSSH public key"

touch "$LOG" && chmod 600 "$LOG"

info "user to create        : ${BOLD}${NEW_USER}${RESET}"
info "SSH port              : ${BOLD}${SSH_PORT}${RESET}"
info "allowed source        : ${BOLD}${VPN_IP}${RESET}"
info "detailed log          : ${DIM}${LOG}${RESET}"

# ---------- detect OS --------------------------------------------------------
step "Detecting operating system"
. /etc/os-release
case "${ID,,}" in
    ubuntu|debian)
        OS_FAMILY="debian"
        PKG_UPDATE="apt-get update -y"
        PKG_UPGRADE="apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"
        SUDO_GROUP="sudo"
        export DEBIAN_FRONTEND=noninteractive
        ;;
    almalinux|rocky|rhel|centos|fedora)
        OS_FAMILY="rhel"
        if command -v dnf >/dev/null 2>&1; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
        PKG_UPDATE="$PKG_MGR makecache"
        PKG_UPGRADE="$PKG_MGR -y upgrade"
        SUDO_GROUP="wheel"
        ;;
    *)
        fail "unsupported OS: $ID (only AlmaLinux/RHEL family and Ubuntu/Debian are supported)"
        ;;
esac
ok "detected ${BOLD}${PRETTY_NAME}${RESET} (${OS_FAMILY} family)"

# ---------- update & patch ---------------------------------------------------
step "Updating package index and patching the system"
info "this may take a few minutes…"
run bash -c "$PKG_UPDATE"
ok "package index refreshed"
run bash -c "$PKG_UPGRADE"
ok "system packages upgraded"

# ---------- automatic security updates ---------------------------------------
step "Enabling automatic security updates"
if [[ "$OS_FAMILY" == "debian" ]]; then
    run apt-get install -y unattended-upgrades apt-listchanges
    ok "installed unattended-upgrades"

    # Turn on the periodic timers
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    ok "enabled daily update + unattended-upgrade timers"

    # Make sure security origin is active and unused deps get auto-removed.
    UU_CFG="/etc/apt/apt.conf.d/50unattended-upgrades"
    if [[ -f "$UU_CFG" ]]; then
        sed -ri 's|^//\s*("\${distro_id}:\${distro_codename}-security";)|        \1|' "$UU_CFG" || true
        sed -ri 's|^//\s*(Unattended-Upgrade::Remove-Unused-Dependencies\s+"false";)|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' "$UU_CFG" || true
        ok "ensured security origin is enabled in 50unattended-upgrades"
    fi

    run systemctl enable --now unattended-upgrades.service
    ok "unattended-upgrades.service active"
else
    run $PKG_MGR -y install dnf-automatic
    ok "installed dnf-automatic"

    AUTO_CFG="/etc/dnf/automatic.conf"
    # Apply security updates only, automatically.
    sed -ri 's|^\s*upgrade_type\s*=.*|upgrade_type = security|'   "$AUTO_CFG"
    sed -ri 's|^\s*apply_updates\s*=.*|apply_updates = yes|'       "$AUTO_CFG"
    sed -ri 's|^\s*download_updates\s*=.*|download_updates = yes|' "$AUTO_CFG"
    ok "configured dnf-automatic for security-only auto-apply"

    run systemctl enable --now dnf-automatic.timer
    ok "dnf-automatic.timer active"
fi

# ---------- ensure openssh server present ------------------------------------
step "Ensuring OpenSSH server is installed"
if [[ "$OS_FAMILY" == "debian" ]]; then
    run apt-get install -y openssh-server
else
    run $PKG_MGR -y install openssh-server policycoreutils-python-utils || \
        run $PKG_MGR -y install openssh-server policycoreutils-python
fi
ok "openssh-server present"

# ---------- create sudo user -------------------------------------------------
step "Creating sudo user '${NEW_USER}'"
if id "$NEW_USER" >/dev/null 2>&1; then
    warn "user '${NEW_USER}' already exists — reusing"
else
    run useradd -m -s /bin/bash "$NEW_USER"
    ok "user created with home directory"
fi

# lock password — key-only login
run passwd -l "$NEW_USER"
ok "password login locked (key-only)"

run usermod -aG "$SUDO_GROUP" "$NEW_USER"
ok "added to '${SUDO_GROUP}' group"

# Passwordless sudo — the account has no password (locked above) and SSH is
# key-only + IP-restricted, so prompting for a password sudo can't satisfy is
# just a footgun. Same pattern AWS/GCP cloud images use.
SUDOERS_FILE="/etc/sudoers.d/90-${NEW_USER}"
echo "${NEW_USER} ALL=(ALL:ALL) NOPASSWD: ALL" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >>"$LOG" 2>&1 || fail "sudoers file failed validation"
ok "sudoers entry installed (passwordless)"

# ---------- install public key ----------------------------------------------
step "Installing SSH public key"
SSH_DIR="/home/${NEW_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "$SSH_DIR"

if grep -qF "$SSH_PUBKEY" "$AUTH_KEYS" 2>/dev/null; then
    info "key already present in authorized_keys"
else
    echo "$SSH_PUBKEY" >> "$AUTH_KEYS"
    ok "public key appended to authorized_keys"
fi
chown "$NEW_USER:$NEW_USER" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
ok "permissions set (700 dir / 600 file)"

# ---------- harden sshd ------------------------------------------------------
step "Hardening SSH daemon"
SSHD_CFG="/etc/ssh/sshd_config"
BACKUP="${SSHD_CFG}.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$SSHD_CFG" "$BACKUP"
ok "backed up original sshd_config → ${DIM}${BACKUP}${RESET}"

# Drop a dedicated hardening file so we don't fight with distro defaults that
# may live in /etc/ssh/sshd_config.d/*.conf — and make sure it's loaded last.
HARDEN_FILE="/etc/ssh/sshd_config.d/99-hardening.conf"
mkdir -p /etc/ssh/sshd_config.d

cat > "$HARDEN_FILE" <<EOF
# Managed by secure-vps.sh — do not edit by hand
Port ${SSH_PORT}
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowUsers ${NEW_USER}@${VPN_IP}
EOF
chmod 600 "$HARDEN_FILE"
ok "wrote hardening config to ${DIM}${HARDEN_FILE}${RESET}"

# Some distros (Ubuntu) ship an Include line; older ones don't.
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d' "$SSHD_CFG"; then
    echo "Include /etc/ssh/sshd_config.d/*.conf" >> "$SSHD_CFG"
    info "added Include directive to main sshd_config"
fi

# Neutralise any conflicting directives in the main file so our drop-in wins.
for key in Port PermitRootLogin PasswordAuthentication ChallengeResponseAuthentication KbdInteractiveAuthentication; do
    sed -ri "s|^[#[:space:]]*${key}[[:space:]].*|# ${key} — overridden by 99-hardening.conf|g" "$SSHD_CFG"
done
ok "neutralised conflicting directives in main config"

# Validate before touching the running daemon.
if sshd -t >>"$LOG" 2>&1; then
    ok "sshd config syntax OK"
else
    fail "sshd -t reported errors — original config preserved at ${BACKUP}"
fi

# ---------- selinux + socket activation for the new port --------------------
step "Applying SELinux / socket settings for port ${SSH_PORT}"
if [[ "$OS_FAMILY" == "rhel" ]] && command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
    if command -v semanage >/dev/null 2>&1; then
        if semanage port -l | awk '$1=="ssh_port_t"{print $0}' | grep -qw "$SSH_PORT"; then
            info "SELinux already labels ${SSH_PORT}/tcp as ssh_port_t"
        else
            run semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"
            ok "SELinux: labelled ${SSH_PORT}/tcp as ssh_port_t"
        fi
    else
        warn "semanage not available — install policycoreutils-python-utils if SELinux blocks port"
    fi
else
    info "SELinux not enforcing — nothing to do"
fi

# Ubuntu 22.04+ uses ssh.socket which overrides the Port directive.
if systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.socket'; then
    if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
        run systemctl disable --now ssh.socket
        ok "disabled ssh.socket (was overriding Port directive)"
    fi
fi

# ---------- restart sshd -----------------------------------------------------
step "Restarting SSH service"

# Find the real unit. Some Ubuntu builds ship 'ssh.service' as an alias for
# 'sshd.service'; others vice versa. systemctl cat handles aliases correctly.
SSHD_UNIT=""
for cand in ssh sshd ssh.service sshd.service; do
    if systemctl cat "$cand" >/dev/null 2>&1; then
        SSHD_UNIT="${cand%.service}"
        break
    fi
done
[[ -n "$SSHD_UNIT" ]] || fail "could not locate ssh/sshd systemd unit"
info "using systemd unit: ${SSHD_UNIT}"

# 'enable' is best-effort: on Ubuntu 24.04+ ssh.service can be a static or
# alias unit that systemctl refuses to enable. That's fine — what matters is
# that it's running after restart.
if systemctl is-enabled "$SSHD_UNIT" >/dev/null 2>&1; then
    ok "${SSHD_UNIT} already enabled"
else
    if systemctl enable "$SSHD_UNIT" >>"$LOG" 2>&1; then
        ok "${SSHD_UNIT} enabled at boot"
    else
        warn "could not 'enable' ${SSHD_UNIT} (likely a static/alias unit) — continuing"
    fi
fi

run systemctl restart "$SSHD_UNIT"
sleep 1
if systemctl is-active --quiet "$SSHD_UNIT"; then
    ok "${SSHD_UNIT} is active and listening on port ${SSH_PORT}"
else
    fail "${SSHD_UNIT} failed to start — check 'journalctl -u ${SSHD_UNIT}'"
fi

# ---------- fail2ban ---------------------------------------------------------
step "Setting up fail2ban for SSH"
if [[ "$OS_FAMILY" == "debian" ]]; then
    run apt-get install -y fail2ban
    ok "fail2ban installed"
else
    if ! rpm -q epel-release >/dev/null 2>&1; then
        run $PKG_MGR -y install epel-release
        ok "EPEL repository added"
    fi
    run $PKG_MGR -y install fail2ban fail2ban-systemd
    ok "fail2ban installed"
fi

# Watch the new SSH port via the systemd journal (works on both families).
cat > /etc/fail2ban/jail.local <<EOF
# Managed by secure-vps.sh — do not edit by hand
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1 ${VPN_IP}

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF
chmod 644 /etc/fail2ban/jail.local
ok "wrote /etc/fail2ban/jail.local (sshd jail on port ${SSH_PORT}, VPN ignored)"

run systemctl enable fail2ban
run systemctl restart fail2ban
sleep 2
if systemctl is-active --quiet fail2ban; then
    ok "fail2ban active — sshd jail watching port ${SSH_PORT}"
    if fail2ban-client status sshd >>"$LOG" 2>&1; then
        info "sshd jail loaded successfully"
    fi
else
    warn "fail2ban failed to start — check 'journalctl -u fail2ban' (SSH hardening still applied)"
fi

# ---------- summary ----------------------------------------------------------
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo "${GREEN}║${RESET}  ${BOLD}Hardening complete${RESET}                                              ${GREEN}║${RESET}"
echo "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo
echo "  ${BOLD}OS${RESET}             : ${PRETTY_NAME}"
echo "  ${BOLD}Sudo user${RESET}      : ${NEW_USER}  (group: ${SUDO_GROUP})"
echo "  ${BOLD}SSH port${RESET}       : ${SSH_PORT}"
echo "  ${BOLD}Root login${RESET}     : ${RED}disabled${RESET}"
echo "  ${BOLD}Password auth${RESET}  : ${RED}disabled${RESET}"
echo "  ${BOLD}Allowed from${RESET}   : ${VPN_IP}  (sshd AllowUsers)"
if [[ "$OS_FAMILY" == "debian" ]]; then
    echo "  ${BOLD}Auto updates${RESET}   : unattended-upgrades (security origin)"
else
    echo "  ${BOLD}Auto updates${RESET}   : dnf-automatic.timer (security only)"
fi
echo "  ${BOLD}fail2ban${RESET}       : sshd jail on ${SSH_PORT} (5 tries / 10 min → 1 h ban)"
echo "  ${BOLD}Backup config${RESET}  : ${BACKUP}"
echo "  ${BOLD}Full log${RESET}       : ${LOG}"
echo
echo "${YELLOW}  ⚠  Keep this SSH session OPEN and test the new login from another"
echo "     terminal before disconnecting:${RESET}"
echo
echo "     ${BOLD}ssh -p ${SSH_PORT} ${NEW_USER}@${SERVER_IP:-<server-ip>}${RESET}"
echo
echo "  If you cannot reconnect, restore the old config:"
echo "     ${DIM}sudo cp ${BACKUP} ${SSHD_CFG} && sudo rm ${HARDEN_FILE} && sudo systemctl restart ${SSHD_UNIT}${RESET}"
echo
