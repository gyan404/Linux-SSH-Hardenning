  VPS Hardening Scripts


Two bash scripts that secure a freshly provisioned VPS (AlmaLinux or Ubuntu)
in one shot: SSH hardening, automatic security updates, fail2ban, and a
locked-down sudo user reachable only from your VPN IP via your SSH key.


--------------------------------------------------------------------------------
  Files
--------------------------------------------------------------------------------

  secure-vps.sh      Runs ON the VPS. Performs the actual hardening work.
                     Can be run standalone (copy to server, execute as root).

  harden-remote.sh   Runs ON your laptop. Drives secure-vps.sh remotely over
                     SSH using username + password bootstrap, then verifies
                     the new key-based login works.


--------------------------------------------------------------------------------
  What the hardener does (10 steps)
--------------------------------------------------------------------------------

   1. Detects the OS (AlmaLinux/Rocky/RHEL family or Ubuntu/Debian)
   2. Updates the package index and applies all pending patches
   3. Enables automatic security updates
        - Ubuntu/Debian : unattended-upgrades (security origin)
        - AlmaLinux/RHEL: dnf-automatic.timer (security only)
   4. Installs OpenSSH server (and SELinux tools on RHEL family)
   5. Creates a sudo user with the password locked (key-only login)
   6. Installs your public key into ~/.ssh/authorized_keys (700/600 perms)
   7. Hardens sshd via a drop-in /etc/ssh/sshd_config.d/99-hardening.conf
        - Port changed (default 7799)
        - PermitRootLogin no
        - PasswordAuthentication no
        - AllowUsers <user>@<vpn_ip>  (source-IP restriction)
   8. SELinux port label + disables ssh.socket on Ubuntu 22.04+
   9. Restarts sshd (after `sshd -t` validates the new config)
  10. Installs and enables fail2ban (sshd jail on the new port, VPN whitelisted)

  Passwordless sudo is granted to the new user (SSH key + VPN IP already gate
  access; a sudo password the locked account can't satisfy would just break
  things).


--------------------------------------------------------------------------------
  Requirements
--------------------------------------------------------------------------------

  On the VPS:
    - AlmaLinux 8/9, Rocky 8/9, RHEL 8/9  --  OR  --  Ubuntu 20.04/22.04/24.04
    - Root access (provider bootstrap user + password, or pre-installed key)

  On your laptop (only if using harden-remote.sh):
    - bash, ssh, scp
    - expect (built into macOS; "apt install expect" / "dnf install expect"
      on Linux)


--------------------------------------------------------------------------------
  Usage A: drive the hardening remotely from your laptop
--------------------------------------------------------------------------------

  Put both scripts in the same directory, then on your laptop run:

      ./harden-remote.sh \
          -H <vps_ip>           \
          -u <new_sudo_user>    \
          -i <vpn_ip_or_cidr>   \
          -k <path_to_your_pubkey>

  Example:

      ./harden-remote.sh \
          -H 203.0.113.10 \
          -u deploy \
          -i 10.8.0.0/24 \
          -k ~/.ssh/id_ed25519.pub

  All flags:
    -H   target VPS IP/hostname                  (required)
    -u   new sudo username                       (required)
    -i   VPN IP or CIDR allowed to SSH in        (required)
    -k   path to LOCAL public-key file           (required)
    -U   bootstrap username                      (default: root)
    -P   bootstrap SSH port                      (default: 22)
    -p   new hardened SSH port                   (default: 7799)
    -h   show help

  You are prompted for the bootstrap password interactively (hidden input,
  never echoed, never appears on the command line).


--------------------------------------------------------------------------------
  Usage B: run the hardener directly on the VPS
--------------------------------------------------------------------------------

  Copy secure-vps.sh to the server, then as root:

      ./secure-vps.sh \
          -u <new_sudo_user>    \
          -i <vpn_ip_or_cidr>   \
          -k <path_or_string>   \
          [-p <port>]

  The -k argument can be either:
    - a path to a public-key file on the VPS,         OR
    - the literal public-key string ("ssh-ed25519 AAAA... me@laptop")

  Examples:

      sudo ./secure-vps.sh -u deploy -i 10.8.0.0/24 -k /root/mykey.pub
      sudo ./secure-vps.sh -u admin  -i 203.0.113.5 \
           -k "ssh-ed25519 AAAAC3Nz... me@laptop" -p 2222


--------------------------------------------------------------------------------
  After it runs
--------------------------------------------------------------------------------

  Connect with:

      ssh -p 7799 <new_sudo_user>@<vps_ip>

  IMPORTANT: keep your initial root session OPEN until you have confirmed the
  new login works from a second terminal. If you cannot reconnect, see the
  rollback section below.

  Quick post-run checks (from inside the new user's session):

      # sshd is on the new port only
      sudo ss -tlnp | grep -E ':(22|7799)\s'

      # auto-updates timer is armed
      systemctl status unattended-upgrades 2>/dev/null \
          || systemctl list-timers dnf-automatic.timer

      # fail2ban is watching the new port
      sudo fail2ban-client status sshd


--------------------------------------------------------------------------------
  Safety / rollback
--------------------------------------------------------------------------------

  - The original /etc/ssh/sshd_config is backed up with a timestamp before
    any changes:  /etc/ssh/sshd_config.bak-YYYYMMDD-HHMMSS
  - `sshd -t` validates the new config BEFORE sshd is restarted, so a typo
    cannot lock you out via syntax error.
  - Full run log:  /var/log/secure-vps-YYYYMMDD-HHMMSS.log
  - The new user's password is locked (key-only); sudo is passwordless.
  - The wrapper auto-verifies the new key-based login at the end of the run.

  If something is wrong and you need to roll back (while a root session is
  still open):

      sudo cp /etc/ssh/sshd_config.bak-<TIMESTAMP> /etc/ssh/sshd_config
      sudo rm /etc/ssh/sshd_config.d/99-hardening.conf
      sudo systemctl restart sshd        # or 'ssh' on Ubuntu


--------------------------------------------------------------------------------
  Notes
--------------------------------------------------------------------------------

  - On Ubuntu 22.04+, ssh.socket can override the Port directive. The script
    detects this and disables ssh.socket so the new port actually takes
    effect.
  - On AlmaLinux/RHEL, SELinux is taught about the new port via
    `semanage port -a -t ssh_port_t -p tcp <port>`.
  - The sshd `AllowUsers <user>@<vpn_ip>` restriction enforces the source-IP
    at the SSH layer. No firewall is configured by this script.
  - fail2ban uses the `systemd` backend (journal-based), so no rsyslog
    dependency, works on both distro families.


--------------------------------------------------------------------------------
  License
--------------------------------------------------------------------------------

  Use, modify, and redistribute freely. No warranty.
