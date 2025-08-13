sudo pct create 100 synology:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  -hostname ansible \
  -storage local-lvm \
  -cores 2 \
  -memory 2048 \
  -rootfs local-lvm:10 \
  -net0 name=mgmt,bridge=vmbr0,tag=10,ip=10.10.0.2/24,gw=10.10.0.1 \
  -unprivileged 1 \
&& sudo pct set 100 -tags mgmt

### IM CONTAINER 

# System aktualisieren
apt update && apt upgrade -y

# Benutzer mit Home-Verzeichnis anlegen
useradd -m -d /home/erik -s /bin/bash erik

# Starkes Passwort setzen
passwd erik

# IPv6 systemweit deaktivieren
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Netzwerk-Sicherheit
tee -a /etc/sysctl.conf << 'EOF'

# Network Security Hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 1

EOF

sysctl -p

# Backup erstellen
mkdir -p /etc/ssh/backups
cp /etc/ssh/sshd_config /etc/ssh/backups/sshd_config.backup.$(date +%Y%m%d_%H%M%S)





tee /etc/ssh/sshd_config << 'EOF'
# /etc/ssh/sshd_config - Minimalversion
# Nur Basis-Konfiguration, alle Sicherheitsoptionen über /etc/ssh/sshd_config.d/99-security-hardening.conf

# Include für zusätzliche Konfigurationsdateien
Include /etc/ssh/sshd_config.d/*.conf

# Default Port (optional, kann in Hardening-Datei geändert werden)
Port 22

# Protokollversion
Protocol 2

# HostKeys (Hardening-Datei legt moderne Algorithmen fest)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Keine weiteren Subsystem-Zeilen hier
EOF





cat << 'EOF' >  /etc/ssh/sshd_config.d/99-security-hardening.conf << 'EOF'
# =============================================================================
# SSH Security Hardening Configuration - Enterprise Standards 2025
# =============================================================================

# Network Configuration
Port 62222
AddressFamily inet
ListenAddress 0.0.0.0

# Protocol and Encryption
Protocol 2

# Host Keys - Nur moderne Algorithmen
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Key Exchange Algorithms - Nur sichere moderne Algorithmen
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Cipher Algorithms - Nur AEAD und sichere Verschlüsselung
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MAC Algorithms - Nur ETM (Encrypt-then-MAC)
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com

# Public Key Algorithms
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521

# =============================================================================
# Authentication Configuration
# =============================================================================

# Root Access - Komplett deaktiviert
PermitRootLogin no

# User Authentication
AllowUsers erik
DenyUsers root
DenyGroups root

# Public Key Authentication - Erforderlich
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

# Password Authentication - Deaktiviert
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM no

# =============================================================================
# Session Configuration
# =============================================================================

# Connection Limits
MaxAuthTries 3
MaxSessions 5
MaxStartups 3:30:10

# Session Timeouts
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

# =============================================================================
# Feature Restrictions
# =============================================================================

# Security Features
X11Forwarding no
AllowTcpForwarding local
AllowStreamLocalForwarding no
GatewayPorts no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no

# =============================================================================
# Logging and Monitoring
# =============================================================================

SyslogFacility AUTHPRIV
LogLevel VERBOSE
Banner /etc/ssh/ssh_banner.txt

# =============================================================================
# Additional Security
# =============================================================================

StrictModes yes
Compression no
TCPKeepAlive yes
UseDNS no
PrintMotd no
PrintLastLog yes

Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes
RequiredRSASize 2048
DebianBanner no
EOF




tee /etc/ssh/ssh_banner.txt << 'EOF'

  ################################################################################
  #                                                                              #
  #                           AUTHORIZED ACCESS ONLY                             #
  #                                                                              #
  #  This system is for authorized users only. All activities may be             #
  #  monitored and recorded. By accessing this system, you acknowledge           #
  #  that you have no reasonable expectation of privacy.                         #
  #                                                                              #
  #  Unauthorized access is strictly prohibited and may be subject to            #
  #  criminal and civil penalties.                                               #
  #                                                                              #
  ################################################################################

EOF





# Bestehende Keys sichern
cp -r /etc/ssh /etc/ssh.backup

# Schwache Keys entfernen
rm -f /etc/ssh/ssh_host_dsa_key*
rm -f /etc/ssh/ssh_host_ecdsa_key*

# Neue starke Keys generieren
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Berechtigungen setzen
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub



# Konfiguration testen
sshd -t

# SSH-Service neu laden
systemctl reload sshd

# Status prüfen
systemctl status sshd
ss -tlnp | grep :62222

#ansibe
apt install sudo -y

su - erik 
