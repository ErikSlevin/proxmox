# Ansible Semaphore LXC Container Setup

## Container Erstellung

```bash
sudo pct create 100 synology:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  -hostname ansible \
  -storage local-lvm \
  -cores 2 \
  -memory 2048 \
  -rootfs local-lvm:10 \
  -net0 name=mgmt,bridge=vmbr0,tag=10,ip=10.10.0.2/24,gw=10.10.0.1 \
  -unprivileged 1 \
&& sudo pct set 100 -tags mgmt
```

## Initial Container-Konfiguration

### System Update und Benutzer

```bash
# System aktualisieren
apt update && apt upgrade -y

# Benutzer erstellen
useradd -m -d /home/erik -s /bin/bash erik
passwd erik

# Sudo installieren
apt install sudo -y

# Erik zu sudo-Gruppe hinzufügen
usermod -aG sudo erik
```

### System-Härtung

#### IPv6 deaktivieren

```bash
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### Netzwerk-Sicherheit

```bash
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
```

## SSH-Härtung

### Backup und Basis-Konfiguration

```bash
# Backup erstellen
mkdir -p /etc/ssh/backups
cp /etc/ssh/sshd_config /etc/ssh/backups/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Basis SSH-Konfiguration
tee /etc/ssh/sshd_config << 'EOF'
# SSH Basis-Konfiguration
Include /etc/ssh/sshd_config.d/*.conf

Port 22
Protocol 2

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
EOF
```

### Security Hardening

```bash
tee /etc/ssh/sshd_config.d/99-security-hardening.conf << 'EOF'
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

# Key Exchange Algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Cipher Algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# MAC Algorithms
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

# Public Key Authentication
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
```

### SSH Banner

```bash
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
```

### SSH Keys erneuern

```bash
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
```

## Semaphore UI Installation

### Datenbank Setup (MariaDB)

```bash
# MariaDB installieren
apt install mariadb-server -y
systemctl status mariadb

# Sicherheits-Setup
mysql_secure_installation

# Datenbank und Benutzer erstellen
sudo mariadb
```

**In der MariaDB-Shell:**

```sql
CREATE DATABASE semaphore_db;
SHOW DATABASES;
GRANT ALL PRIVILEGES ON semaphore_db.* TO semaphore_user@localhost IDENTIFIED BY "DEIN_SICHERES_PASSWORT";
FLUSH PRIVILEGES;
EXIT;
```

### Semaphore Benutzer und Installation

```bash
# System-Benutzer für Semaphore erstellen
sudo adduser --system --group --home /home/semaphore semaphore

# Semaphore herunterladen
wget https://github.com/semaphoreui/semaphore/releases/download/v2.16.16/semaphore_2.16.16_linux_amd64.deb

# Installation
sudo apt install ./semaphore_2.16.16_linux_amd64.deb

# Aufräumen
rm *_linux_amd64.deb -v
```

### Semaphore Konfiguration

```bash
# Setup starten
semaphore setup
```

**Setup-Parameter:**

| Parameter | Wert |
|-----------|------|
| Database | `1` (MySQL) |
| Hostname | `127.0.0.1:3306` (Enter) |
| User | `semaphore_user` |
| Password | `DEIN_SICHERES_PASSWORT` |
| DB Name | `semaphore_db` |
| Playbook path | `/tmp/semaphore` (Enter) |
| Public URL | _(leer lassen)_ |
| Email alerts | `no` (Enter) |
| Telegram alerts | `no` (Enter) |
| Slack alerts | `no` (Enter) |
| Rocket.Chat alerts | `no` (Enter) |
| MS Teams alerts | `no` (Enter) |
| LDAP auth | `no` (Enter) |

**Admin-Benutzer erstellen:**

- **Username:** `erik`
- **Email:** `deine@email.de`
- **Name:** `Erik`
- **Password:** `DEIN_SICHERES_PASSWORT`

### Konfiguration finalisieren

```bash
# Konfiguration verschieben
sudo chown semaphore:semaphore config.json
sudo mkdir /etc/semaphore -v
sudo chown semaphore:semaphore /etc/semaphore -v
sudo mv ./config.json /etc/semaphore/

# Ansible installieren
sudo apt install ansible -y
```

## Systemd Service Setup

### Service-Datei erstellen

```bash
sudo tee /etc/systemd/system/semaphore.service << 'EOF'
[Unit]
Description=Ansible Semaphore
Documentation=https://docs.ansible-semaphore.com/
Wants=network-online.target
After=network-online.target
ConditionPathExists=/usr/bin/semaphore
ConditionPathExists=/etc/semaphore/config.json

[Service]
ExecStart=/usr/bin/semaphore server --config /etc/semaphore/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10s
User=semaphore
Group=semaphore

[Install]
WantedBy=multi-user.target
EOF
```

### Service aktivieren

```bash
# Systemd neu laden
sudo systemctl daemon-reload

# Service aktivieren
sudo systemctl enable semaphore.service

# Service starten
sudo systemctl start semaphore.service

# Status prüfen
sudo systemctl status semaphore.service
```

## Zugriff und Verifikation

### WebUI-Zugriff

- **URL:** `http://10.10.0.2:3000/`
- **Benutzer:** `erik`
- **Passwort:** _Das beim Setup gewählte Passwort_

### SSH-Zugriff

```bash
# Vom Proxmox-Host aus
ssh erik@10.10.0.2 -p 62222
```

### Service-Status prüfen

```bash
# Semaphore Service
sudo systemctl status semaphore.service

# SSH Service
sudo systemctl status sshd

# MariaDB Service
sudo systemctl status mariadb

# Netzwerk-Status
ip addr show
ss -tlnp | grep -E "(3000|62222|3306)"
```

## Container-Informationen

| Parameter | Wert |
|-----------|------|
| **Container ID** | 100 |
| **Hostname** | ansible |
| **IP-Adresse** | 10.10.0.2/24 |
| **Gateway** | 10.10.0.1 |
| **VLAN** | 10 (Management) |
| **SSH Port** | 62222 |
| **WebUI Port** | 3000 |
| **Cores** | 2 |
| **Memory** | 2048 MB |
| **Storage** | 10 GB |

## Referenzen

- **Tutorial-Quelle:** [YouTube - Semaphore Installation](https://www.youtube.com/watch?v=CltoVfeRdoM&list=PLjxLL_QG98bjlTySo8kACJGuHks2pT5KQ)
- **Semaphore Dokumentation:** [docs.ansible-semaphore.com](https://docs.ansible-semaphore.com/)
- **Ansible Dokumentation:** [docs.ansible.com](https://docs.ansible.com/)

---

## Nächste Schritte

1. **SSH-Keys einrichten** für passwortlose Authentifizierung
2. **Ansible Inventory** konfigurieren für Ziel-Hosts
3. **Playbooks** erstellen und in Semaphore verwalten
4. **Firewall-Regeln** auf Proxmox-Host anpassen falls nötig

**🎯 Der Ansible Semaphore Container ist jetzt einsatzbereit für automatisierte Infrastruktur-Verwaltung!**
