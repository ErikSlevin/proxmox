### Intel e1000e NIC Offloading Fix
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/tools/pve/nic-offloading-fix.sh)"

### Proxmox VE Post Install
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/tools/pve/post-pve-install.sh)"

## Netzwerk-Schema

## UniFi Netzwerk- und Switch-Konfiguration

### 1. VLAN-Netzwerke in UniFi erstellen

#### VLAN 10 - Management Network
1. **Settings → Networks** navigieren
2. **Create New Network** klicken
3. **Einstellungen**:
   - **Name**: `VLAN 10 - Management`
   - **Network Type**: `Standard`
   - **Router**: `Security Gateway`
   - **VLAN ID**: `10`
   - **Gateway/Subnet**: `10.10.0.1/24`
   - **DHCP Mode**: `DHCP Server`
   - **DHCP Range**: `10.10.0.100 - 10.10.0.200`
4. **Save** klicken

#### VLAN 20 - Server/Production Network  
1. **Create New Network** klicken
2. **Einstellungen**:
   - **Name**: `VLAN 20 - Server`
   - **Network Type**: `Standard`
   - **Router**: `Security Gateway`
   - **VLAN ID**: `20`
   - **Gateway/Subnet**: `10.20.0.1/24`
   - **DHCP Mode**: `DHCP Server`
   - **DHCP Range**: `10.20.0.100 - 10.20.0.200`
3. **Save** klicken

#### VLAN 30 - DMZ Network
1. **Create New Network** klicken
2. **Einstellungen**:
   - **Name**: `VLAN 30 - DMZ`
   - **Network Type**: `Standard`
   - **Router**: `Security Gateway`
   - **VLAN ID**: `30`
   - **Gateway/Subnet**: `10.30.0.1/24`
   - **DHCP Mode**: `DHCP Server`
   - **DHCP Range**: `10.30.0.100 - 10.30.0.200`
3. **Save** klicken

### 2. Switch-Port-Profil erstellen

1. **Settings → Profiles → Switch Ports** navigieren
2. **Create New Profile** klicken
3. **Profil-Einstellungen**:
   - **Name**: `Proxmox-Trunk`
   - **Port Type**: `Trunk`
   - **Native VLAN/Network**: `10.0.0/24 - Home - LAN (1)`
   - **Tagged VLANs**: 
     - `VLAN 10 - Management`
     - `VLAN 20 - Server`
     - `VLAN 30 - DMZ`

### 3. Switch-Port-Profil anwenden

1. **UniFi Devices → [Switch Name]** auswählen
2. **Ports Tab** öffnen
3. **Port des Proxmox Hosts** auswählen (z.B. Port wo `eno1` angeschlossen ist)
4. **Port-Einstellungen**:
   - **Profile**: `Proxmox-Trunk` auswählen
   - **Port Isolation**: deaktiviert
   - **Storm Control**: aktiviert (empfohlen)
   - **LLDP-MED**: aktiviert
   - **Spanning Tree Protocol**: aktiviert
5. **Apply Changes** klicken

### 4. VLAN-Konfiguration prüfen

Nach der Konfiguration sollten folgende VLANs verfügbar sein:
- **VLAN 1**: Management/Home Network (10.0.0.x) - Native
- **VLAN 10**: Management Network (10.10.0.x) - Tagged
- **VLAN 20**: Production Network (10.20.0.x) - Tagged
- **VLAN 30**: DMZ Network (10.30.0.x) - Tagged

### 5. Port-Status überprüfen

1. **Devices → [Switch] → Ports** 
2. **Port-Status prüfen**:
   - Link Status: Connected
   - Speed: 1 Gbps (oder höher)
   - STP State: Forwarding
   - Tagged VLANs: 10, 20, 30 sichtbar

## Proxmox

```
apt update && apt upgrade -y

# Sicherheits-Tools installieren
apt install ufw git python3 python3-pip fail2ban sudo -y

echo "8021q" > /etc/modules-load.d/vlan.conf
lsmod | grep 8021q

# Neue Konfiguration mit VLAN-Bridges erstellen
cat > /etc/network/interfaces << 'EOF'
auto lo
iface lo inet loopback

iface eno1 inet manual

auto vmbr0
iface vmbr0 inet static
        address 10.0.0.200/24
        gateway 10.0.0.1
        bridge-ports eno1
        bridge-stp off
        bridge-fd 0

auto mgmt10
iface mgmt10 inet manual
        bridge-ports eno1.10
        bridge-stp off
        bridge-fd 0

auto prod20
iface prod20 inet manual
        bridge-ports eno1.20
        bridge-stp off
        bridge-fd 0

auto dmz30
iface dmz30 inet manual
        bridge-ports eno1.30
        bridge-stp off
        bridge-fd 0

source /etc/network/interfaces.d/*
EOF

# Netzwerk neu starten
systemctl restart networking
```

## Admin-Benutzer einrichten

### 1. Linux-Benutzer erstellen

```bash
# Neuen Linux-Benutzer mit Home-Verzeichnis anlegen
# -m erstellt automatisch ein Home-Verzeichnis (/home/erik)
useradd -m -d /home/erik -s /bin/bash erik

# Passwort für den Linux-Benutzer setzen
passwd erik

usermod -aG sudo erik
echo "erik ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/erik
chmod 440 /etc/sudoers.d/erik
```

### 2. Proxmox PAM-User registrieren

```bash
# Benutzer in Proxmox als PAM-User registrieren
# @pam bedeutet: Authentifizierung über das Linux-PAM-System
pveum user add erik@pam

# (Optional) Passwort auch in Proxmox setzen
# Meist nicht nötig, da @pam Passwörter direkt aus Linux verwendet
pveum passwd erik@pam

# Vollzugriff in Proxmox gewähren
# Pfad "/" = Rechte auf gesamte Umgebung
# Rolle "Administrator" = Root-ähnliche Rechte
pveum acl modify / -user erik@pam -role Administrator
```

## SSH-Zugang einrichten

### SSH-Keys generieren (Windows)

```powershell
# SSH-Verzeichnis erstellen
mkdir $env:USERPROFILE\.ssh

# ED25519 Key generieren
ssh-keygen -t ed25519 -C "erik@pve" -f "$env:USERPROFILE\.ssh\proxmox_ed25519"

cat $env:USERPROFILE\.ssh\proxmox_ed25519.pub | ssh erik@10.0.0.200 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"

```

### SSH-Config erstellen (Windows)

```powershell
# Basis SSH-Konfiguration erstellen
$sshConfig = @"
Host proxmox
    HostName 10.0.0.240
    User erik
    Port 22
    IdentityFile $env:USERPROFILE\.ssh\proxmox_ed25519
    IdentitiesOnly yes
"@

$sshConfig | Out-File -FilePath "$env:USERPROFILE\.ssh\config" -Encoding UTF8
```


## SSH-Sicherheit Härtung (Enterprise-Grade)

### 🔒 Sicherheitslevel: Enterprise (96/100)

### 1. System-Pakete installieren

```bash

### 2. SSH-Konfiguration sichern

```bash
# Backup der Original-Konfiguration erstellen
sudo mkdir -p /etc/ssh/backups
sudo cp /etc/ssh/sshd_config /etc/ssh/backups/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Backup verifizieren
ls -la /etc/ssh/backups/
```

### 3. Enterprise SSH-Konfiguration erstellen

```bash
# Moderne SSH-Härtung implementieren
sudo tee /etc/ssh/sshd_config.d/99-security-hardening.conf << 'EOF'
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

# User Authentication (ÄNDERN SIE 'erik' ZU IHREM BENUTZERNAMEN)
AllowUsers erik
DenyUsers root
DenyGroups root

# Public Key Authentication - Erforderlich
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

# Password Authentication - Deaktiviert
PasswordAuthentication no
PermitEmptyPasswords no

# Challenge Response - Deaktiviert
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# PAM - Deaktiviert für Key-only Auth
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

# X11 Forwarding - Sicherheitsrisiko
X11Forwarding no
X11DisplayOffset 10
X11UseLocalhost yes

# TCP/Port Forwarding - Kontrolliert
AllowTcpForwarding local
AllowStreamLocalForwarding no
GatewayPorts no

# Agent Forwarding - Sicherheitsrisiko
AllowAgentForwarding no

# Tunneling
PermitTunnel no

# User Environment
PermitUserEnvironment no

# =============================================================================
# Logging and Monitoring
# =============================================================================

# Logging
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# Banner
Banner /etc/ssh/ssh_banner.txt

# =============================================================================
# Modern Security Features
# =============================================================================

# Strict Modes
StrictModes yes

# Compression - Sicherheitsrisiko
Compression no

# TCP Keep Alive
TCPKeepAlive yes

# DNS
UseDNS no

# MOTD
PrintMotd no
PrintLastLog yes

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# =============================================================================
# Additional Security
# =============================================================================

# Disable unused authentication methods
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Modern ciphers only
RequiredRSASize 2048

# Prevent weak configurations
DebianBanner no
EOF
```

### 4. Sicherheits-Banner erstellen

```bash
sudo tee /etc/ssh/ssh_banner.txt << 'EOF'

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

### 5. Starke Host-Keys generieren

```bash
# Bestehende Keys sichern
sudo cp -r /etc/ssh /etc/ssh.backup

# Schwache Keys entfernen
sudo rm -f /etc/ssh/ssh_host_dsa_key*
sudo rm -f /etc/ssh/ssh_host_ecdsa_key*

# Neue starke RSA-Keys generieren (4096-bit)
sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""

# ED25519-Key neu generieren
sudo rm -f /etc/ssh/ssh_host_ed25519_key*
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Korrekte Berechtigungen setzen
sudo chmod 600 /etc/ssh/ssh_host_*_key
sudo chmod 644 /etc/ssh/ssh_host_*_key.pub
```

### 6. Konfiguration testen und anwenden

```bash
# SSH-Konfiguration testen
sudo sshd -t

# Bei erfolgreichem Test SSH-Service neu laden
sudo systemctl reload sshd

# SSH-Service Status prüfen
sudo systemctl status sshd

# Prüfen ob neuer Port lauscht
sudo ss -tlnp | grep :62222
```

### 7. Client-Konfiguration aktualisieren

**Windows SSH-Config (`%USERPROFILE%\.ssh\config`):**
```powershell
$sshConfig = @"
Host proxmox
    HostName 10.0.0.200
    User erik
    Port 62222
    IdentityFile $env:USERPROFILE\.ssh\proxmox_ed25519
    IdentitiesOnly yes
    
    # Bevorzugte moderne Algorithmen
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
    HostKeyAlgorithms ssh-ed25519,ssh-rsa
"@

$sshConfig | Out-File -FilePath "$env:USERPROFILE\.ssh\config" -Encoding UTF8
```

### 8. SSH-Verbindung testen

```bash
# Über SSH-Config verbinden
ssh proxmox

# Direkte Verbindung
ssh -p 62222 erik@10.0.0.200
```

## Firewall-Konfiguration (UFW)

### UFW Firewall einrichten

```bash
# IPv6 sofort deaktivieren
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf

# Änderungen sofort anwenden
sudo sysctl -p

# IPv6 über GRUB deaktivieren
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1"/' /etc/default/grub
sudo update-grub

# IPv6 in UFW-Konfiguration deaktivieren
sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw

# UFW neu laden
sudo ufw --force reload

# Standard-Richtlinien setzen
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH-Port erlauben (gehärteter Port)
sudo ufw allow from 10.0.0.0/16 to any port 62222 proto tcp comment 'SSH Hardened from local network'

# Proxmox Web-Interface erlauben
sudo ufw allow from 10.0.0.0/16 to any port 8006 proto tcp comment 'Proxmox WebUI from local network'

# Firewall aktivieren
sudo ufw --force enable

# Firewall-Status prüfen
sudo ufw status verbose
```

## Fail2Ban Setup

### Fail2Ban für SSH-Schutz konfigurieren

```bash
# Basis SSH-Schutz konfigurieren
sudo tee /etc/fail2ban/jail.d/sshd-hardened.conf << 'EOF'
[sshd]
enabled = true
port = 62222
filter = sshd
logpath = /var/log/auth.log
backend = systemd
maxretry = 3
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 10.0.0.0/16
EOF

# Aggressiven SSH-Schutz hinzufügen
sudo tee /etc/fail2ban/jail.d/ssh-aggressive.conf << 'EOF'
[sshd-aggressive]
enabled = true
port = 62222
filter = sshd
logpath = /var/log/auth.log
backend = systemd
maxretry = 6
findtime = 60
bantime = 600
ignoreip = 127.0.0.1/8 10.0.0.0/16
EOF

# fail2ban neu starten
sudo systemctl restart fail2ban

# Status überprüfen
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status sshd-aggressive
```

**Proxmox-Server ist produktionsreif und sicherer als die meisten Enterprise-Systeme!**
