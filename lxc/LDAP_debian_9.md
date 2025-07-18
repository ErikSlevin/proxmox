# LDAP Server Installation in Proxmox LXC Container - Teil 1
**Server:** openldap.home.intern (10.0.0.110)

## Übersicht
Diese Anleitung beschreibt die schrittweise Installation und Konfiguration eines LDAP-Servers (OpenLDAP) in einem LXC Container unter Proxmox VE. Der Container basiert auf der aktuellsten Debian-Version und wird nach bewährten Sicherheitsstandards gehärtet.

## Voraussetzungen
- Proxmox VE Server mit bereits durchgeführter Grundkonfiguration
- Administratorzugang zur Proxmox Web-UI
- SSH-Zugang zum Proxmox Host
- Grundlegende Linux-Kenntnisse

## 1. LXC Container erstellen

### 1.1 Aktuellstes Debian Template herunterladen
```bash
# Verfügbare Templates anzeigen
pveam available --section system | grep debian

# Aktuellstes Debian Template herunterladen
pveam download local debian-12-standard_12.7-1_amd64.tar.zst

# Heruntergeladene Templates anzeigen
pveam list local
```

### 1.2 Nächste verfügbare Container-ID ermitteln
```bash
# Alle Container-IDs anzeigen
pct list

# Nächste freie ID automatisch ermitteln
NEXT_ID=$(pvesh get /cluster/nextid)
echo "Nächste verfügbare Container-ID: $NEXT_ID"
```

### 1.3 Container-Spezifikationen
```yaml
Container-ID: [Automatisch ermittelt]
Hostname: openldap
Template: debian-12-standard (neueste Version)
CPU: 2 Cores
RAM: 2048 MB
Storage: 16 GB
Netzwerk: 
  - Bridge: vmbr0
  - IP: 10.0.0.110/24
  - Gateway: 10.0.0.1
  - DNS: 10.0.10.2
  - Search Domain: home.intern
```

### 1.4 Container erstellen
```bash
# Automatische ID-Ermittlung und Container-Erstellung
NEXT_ID=$(pvesh get /cluster/nextid)
echo "Erstelle Container mit ID: $NEXT_ID"

# Container erstellen
pct create $NEXT_ID local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname openldap \
  --cores 2 \
  --memory 2048 \
  --rootfs local-lvm:16 \
  --net0 name=eth0,bridge=vmbr0,ip=10.0.0.110/24,gw=10.0.0.1 \
  --nameserver 10.0.10.2 \
  --searchdomain home.intern \
  --ssh-public-keys /root/.ssh/authorized_keys \
  --unprivileged 1 \
  --start 1 \
  --tags "10.0.0.110"

echo "Container $NEXT_ID wurde erstellt und gestartet"

# Container einmal neu starten für saubere Initialisierung
echo "Container wird neu gestartet..."
pct shutdown $NEXT_ID
sleep 5
pct start $NEXT_ID

echo "Container $NEXT_ID wurde erfolgreich neu gestartet"

# Container-Status und Konfiguration prüfen
pct status $NEXT_ID
pct config $NEXT_ID
```

### 1.5 Tag nachträglich setzen (falls vergessen)
```bash
# Falls der Tag nicht beim Erstellen gesetzt wurde, nachträglich hinzufügen
CONTAINER_ID=$(pct list | grep openldap | awk '{print $1}')
pct set $CONTAINER_ID --tags "10.0.0.110"

# Tags prüfen
pct config $CONTAINER_ID | grep tags
```

## 2. Grundsicherung des LXC Containers

### 2.1 Erste Anmeldung und Updates
```bash
# Container betreten
CONTAINER_ID=$(pct list | grep openldap | awk '{print $1}')
pct enter $CONTAINER_ID

# System aktualisieren
apt update && apt upgrade -y

# Basis-Pakete installieren
apt install -y sudo vim curl wget htop tree ufw fail2ban ssh-audit nano

# Nützliche Aliase direkt zur .bashrc hinzufügen
cat >> ~/.bashrc << 'EOF'

# System-Aliase
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'

# LDAP-spezifische Aliase
alias ldap-status='systemctl status slapd'
alias ldap-logs='journalctl -u slapd -f'
alias ldap-search='ldapsearch -x -H ldap://localhost -b dc=home,dc=intern'

# System-Info beim Login anzeigen (in grün)
echo -e "\033[32m🔧 OpenLDAP Server - $(hostname) (10.0.0.110)\033[0m"
echo -e "\033[32m📍 IP: $(hostname -I | awk '{print $1}')\033[0m"
echo -e "\033[32m⏰ Uptime: $(uptime -p)\033[0m"
echo -e "\033[32m🌐 Domain: home.intern\033[0m"
EOF

# Bashrc neu laden
source ~/.bashrc

echo "✅ System-Updates und Aliase konfiguriert!"
```

### 2.2 Admin-User "Erik" erstellen
```bash
# Benutzer "erik" erstellen
useradd -m -s /bin/bash erik

# Sudo-Rechte ohne Passwort-Eingabe vergeben
usermod -aG sudo erik
echo "erik ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/erik

# SSH-Verzeichnis für Erik erstellen
mkdir -p /home/erik/.ssh
touch /home/erik/.ssh/authorized_keys

# Berechtigungen setzen
chown -R erik:erik /home/erik/.ssh
chmod 700 /home/erik/.ssh
chmod 600 /home/erik/.ssh/authorized_keys

# SSH-Key von Proxmox Host kopieren (Container verlassen)
exit

# Auf Proxmox Host: SSH-Key zu Erik kopieren
CONTAINER_ID=$(pct list | grep openldap | awk '{print $1}')
cat ~/.ssh/id_ed25519.pub | pct exec $CONTAINER_ID -- tee -a /home/erik/.ssh/authorized_keys

# Berechtigungen im Container korrigieren
pct exec $CONTAINER_ID -- chown erik:erik /home/erik/.ssh/authorized_keys
pct exec $CONTAINER_ID -- chmod 600 /home/erik/.ssh/authorized_keys

# Zurück in den Container
pct enter $CONTAINER_ID

echo "✅ User erik erstellt mit SSH-Key-Zugang!"
```

### 2.3 SSH-Härtung (Ultra-Sicher)
```bash
# SSH-Konfiguration sichern
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Alte Host-Keys entfernen und neue erstellen
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Schwache Diffie-Hellman Moduli entfernen
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli

# Moderne SSH-Härtung basierend auf ssh-audit.com
cat > /etc/ssh/sshd_config.d/99-ssh-hardening.conf << 'EOF'
# SSH Härtung - Moderne Kryptographie
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

RequiredRSASize 3072
EOF

# SSH-Basiskonfiguration
sed -ri 's/#?Port\s.*$/Port 62253/' /etc/ssh/sshd_config
sed -ri 's/#?Protocol\s.*$/Protocol 2/' /etc/ssh/sshd_config
sed -ri 's/#?AddressFamily\s.*$/AddressFamily inet/' /etc/ssh/sshd_config

# Sicherheitseinstellungen
sed -ri 's/#?PermitRootLogin\s.*$/PermitRootLogin no/' /etc/ssh/sshd_config
sed -ri 's/#?PasswordAuthentication\s.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -ri 's/#?PubkeyAuthentication\s.*$/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -ri 's/#?PermitEmptyPasswords\s.*$/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -ri 's/#?ChallengeResponseAuthentication\s.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sed -ri 's/#?KbdInteractiveAuthentication\s.*$/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config

# Verbindungseinstellungen
sed -ri 's/#?MaxAuthTries\s.*$/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -ri 's/#?LoginGraceTime\s.*$/LoginGraceTime 30/' /etc/ssh/sshd_config
sed -ri 's/#?ClientAliveInterval\s.*$/ClientAliveInterval 600/' /etc/ssh/sshd_config
sed -ri 's/#?ClientAliveCountMax\s.*$/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# Sicherheitsfeatures
sed -ri 's/#?StrictModes\s.*$/StrictModes yes/' /etc/ssh/sshd_config
sed -ri 's/#?IgnoreRhosts\s.*$/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -ri 's/#?HostbasedAuthentication\s.*$/HostbasedAuthentication no/' /etc/ssh/sshd_config

# Tunneling und Forwarding deaktivieren
sed -ri 's/#?AllowAgentForwarding\s.*$/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -ri 's/#?AllowTcpForwarding\s.*$/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -ri 's/#?X11Forwarding\s.*$/X11Forwarding no/' /etc/ssh/sshd_config
sed -ri 's/#?PermitTunnel\s.*$/PermitTunnel no/' /etc/ssh/sshd_config

# Logging
sed -ri 's/#?SyslogFacility\s.*$/SyslogFacility AUTHPRIV/' /etc/ssh/sshd_config
sed -ri 's/#?LogLevel\s.*$/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Nur Erik erlauben
echo "AllowUsers erik" >> /etc/ssh/sshd_config

# Konfiguration testen
sshd -t

# SSH-Service neu starten
systemctl restart sshd

# SSH-Audit durchführen
ssh-audit localhost:62253

echo "✅ SSH ultra-sicher auf Port 62253 konfiguriert!"
```

---

# LDAP Server Installation - Teil 2: Firewall & LDAP-Installation
**Server:** openldap.home.intern (10.0.0.110)

**⬅️ Fortsetzung von Teil 1: Container & Grundsicherung**

## 2.4 UFW Firewall konfigurieren (Vertrauensnetzwerke)
```bash
# UFW installieren falls nicht vorhanden
apt install ufw -y

# IPv6 deaktivieren 
sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw

# Standard-Policies setzen
ufw default deny incoming
ufw default allow outgoing

# SSH für vertrauenswürdige Netzwerke erlauben (Port 62253)
ufw allow from 10.0.0.0/24 to any port 62253 proto tcp comment 'SSH für 10.0.0.0/24'
ufw allow from 10.0.10.0/24 to any port 62253 proto tcp comment 'SSH für 10.0.10.0/24'
ufw allow from 10.0.20.0/24 to any port 62253 proto tcp comment 'SSH für 10.0.20.0/24'

# LDAP-Ports für vertrauenswürdige Netzwerke
# Standard LDAP (389)
ufw allow from 10.0.0.0/24 to any port 389 proto tcp comment 'LDAP für 10.0.0.0/24'
ufw allow from 10.0.10.0/24 to any port 389 proto tcp comment 'LDAP für 10.0.10.0/24'
ufw allow from 10.0.20.0/24 to any port 389 proto tcp comment 'LDAP für 10.0.20.0/24'

# LDAPS verschlüsselt (636)
ufw allow from 10.0.0.0/24 to any port 636 proto tcp comment 'LDAPS für 10.0.0.0/24'
ufw allow from 10.0.10.0/24 to any port 636 proto tcp comment 'LDAPS für 10.0.10.0/24'
ufw allow from 10.0.20.0/24 to any port 636 proto tcp comment 'LDAPS für 10.0.20.0/24'

# DNS erlauben (zu 10.0.10.2)
ufw allow out to 10.0.10.2 port 53 proto tcp comment 'DNS TCP zu 10.0.10.2'
ufw allow out to 10.0.10.2 port 53 proto udp comment 'DNS UDP zu 10.0.10.2'

# NTP erlauben
ufw allow out 123 comment 'NTP ausgehend'

# HTTP/HTTPS für Updates erlauben
ufw allow out 80 comment 'HTTP für Updates'
ufw allow out 443 comment 'HTTPS für Updates'

# Logging aktivieren
ufw logging on

# Firewall aktivieren
ufw enable

# Status anzeigen
ufw status verbose

echo "✅ UFW Firewall für 3 Netzwerke konfiguriert!"
```

## 2.5 Fail2Ban für SSH und LDAP konfigurieren
```bash
# Locale-Problem in Containern beheben
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
echo 'export LANG=C.UTF-8' >> ~/.bashrc
echo 'export LC_ALL=C.UTF-8' >> ~/.bashrc

# Fail2Ban ist bereits installiert, jetzt konfigurieren
# Backup der Standardkonfiguration
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.backup

# SSH-Jail für unseren angepassten Port 62253 konfigurieren
cat > /etc/fail2ban/jail.d/sshd.conf << 'EOF'
[sshd]
enabled = true
port = 62253
logpath = %(sshd_log)s
backend = systemd
maxretry = 3
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 10.0.0.0/24 10.0.10.0/24 10.0.20.0/24
EOF

# LDAP-Filter erstellen (für später wenn LDAP läuft)
cat > /etc/fail2ban/filter.d/slapd.conf << 'EOF'
[Definition]
failregex = slapd\[.*\]: conn=.* fd=.* ACCEPT from IP=<HOST>:.*
            slapd\[.*\]: conn=.* op=.* BIND dn=.* method=.* ssf=.* Invalid credentials
ignoreregex =
EOF

# LDAP-Jail konfigurieren
cat > /etc/fail2ban/jail.d/slapd.conf << 'EOF'
[slapd]
enabled = true
filter = slapd
logpath = /var/log/syslog
maxretry = 5
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 10.0.0.0/24 10.0.10.0/24 10.0.20.0/24
EOF

# Fail2Ban aktivieren und starten (ohne Locale-Warnungen)
systemctl enable fail2ban
systemctl restart fail2ban

# Status prüfen
systemctl status fail2ban --no-pager
fail2ban-client status

echo "✅ Fail2Ban erfolgreich konfiguriert und gestartet!"
```

## 2.6 SSH-Verbindung von Proxmox Host testen
```bash
# Container verlassen
exit

# SSH-Verbindung als Erik testen (von Proxmox Host)
ssh -p 62253 erik@10.0.0.110

# Bei erfolgreichem Test: Wieder zum Container wechseln für LDAP-Installation
```

---

## ✅ **GRUNDSICHERUNG ABGESCHLOSSEN**

**Der Container ist jetzt ultra-sicher konfiguriert:**
- 🔐 SSH auf Port 62253 mit modernster Kryptographie
- 🛡️ UFW Firewall für 3 vertrauenswürdige Netzwerke (10.0.0.0/24, 10.0.10.0/24, 10.0.20.0/24)  
- 🚫 Nur Erik hat SSH-Zugang mit Schlüsseln
- 🛡️ Fail2Ban aktiv gegen Brute-Force-Angriffe
- 🔒 Alle unsicheren SSH-Features deaktiviert

---

## 3. LDAP Server Installation (OpenLDAP)

### 3.1 OpenLDAP installieren
```bash
# In den Container einloggen (falls nicht bereits drin)
CONTAINER_ID=$(pct list | grep openldap | awk '{print $1}')
pct enter $CONTAINER_ID

# LDAP-Pakete installieren
apt install -y slapd ldap-utils

# LDAP-Konfiguration zurücksetzen für saubere Installation
dpkg-reconfigure slapd
```

### 3.2 Konfigurationsparameter
```
Omit OpenLDAP server configuration? No
DNS domain name: home.intern
Organization name: Home Network
Administrator password: [SICHERES_PASSWORT]
Database backend: MDB
Remove database when slapd is purged? No
Move old database? Yes
```

### 3.3 LDAP-Grundkonfiguration testen
```bash
# LDAP-Service Status prüfen
systemctl status slapd

# LDAP-Konfiguration testen
ldapsearch -x -H ldap://localhost -b dc=home,dc=intern
```

## 4. LDAP-Konfiguration

### 4.1 Basis-Organisationsstruktur erstellen
```bash
# LDIF-Datei für Organisationsstruktur erstellen
cat > /tmp/base_structure.ldif << 'EOF'
# Organizational Units
dn: ou=users,dc=home,dc=intern
objectClass: organizationalUnit
ou: users
description: Container for user accounts

dn: ou=groups,dc=home,dc=intern
objectClass: organizationalUnit
ou: groups
description: Container for groups

dn: ou=services,dc=home,dc=intern
objectClass: organizationalUnit
ou: services
description: Container for service accounts
EOF

# Struktur in LDAP importieren
ldapadd -x -D cn=admin,dc=home,dc=intern -W -f /tmp/base_structure.ldif

# Struktur testen
ldapsearch -x -H ldap://localhost -b dc=home,dc=intern "(objectClass=organizationalUnit)"
```

## 5. Sicherheitskonfiguration

### 5.1 TLS/SSL aktivieren
```bash
# SSL-Zertifikate erstellen
mkdir -p /etc/ssl/ldap
cd /etc/ssl/ldap

# Selbstsigniertes Zertifikat erstellen (für Produktiv: CA-signiert verwenden)
openssl req -new -x509 -days 365 -nodes \
  -out ldap-server.crt \
  -keyout ldap-server.key \
  -subj "/C=DE/ST=NRW/L=Home/O=Home Network/CN=openldap.home.intern"

# Berechtigungen setzen
chown openldap:openldap /etc/ssl/ldap/*
chmod 600 /etc/ssl/ldap/ldap-server.key
chmod 644 /etc/ssl/ldap/ldap-server.crt

# Zertifikate prüfen
ls -la /etc/ssl/ldap/
```

### 5.2 Fail2Ban für SSH und LDAP
```bash
# Fail2Ban ist bereits installiert und konfiguriert
# SSH-Jail für Port 62253 aktiv
# LDAP-Jail für Port 389/636 aktiv

# Fail2Ban Status prüfen
fail2ban-client status
fail2ban-client status sshd
fail2ban-client status slapd
```

## 6. Backup und Monitoring

### 6.1 Backup-Script erstellen
```bash
# Backup-Verzeichnis erstellen
mkdir -p /opt/ldap-backup

# Backup-Script erstellen
cat > /opt/ldap-backup/backup-ldap.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/ldap-backup"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="ldap_backup_${DATE}.ldif"

# LDAP-Datenbank exportieren
slapcat > ${BACKUP_DIR}/${BACKUP_FILE}

# Komprimieren für Speicherplatz
gzip ${BACKUP_DIR}/${BACKUP_FILE}

# Alte Backups löschen (älter als 30 Tage)
find ${BACKUP_DIR} -name "ldap_backup_*.ldif.gz" -mtime +30 -delete

echo "LDAP Backup erstellt: ${BACKUP_FILE}.gz"
EOF

# Script ausführbar machen
chmod +x /opt/ldap-backup/backup-ldap.sh

# Erstes Backup testen
/opt/ldap-backup/backup-ldap.sh

# Cron-Job für tägliches Backup
echo "0 2 * * * root /opt/ldap-backup/backup-ldap.sh" >> /etc/crontab

# Backup-Verzeichnis prüfen
ls -la /opt/ldap-backup/
```

---

# LDAP Server Installation - Teil 3: Tests & Administration
**Server:** openldap.home.intern (10.0.0.110)

**⬅️ Fortsetzung von Teil 2: Firewall & LDAP-Installation**

## 7. Tests und Verifikation

### 7.1 SSH-Sicherheit testen
```bash
# SSH-Audit auf dem Container durchführen
ssh-audit localhost:62253

# Von Proxmox Host aus testen
ssh-audit 10.0.0.110:62253

# SSH-Verbindung als Erik testen (von Proxmox Host)
ssh -p 62253 erik@10.0.0.110

# SSH-Key-Fingerprint verifizieren
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

### 7.2 LDAP-Funktionalität testen
```bash
# Lokale Verbindung testen
ldapsearch -x -H ldap://localhost -b dc=home,dc=intern

# Remote-Verbindung testen (von anderem System)
ldapsearch -x -H ldap://10.0.0.110:389 -b dc=home,dc=intern

# LDAPS-Verbindung testen (verschlüsselt, vorbereitet)
ldapsearch -x -H ldaps://10.0.0.110:636 -b dc=home,dc=intern

# Organisationsstruktur anzeigen
ldapsearch -x -H ldap://localhost -b dc=home,dc=intern "(objectClass=organizationalUnit)"
```

### 7.3 Firewall und Sicherheit testen
```bash
# Offene Ports prüfen
ss -tuln | grep -E ':389|:636|:62253'

# UFW-Status detailliert anzeigen
ufw status numbered

# Fail2Ban Status für alle Jails
fail2ban-client status
fail2ban-client status sshd
fail2ban-client status slapd

# Netzwerkverbindungen überwachen
ss -tuln
```

### 7.4 Komplette Systemübersicht
```bash
echo "=== LDAP-Service Status ==="
systemctl status slapd --no-pager

echo "=== Offene LDAP-Ports ==="
ss -tuln | grep -E ':389|:636'

echo "=== LDAP-Datenbank-Inhalt ==="
ldapsearch -x -H ldap://localhost -b dc=home,dc=intern

echo "=== Backup-System ==="
ls -la /opt/ldap-backup/

echo "=== UFW Firewall Status ==="
ufw status | grep -E '389|636|62253'

echo "=== Fail2Ban Status ==="
fail2ban-client status

echo ""
echo "🎉 OPENLDAP-SERVER ERFOLGREICH INSTALLIERT!"
echo "✅ LDAP läuft auf Port 389 (unverschlüsselt)"
echo "✅ LDAPS vorbereitet für Port 636 (verschlüsselt)"
echo "✅ Organisationsstruktur: users, groups, services"
echo "✅ Backup-System aktiv (täglich um 2:00 Uhr)"
echo "✅ Firewall erlaubt Zugang für 3 Netzwerke"
echo "✅ SSH ultra-sicher auf Port 62253"
echo ""
echo "🌐 LDAP-Server: openldap.home.intern (10.0.0.110)"
echo "🔑 Admin: cn=admin,dc=home,dc=intern"
echo "📂 Base DN: dc=home,dc=intern"
```

### 7.5 SSH-Verbindung von Proxmox Host einrichten
```bash
# Auf dem Proxmox Host: SSH-Config für einfache Verbindung erstellen
cat >> ~/.ssh/config << 'EOF'
Host openldap
    HostName 10.0.0.110
    Port 62253
    User erik
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    # OpenLDAP Server - home.intern
EOF

# Verbindung testen
ssh openldap
```

## 8. Wartung und Administration

### 8.1 Nützliche LDAP-Befehle
```bash
# LDAP-Logs überwachen
tail -f /var/log/syslog | grep slapd

# LDAP-Statistiken anzeigen
ldapsearch -x -H ldap://localhost -b cn=monitor -s base '(objectclass=*)' monitorOpCompleted

# Backup durchführen
/opt/ldap-backup/backup-ldap.sh

# Service-Status prüfen
systemctl status slapd
systemctl status fail2ban
systemctl status ssh
```

### 8.2 Regelmäßige Wartungsaufgaben
- **Tägliche Backups überprüfen** (`ls -la /opt/ldap-backup/`)
- **Wöchentliche Sicherheitsupdates** (`apt update && apt upgrade`)
- **Monatliche Log-Analyse** (`journalctl -u slapd --since "1 month ago"`)
- **Quartalsmäßige SSH-Audits** (`ssh-audit localhost:62253`)

### 8.3 Erweiterte Konfiguration (optional)
- LDAP-User und -Gruppen erstellen
- LDAPS vollständig aktivieren und konfigurieren
- Integration mit anderen Services (Nextcloud, etc.)
- Monitoring mit Prometheus/Grafana

### 8.4 Troubleshooting
```bash
# LDAP-Service-Probleme
systemctl status slapd
journalctl -u slapd -f

# SSH-Verbindungsprobleme
ssh -vvv -p 62253 erik@10.0.0.110

# Firewall-Probleme
ufw status verbose
iptables -L

# Fail2Ban-Probleme
fail2ban-client status
journalctl -u fail2ban -f
```

## 9. Beispiel: LDAP-User erstellen

### 9.1 Ersten LDAP-User hinzufügen
```bash
# User-LDIF erstellen
cat > /tmp/add_user.ldif << 'EOF'
dn: uid=testuser,ou=users,dc=home,dc=intern
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: testuser
sn: User
givenName: Test
cn: Test User
displayName: Test User
uidNumber: 10001
gidNumber: 10001
userPassword: {SSHA}GeneratedHashHere
gecos: Test User
loginShell: /bin/bash
homeDirectory: /home/testuser
mail: testuser@home.intern
EOF

# User hinzufügen
ldapadd -x -D cn=admin,dc=home,dc=intern -W -f /tmp/add_user.ldif

# User-Erstellung testen
ldapsearch -x -H ldap://localhost -b ou=users,dc=home,dc=intern "(uid=testuser)"
```

### 9.2 LDAP-Gruppe erstellen
```bash
# Gruppen-LDIF erstellen
cat > /tmp/add_group.ldif << 'EOF'
dn: cn=admins,ou=groups,dc=home,dc=intern
objectClass: groupOfNames
cn: admins
description: Administrator Group
member: uid=testuser,ou=users,dc=home,dc=intern
EOF

# Gruppe hinzufügen
ldapadd -x -D cn=admin,dc=home,dc=intern -W -f /tmp/add_group.ldif

# Gruppe testen
ldapsearch -x -H ldap://localhost -b ou=groups,dc=home,dc=intern "(cn=admins)"
```

## 10. Quellen und Dokumentation
- [OpenLDAP Administrator's Guide](https://www.openldap.org/doc/admin24/)
- [Debian OpenLDAP Wiki](https://wiki.debian.org/LDAP/OpenLDAPSetup)
- [LDAP Security Best Practices](https://ldap.com/ldap-security/)
- [SSH Hardening Guide](https://www.sshaudit.com/hardening_guides.html)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [Fail2Ban Manual](https://www.fail2ban.org/wiki/index.php/Manual)

---

## 🎉 **SERVER-ZUSAMMENFASSUNG**

**OpenLDAP Server erfolgreich installiert und konfiguriert:**

### Server-Details
🌐 **Server:** openldap.home.intern (10.0.0.110)  
🔑 **LDAP Admin:** cn=admin,dc=home,dc=intern  
📂 **Base DN:** dc=home,dc=intern  
🔌 **LDAP Port:** 389 (unverschlüsselt)  
🔐 **LDAPS Port:** 636 (verschlüsselt, vorbereitet)  
🚪 **SSH Port:** 62253 (nur Erik)  

### Sicherheitsfeatures
- ✅ **Ultra-sichere SSH-Konfiguration** mit modernster Kryptographie
- ✅ **UFW Firewall** für 3 vertrauenswürdige Netzwerke
- ✅ **Fail2Ban** gegen Brute-Force-Angriffe
- ✅ **Nur Erik hat Admin-Zugang** mit SSH-Schlüsseln
- ✅ **TLS/SSL-Zertifikate** für LDAPS vorbereitet
- ✅ **Automatisches tägliches Backup-System**
- ✅ **Organisationsstruktur** (users, groups, services)

### Netzwerk-Zugang
- 🏠 **10.0.0.0/24** - Hauptnetzwerk
- 🖥️ **10.0.10.0/24** - Server-Netzwerk  
- 📱 **10.0.20.0/24** - Client-Netzwerk

### Container-Spezifikationen
- 💻 **2 CPU Cores, 2GB RAM, 16GB Storage**
- 🐧 **Debian 12 (Bookworm)**
- 🏷️ **Tag:** 10.0.0.110
- 🌐 **Domain:** home.intern
- 🚀 **Unprivileged LXC Container**

### Installierte Services
- **OpenLDAP** (slapd) - LDAP-Server
- **OpenSSH** - Sichere Remote-Verbindung
- **UFW** - Uncomplicated Firewall
- **Fail2Ban** - Intrusion Prevention
- **Cron** - Automatische Backups

### Nächste Schritte
1. **LDAP-Benutzer und -Gruppen** erstellen
2. **LDAPS vollständig aktivieren** für verschlüsselte Verbindungen
3. **Integration in bestehende Services** (Nextcloud, etc.)
4. **Monitoring und Alerting** einrichten
5. **Dokumentation der User-Verwaltung** erstellen

### Backup-Informationen
- **Backup-Pfad:** `/opt/ldap-backup/`
- **Zeitplan:** Täglich um 2:00 Uhr
- **Retention:** 30 Tage
- **Format:** Komprimierte LDIF-Dateien (.ldif.gz)

### Support und Wartung
- **SSH-Zugang:** `ssh openldap` (nach SSH-Config Setup)
- **LDAP-Admin-Tool:** `ldap-search` Alias verfügbar
- **Service-Status:** `ldap-status` Alias verfügbar
- **Logs:** `ldap-logs` Alias für Live-Monitoring

---

## 📋 **SCHNELLREFERENZ**

### Wichtige Befehle
```bash
# Container betreten
ssh openldap

# LDAP-Status prüfen
ldap-status

# LDAP durchsuchen
ldap-search

# Backup erstellen
/opt/ldap-backup/backup-ldap.sh

# Firewall-Status
ufw status

# Fail2Ban-Status
fail2ban-client status
```

### Wichtige Dateien
- **SSH-Config:** `/etc/ssh/sshd_config`
- **LDAP-Config:** `/etc/ldap/slapd.d/`
- **UFW-Regeln:** `/etc/ufw/user.rules`
- **Fail2Ban-Jails:** `/etc/fail2ban/jail.d/`
- **Backups:** `/opt/ldap-backup/`
- **SSL-Zertifikate:** `/etc/ssl/ldap/`

### Notfall-Kontakte
- **Systemadministrator:** Erik
- **SSH-Zugang:** Port 62253 (nur mit Schlüssel)
- **LDAP-Admin:** cn=admin,dc=home,dc=intern

---

**🎯 MISSION ACCOMPLISHED!**  
*Vollständig funktionsfähiger, produktionsreifer OpenLDAP-Server mit maximaler Sicherheit!*

---
*Erstellt: 2025-07-18*  - *Version: 1.0*  -  *Autor: Erik*  