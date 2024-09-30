# Proxmox Grundkonfiguration 

## 1. Post Install

``` shell
# Post Install Script durchlaufen lassen
bash -c "$(wget -qLO - https://github.com/tteck/Proxmox/raw/main/misc/post-pve-install.sh)"

# Start the Proxmox VE Post Install Script (y/n)?   ->  YES
# Correct Proxmox VE sources?                       ->  YES
# Disable 'pve-enterprise' repository?              ->  YES
# Enable 'pve-no-subscription' repository?          ->  YES
# Correct 'ceph package sources?                    ->  YES
# Add (Disabled) 'pvetest' repository?              ->   NO
# Disable subscription nag?                         ->  YES
# Disable high availability?                        ->  YES
# Update Proxmox VE now?                            ->  YES
# Reboot Proxmox VE now? (recommended)              ->  YES
```

### Quellen
- [`Proxmox VE Helper-Scripts`](https://tteck.github.io/Proxmox/proxmox-ve-post-install)

## 2. NTP-Dienst

```shell
# Anpassen der chrony.conf - Ändern der Zeitserver
nano /etc/chrony/chrony.conf

# NTP neu starten 
systemctl restart chronyd

# Sources überprüfen
chronyc sources -v

# Logs auf Offset überprüfen
journalctl --since -1h -u chrony
chronyc tracking
```

### Verwendete Dateien
- [`chrony.conf`](files/install_config/chrony.conf)

### Quellen
- [`Public Primary (stratum 1) Time Servers`](https://www.advtimesync.com/docs/manual/stratum1.html)

## 3. MODT anpassen

```shell
# issue.net anpassen
nano /etc/issue.net

# MOTD löschen
rm /etc/motd
rm /etc/update-motd.d/10-uname
```
### Verwendete Dateien
- [`issue.net`](files/install_config/issue.net)

## 4. Admin-User erstellen
```shell

# sudo nachinstallieren
apt install sudo -y

# Benutzer "erik" in Debian und Proxmox erstellen (siehe YT Video!)
useradd -m -s /bin/bash erik && pveum user add erik@pam 

# Passwort in Debian und Proxmox vergeben für den Benutzer 
passwd erik && pveum passwd erik@pam

# Benutzer der sudo-Gruppe hinzufügen:
usermod -aG sudo erik

# Admingruppe ersellen und Admin-User aufnehmen
pveum group add admin -comment "System Administrators"
pveum acl modify / -group admin -role Administrator
pveum user modify erik@pam -group admin

# SSH-Verzeichnis erstellen
mkdir -p /home/erik/.ssh

# authorized_keys-Datei anlegen
touch /home/erik/.ssh/authorized_keys

# Berechtigungen setzen:
chown -R erik:erik /home/erik/.ssh    
chmod 700 /home/erik/.ssh            
chmod 600 /home/erik/.ssh/authorized_keys  

# 2FA Authentifizierung aktivieren!
# root FA aktivieren via GUI
# neuer admin user 2FA aktivieren via GUI

```
### Quellen
- [`Youtube: PVE Complete Course Part 9 - User Management`](https://youtu.be/frnILOGmATs?si=T1NyoEUJ5_Q4frDz&t=152)


## 5. SSH-Konfigurieren
```shell
# Installiert pip für Python 3.
apt install ssh-audit -y

# SSH-Security-Scan 
ssh-audit localhost:22

# Re-generate the RSA and ED25519 keys
rm /etc/ssh/ssh_host_*
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli

# Restrict supported key exchange, cipher, and MAC algorithms
echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf

# Generiert einen sicheren SSH-Key (ed25519) - mit y Bestätigen.
ssh-keygen -o -a 100 -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key -C "$(hostname)-$(date -I)"

# Öffentlichen Schlüssel dem root verfügbar machen
cat /etc/ssh/ssh_host_ed25519_key.pub >> ~/.ssh/authorized_keys

# Öffentlichen Schlüssel dem neu erstellten User verfügbar machen
cat /etc/ssh/ssh_host_ed25519_key.pub >> /home/erik/.ssh/authorized_keys

# Privaten Schlüssel anzeigem
cat /etc/ssh/ssh_host_ed25519_key 

# Inhalt im C:\Users\erikw\.ssh in eine neue Datei schreibem
# Dateiname: 20240929-pve-ed25519_key
# In der 8. Zeile muss eine Leerzeile sein und Format LF!!

# Verhindert das anmelden mittels Passwort.
sed -ri 's/#?PasswordAuthentication\s.*$/PasswordAuthentication no/' /etc/ssh/sshd_config

# Erlaubt das anmelden mittels SSH-Schlüsselpaare.
sed -ri 's/#?PubkeyAuthentication\s.*$/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Begrenzt die Authentifizierungsversuche !der Wert hier ist 3, kann angepasst werden.
sed -ri 's/#?MaxAuthTries\s.*$/MaxAuthTries 3/' /etc/ssh/sshd_config

# Einstellungen übernehmen.
systemctl reload sshd

# Wir ändern den Port auf 62253 - ! Kann angepasst werden.
sed -ri 's/#?Port\s.*$/Port 62253/' /etc/ssh/sshd_config

# aktiviert das sicherer Protocol 2.
sed -i '/^.*Port.*/a Protocol 2' /etc/ssh/sshd_config

# lässt nur IPv4 zu. !Kann angepasst werden - "any" (IPv4 & IPv6), "inet" (nur IPv4) oder "inet6" (nur IPv6).
sed -ri 's/#?AddressFamily\s.*$/AddressFamily inet/' /etc/ssh/sshd_config

# Gibt die verfügbaren KEX (Key Exchange)-Algorithmen an.
sed -i '/^.*Ciphers.*/a KexAlgorithms curve25519-sha256@libssh.org' /etc/ssh/sshd_config

# Gibt die verfügbaren MAC-Algorithmen (Message Authentication Code) an.
sed -i '/^.*KexAlgorithms.*/a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-512' /etc/ssh/sshd_config

# Gibt die zulässigen Verschlüsselungen an.
sed -i '/^.*MACs.*/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com' /etc/ssh/sshd_config

# Gibt die vom Server angebotenen Algorithmen für die Schlüsselsignatur des Hosts an.
sed -i '/^.*Ciphers chacha20.*/a HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519' /etc/ssh/sshd_config

# stellt das LogLevel auf "INFO" und das SyslogFacility auf "AUTHPRIV".
sed -ri 's/#?SyslogFacility\s.*$/SyslogFacility AUTHPRIV/' /etc/ssh/sshd_config
sed -ri 's/#?LogLevel\s.*$/LogLevel INFO/' /etc/ssh/sshd_config

# Anmeldezeitraum zur Authentifizierung !Kann angepasst werden.
sed -ri 's/#?LoginGraceTime\s.*$/LoginGraceTime 30/' /etc/ssh/sshd_config

# Verhindert Konfigurationsfehler.
sed -ri 's/#?StrictModes\s.*$/StrictModes yes/' /etc/ssh/sshd_config

# Deaktiviert die hostbasierte Authentifizierung.
sed -ri 's/#?HostbasedAuthentication\s.*$/HostbasedAuthentication no/' /etc/ssh/sshd_config

# Gibt an, dass .rhosts- und .shosts-Dateien nicht verwendet werden.
sed -ri 's/#?IgnoreRhosts\s.*$/IgnoreRhosts yes/' /etc/ssh/sshd_config

# Deaktiviert das einloggen mit leeren Passwörtern.
sed -ri 's/#?PermitEmptyPasswords\s.*$/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Deaktiviert die Kerberos-Authentifizierung.
sed -ri 's/#?KerberosAuthentication\s.*$/KerberosAuthentication no/' /etc/ssh/sshd_config
sed -ri 's/#?GSSAPIAuthentication\s.*$/GSSAPIAuthentication no/' /etc/ssh/sshd_config

# Deaktiviert die Agentenweiterleitung/-tunnelung.
sed -ri 's/#?AllowAgentForwarding\s.*$/AllowAgentForwarding no/' /etc/ssh/sshd_config

# Deaktiviert die TCP-Weiterleitung/Tunneling.
sed -ri 's/#?AllowTcpForwarding\s.*$/AllowTcpForwarding no/' /etc/ssh/sshd_config

# Deaktiviert das Remote-Port-Forwarding.
sed -ri 's/#?GatewayPorts\s.*$/GatewayPorts no/' /etc/ssh/sshd_config

# Deaktiviert die X11-Weiterleitung/Tunneling (GUI).
sed -ri 's/#?X11Forwarding\s.*$/X11Forwarding no/' /etc/ssh/sshd_config

# Deaktiviert das Motd-Banner "Message of the Day".
sed -ri 's/#?PrintMotd\s.*$/PrintMotd no/' /etc/ssh/sshd_config

# Zeigt das Datum und Uhrzeit der letzten Benutzeranmeldung an.
sed -ri 's/#?PrintLastLog\s.*$/PrintLastLog yes/' /etc/ssh/sshd_config

# Verhindert, dass die Verbindung zum Server unterbrochen wird.
sed -ri 's/#?TCPKeepAlive\s.*$/TCPKeepAlive yes/' /etc/ssh/sshd_config

# Deaktiviert die User Environment Files.
sed -ri 's/#?PermitUserEnvironment\s.*$/PermitUserEnvironment no/' /etc/ssh/sshd_config

# Deaktiviert die Komprimierung und sorgt für mehr Sicherheit.
sed -ri 's/#?Compression\s.*$/Compression no/' /etc/ssh/sshd_config

# Beendet die Verbindung nach 30 Minuten Inaktivität - !Kann angepasst werden.
sed -ri 's/#?ClientAliveInterval\s.*$/ClientAliveInterval 1800/' /etc/ssh/sshd_config

# Sendet 2 Mal eine ClientAlive-Nachricht bevor die Verbindung abbricht - !Kann angepasst werden.
sed -ri 's/#?ClientAliveCountMax\s.*$/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# Deaktiviert DNS-Lookup, dadurch wird die Verbindung schneller hergestellt.
sed -ri 's/#?UseDNS\s.*$/UseDNS no/' /etc/ssh/sshd_config

# Deaktiviert die Weiterleitung von tun-Geräten bei SSH-Verbindugen.
sed -ri 's/#?PermitTunnel\s.*$/PermitTunnel no/' /etc/ssh/sshd_config

# Deaktiviert das SSH-Protokollbanner.
sed -ri 's/#?VersionAddendum\s.*$/VersionAddendum none/' /etc/ssh/sshd_config

# Beschränkt den Zugang auf folgende Benutzer – !ACHTUNG bitte Namen anpassen.
sed -i '/^.*AddressFamily.*/a AllowUsers erik' /etc/ssh/sshd_config

# Prüft die Konfiguration auf Fehler.
sshd -t

# startet den OpenSSH-Server neu.
service ssh restart

# Powershell SSH Config anpassen - zukünftig SSH Connect via "ssh proxmox"
Add-Content -Path "$env:USERPROFILE\.ssh\config" -Value @"
Host proxmox
    HostName 10.0.0.200
    Port 62253
    User erik
    IdentityFile C:/Users/erikw/.ssh/20240929-pve-ed25519_key
    IdentitiesOnly yes
"@

# SSH Zugang in einer NEUEN Shell überprüfen
ssh proxmox
 ```

### Quellen
- [`SSH Hardening Guides`](https://www.sshaudit.com/hardening_guides.html)
- [`Proxmox Wiki`](https://pve.proxmox.com/wiki/Fail2ban)
- [`Firewall und Fail2Bann einrichten`](https://github.com/ErikSlevin/raspberry-install?tab=readme-ov-file#firewall-unf-fail2bann-einrichten)
- [`Proxmox Ab-Härtung Debian Bullseye und Debian Bookworm`](https://ralf-peter-kleinert.de/linux-server/proxmox-server-sichern-haerten.html)
- [`OpenSSH Server abhärten `](https://sakis.tech/openssh-server-abhaerten-und-absichern-unter-linux/)


## 6. Fail2Bann

```shell
# Fail2Bann installieren 
apt install fail2ban -y

# erstellt eine Kopie der Konfigurationsdatei.
sudo cp /etc/fail2ban/jail.{conf,local} -v

# jail.conf -> wird bei jedem Update überschriebn (Orginalkonfiguration)
# jail.local -> Benutzerdefinierte Konfog / Persistent
# jail.local
nano /etc/fail2ban/jail.local

[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
backend = systemd
maxretry = 3
findtime = 2d
bantime = 1h

[sshd]
enabled = true
port = 62253
logpath = %(sshd_backend)s
backend = systemd
maxretry = 3
findtime = 1d
bantime = 2h
ignoreip = 127.0.0.1/8

# proxmox2.conf
nano /etc/fail2ban/filter.d/proxmox.conf 

# Fail2Ban neu starten 
systemctl enable fail2ban --now

# Webfrontend-Login - Jail überprüfen (RegEx +1)
fail2ban-regex systemd-journal /etc/fail2ban/filter.d/proxmox.conf

# fail2ban-client unban --all

 ```
### Verwendete Dateien
- [`proxmox.conf `](files/install_config/proxmox.conf)

### Quellen
- [`SSH Hardening Guides`](https://www.sshaudit.com/hardening_guides.html)
- [`Proxmox Wiki`](https://pve.proxmox.com/wiki/Fail2ban)
- [`Firewall und Fail2Bann einrichten`](https://github.com/ErikSlevin/raspberry-install?tab=readme-ov-file#firewall-unf-fail2bann-einrichten)
- [`Proxmox Ab-Härtung Debian Bullseye und Debian Bookworm`](https://ralf-peter-kleinert.de/linux-server/proxmox-server-sichern-haerten.html)

## 7. Nicht benötigte Protokolle deaktivieren
```shell
# NFS deaktivieren
sudo sed -i 's/^NEED_STATD=.*/NEED_STATD=no/' /etc/default/nfs-common

# RPC deaktivieren
systemctl disable --now rpcbind.service rpcbind.socket

# Deaktivierung von IPv6
echo "# Deaktivierung von IPv6" | sudo tee -a /etc/sysctl.conf > /dev/null && echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf > /dev/null

# Postfix auf IPv4 beschränken
sudo bash -c 'echo "# Nur IPv4-Protokoll aktivieren" >> /etc/postfix/main.cf && echo "inet_protocols = ipv4" >> /etc/postfix/main.cf'

sudo bash -c 'echo "# Forwarding deaktivieren" >> /etc/sysctl.conf'
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Packet Redirect deaktivieren" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Routed Packets nicht akzeptieren" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# ICMP Redirects nicht akzeptieren" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Secure ICMP Redirects nicht akzeptieren" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Suspicious Packets müssen geloggt werden" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Broadcast ICMP Requests müssen ignoriert werden" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Bogus ICMP Responses müssen ignoriert werden" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# Reverse Path Filtering aktivieren" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# TCP SYN Cookies müssen aktiviert werden" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

echo "" >> /etc/sysctl.conf

echo "# IPv6 Router Advertisements deaktivieren" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf'


 ```


### Quellen
- [`Proxmox VE: Anleitung zur Sicherheitshärtung`](https://bw-edv.de/blog/de-de/proxmox-ve-anleitung-zur-sicherheitshaertung)

## 8. Firewall-Regeln

```shell
# UFW installieren
apt install ufw -y

# IPv6 deaktivieren 
sudo sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw

# eingehende Verbindungen werden abgelehnt und ausgehende Verbindungen zugelassen.
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH zulassen für 10.0.0.0/24
sudo ufw allow from 10.0.0.0/24 to 10.0.0.0/24 port 62253 proto tcp comment 'SSH zulassen für 10.0.0.0/24'

# Proxmox Web-UI zulassen für 10.0.0.0/24
sudo ufw allow from 10.0.0.0/24 to 10.0.0.0/24 port 8006 proto tcp comment 'Proxmox Web-UI zulassen für 10.0.0.0/24'

# VNC Web-Console zulassen für 10.0.0.0/24
sudo ufw allow from 10.0.0.0/24 to 10.0.0.0/24 port 5900:5999 proto tcp comment 'VNC Web-Console zulassen für 10.0.0.0/24'

# SPICE Proxy zulassen für 10.0.0.0/24
sudo ufw allow from 10.0.0.0/24 to 10.0.0.0/24 port 3128 proto tcp comment 'SPICE Proxy zulassen für 10.0.0.0/24'

# UFW-Regeln überprüfen
sudo ufw status verbose

sudo ufw enable

```
