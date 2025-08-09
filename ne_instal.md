# Proxmox: Neuen Admin-Benutzer mit Root-Rechten anlegen (@pam)

## Schritte

```bash
# 1. Neuen Linux-Benutzer mit Home-Verzeichnis anlegen
#    -m  → erstellt automatisch ein Home-Verzeichnis (/home/erik)
useradd -m erik

# 2. Passwort für den neuen Linux-Benutzer setzen
#    Hier wird das Passwort direkt im Linux-System gespeichert (PAM)
passwd erik

# 3. Benutzer in Proxmox als PAM-User registrieren
#    @pam bedeutet: Authentifizierung über das Linux-PAM-System
pveum user add erik@pam

# 4. (Optional) Passwort auch in Proxmox setzen
#    Wird meist nicht benötigt, da @pam-Passwörter direkt aus Linux kommen.
#    Der Befehl funktioniert aber für Synchronisierung/Tests.
pveum passwd erik@pam

# 5. Benutzer Vollzugriff in Proxmox geben
#    - Pfad "/" bedeutet: Rechte auf der gesamten Umgebung
#    - Rolle "Administrator" hat Root-ähnliche Rechte
pveum acl modify / -user erik@pam -role Administrator
