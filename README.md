# Patientendaten (SQL + UI)

Dieses Projekt bildet das ER-Diagramm als SQLite-Datenbank ab und liefert ein lokales Web-UI mit rollenbasiertem Login.

## Features

- Vollständiges SQL-Schema inkl. Kern- und Zuordnungstabellen (`schema.sql`)
- Login-Frontpage unter `/` mit **einem Eingabefeld** (Login-ID)
- Getrennte Login-Seiten je Rolle:
  - Patient: `/patienten/login`
  - Arzt: `/arzt/login`
  - Admin: `/admin/login`
- Patienten-Erstanmeldung über `/patienten/erstlogin` mit Passwortwechsel
- Admin Control Center für:
  - gruppierte Bereiche (Überblick, Stammdaten, Zuordnungen, Kontenverwaltung)
  - Direktzugriff auf Praxis-Dashboards im Lesemodus
  - Übersicht aller User-Logins und simulierte Mail-Outbox
- Arzt-Oberfläche mit Behandlungs-/Rezeptübersicht und Edit-Funktionen
- Separate Login-Datenbank `user_logins.db`, verknüpft über `patient_id`, `arzt_id` und `mensch_id`
- Beim Anlegen von Patient/Arzt werden temporäre Logindaten erzeugt und als E-Mail in `mail_outbox` protokolliert

## Start

```bash
python3 app.py
```

Dann im Browser öffnen:

- http://localhost:5000

Beim ersten Start werden automatisch erstellt:

- `patientendaten.db`
- `user_logins.db`

Demo-Admin-Login:

- Login-ID: `admin`
- Passwort: `Admin123!`


## LDAP für Admin-Login

Optional kann die Admin-Anmeldung per LDAP-Bind erfolgen (zusätzlich zur lokalen Passwort-Prüfung).

Benötigte Variablen:

- `LDAP_ENABLED=1`
- `LDAP_SERVER_URI=ldap://<server>:389`
- `LDAP_BIND_DN_TEMPLATE=uid={login_id},ou=people,dc=schule,dc=local`
