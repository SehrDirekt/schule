# Patientendaten (SQL + UI)

Dieses Projekt bildet dein ER-Diagramm als SQL-Datenbank (SQLite) ab und liefert ein lokales Web-UI zur Verwaltung der Daten.

## Features

- Vollständiges SQL-Schema inkl. Kern- und Zuordnungstabellen (`schema.sql`)
- Web-UI mit folgenden Bereichen:
  - Patientenübersicht mit anklickbaren Zeilen
  - Ausfahrende InfoCard mit Detaildaten eines Patienten
  - Formulare zur Verwaltung weiterer DB-Funktionen (Praxis, Arzt, Behandlung, Dokumente, Medikamente, Rezepte, Zuordnungen)
- Privacy-Modus:
  - Standardmäßig **aktiviert**
  - Daten werden maskiert
  - Entsperren per Passwort `Entsperren123!`
  - Zustand in verschlüsseltem Cookie gespeichert
  - Cookie läuft nach 5 Minuten ab

## Start

```bash
python3 app.py
```

Dann im Browser öffnen:

- http://localhost:5000

Beim ersten Start wird die Datei `patientendaten.db` automatisch erstellt.
