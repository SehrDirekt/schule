# Patientendaten (SQL + UI)

Dieses Projekt bildet dein ER-Diagramm als SQL-Datenbank (SQLite) ab und liefert ein einfaches Web-UI zum Anlegen und Anzeigen von Patienten.

## Enthalten

- `schema.sql`: Tabellen + Beziehungen aus dem Diagramm
- `app.py`: Lokale WSGI-Web-App (Python-Standardbibliothek) mit SQLite
- UI-Seiten:
  - Übersicht (`/`)
  - Patient anlegen (`/patient/new`)

## Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Dann im Browser öffnen:

- http://localhost:5000

Beim ersten Start wird die Datei `patientendaten.db` automatisch erstellt.
