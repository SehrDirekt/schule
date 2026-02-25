import html
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "patientendaten.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        db.executescript(schema_file.read())
    db.commit()
    db.close()


def base_layout(content: str) -> bytes:
    return f"""<!doctype html>
<html lang='de'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>Patientendaten</title>
  <link rel='stylesheet' href='/styles.css'>
</head>
<body>
  <header>
    <h1>Patientendaten</h1>
    <nav>
      <a href='/'>Übersicht</a>
      <a href='/patient/new'>Patient anlegen</a>
    </nav>
  </header>
  <main>{content}</main>
</body>
</html>""".encode("utf-8")


def index_page() -> bytes:
    db = get_db()
    patients = db.execute(
        """
        SELECT p.patient_id, m.vor_nachname, p.geburtsdatum, p.geschlecht,
               v.krankenkasse, v.versicherungsnr
        FROM patient p
        JOIN mensch m ON m.mensch_id = p.mensch_id
        LEFT JOIN versichertendaten v ON v.versicherungsnr = p.versicherungsnr
        ORDER BY p.patient_id DESC
        """
    ).fetchall()
    db.close()

    if patients:
        rows = "".join(
            f"""<tr>
<td>{p['patient_id']}</td>
<td>{html.escape(p['vor_nachname'])}</td>
<td>{p['geburtsdatum'] or '-'}</td>
<td>{p['geschlecht'] or '-'}</td>
<td>{p['krankenkasse'] or '-'}</td>
<td>{p['versicherungsnr'] or '-'}</td>
</tr>"""
            for p in patients
        )
        table = f"""
<section>
<h2>Patientenliste</h2>
<table>
<thead><tr><th>ID</th><th>Name</th><th>Geburtsdatum</th><th>Geschlecht</th><th>Krankenkasse</th><th>Vers.-Nr.</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</section>
"""
    else:
        table = "<section><h2>Patientenliste</h2><p>Noch keine Patienten vorhanden.</p></section>"
    return base_layout(table)


def patient_form_page() -> bytes:
    return base_layout(
        """
<section>
  <h2>Neuen Patienten anlegen</h2>
  <form method='post' class='form-grid'>
    <label>Name <input name='name' required></label>
    <label>Geburtsdatum <input type='date' name='geburtsdatum'></label>
    <label>Geschlecht <input name='geschlecht'></label>

    <label>Straße + Hausnr. <input name='strasse' required></label>
    <label>PLZ <input name='plz' required></label>
    <label>Ort <input name='ort' required></label>
    <label>Telefon <input name='telefon'></label>
    <label>E-Mail <input type='email' name='email'></label>

    <label>Versicherungsnummer <input name='versicherungsnr'></label>
    <label>Kartennummer <input name='kartennr'></label>
    <label>Versicherungsart <input name='versicherungsart'></label>
    <label>Krankenkasse <input name='krankenkasse'></label>

    <button type='submit'>Speichern</button>
  </form>
</section>
"""
    )


def create_patient(form_data: dict[str, list[str]]) -> None:
    def val(name: str) -> str:
        return form_data.get(name, [""])[0].strip()

    db = get_db()
    db.execute(
        """
        INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email)
        VALUES (?, ?, ?, ?, ?)
        """,
        (val("strasse"), val("plz"), val("ort"), val("telefon"), val("email")),
    )
    kontakt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    db.execute(
        "INSERT INTO mensch (vor_nachname, kontakt_id) VALUES (?, ?)",
        (val("name"), kontakt_id),
    )
    mensch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    versicherungsnr = val("versicherungsnr") or None
    if versicherungsnr:
        db.execute(
            """
            INSERT OR REPLACE INTO versichertendaten
            (versicherungsnr, kartennr, versicherungsart, krankenkasse)
            VALUES (?, ?, ?, ?)
            """,
            (versicherungsnr, val("kartennr"), val("versicherungsart"), val("krankenkasse")),
        )

    db.execute(
        """
        INSERT INTO patient (geburtsdatum, geschlecht, mensch_id, versicherungsnr)
        VALUES (?, ?, ?, ?)
        """,
        (val("geburtsdatum"), val("geschlecht"), mensch_id, versicherungsnr),
    )
    db.commit()
    db.close()


def styles_css() -> bytes:
    return (BASE_DIR / "static" / "styles.css").read_bytes()


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/styles.css":
        start_response("200 OK", [("Content-Type", "text/css; charset=utf-8")])
        return [styles_css()]

    if path == "/" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [index_page()]

    if path == "/patient/new" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [patient_form_page()]

    if path == "/patient/new" and method == "POST":
        try:
            size = int(environ.get("CONTENT_LENGTH", "0"))
        except ValueError:
            size = 0
        body = environ["wsgi.input"].read(size).decode("utf-8")
        form_data = parse_qs(body)
        create_patient(form_data)
        start_response("303 See Other", [("Location", "/")])
        return [b""]

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Not Found"]


if __name__ == "__main__":
    init_db()
    with make_server("0.0.0.0", 5000, app) as server:
        print("Server running on http://0.0.0.0:5000")
        server.serve_forever()
