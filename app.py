import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "patientendaten.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"
COOKIE_NAME = "privacy_state"
PRIVACY_PASSWORD = "Entsperren123!"
COOKIE_TTL_SECONDS = 300
APP_SECRET = os.environ.get("APP_SECRET", "schule-local-secret-change-me").encode("utf-8")


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


def parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        key, value = part.strip().split("=", 1)
        cookies[key] = value
    return cookies


def _keystream(length: int, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        counter_bytes = counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(APP_SECRET + nonce + counter_bytes).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_cookie(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(16)
    cipher = bytes(a ^ b for a, b in zip(raw, _keystream(len(raw), nonce)))
    mac = hmac.new(APP_SECRET, nonce + cipher, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(nonce + cipher + mac).decode("ascii")
    return token


def decrypt_cookie(token: str) -> dict | None:
    try:
        data = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(data) < 48:
            return None
        nonce = data[:16]
        mac = data[-32:]
        cipher = data[16:-32]
        expected_mac = hmac.new(APP_SECRET, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None
        raw = bytes(a ^ b for a, b in zip(cipher, _keystream(len(cipher), nonce)))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def is_privacy_mode(environ: dict) -> bool:
    cookies = parse_cookies(environ.get("HTTP_COOKIE", ""))
    token = cookies.get(COOKIE_NAME)
    if not token:
        return True
    payload = decrypt_cookie(token)
    if not payload:
        return True
    if payload.get("privacy") is not False:
        return True
    expiry = int(payload.get("exp", 0))
    return expiry <= int(time.time())


def build_privacy_set_cookie(enabled: bool) -> str:
    exp = int(time.time()) + COOKIE_TTL_SECONDS
    payload = {"privacy": enabled, "exp": exp}
    token = encrypt_cookie(payload)
    return f"{COOKIE_NAME}={token}; Max-Age={COOKIE_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax"


def mask(value: str | None, privacy_mode: bool) -> str:
    if not value:
        return "-"
    if not privacy_mode:
        return value
    return "••••••"


def base_layout(content: str, privacy_mode: bool, error: str = "") -> bytes:
    privacy_label = "Privacy-Modus aktiv" if privacy_mode else "Privacy-Modus deaktiviert"
    unlock_form = "" if not privacy_mode else """
      <form method='post' action='/privacy/unlock' class='inline-form'>
        <input type='password' name='password' placeholder='Passwort' required>
        <button type='submit'>Entsperren</button>
      </form>
    """
    lock_button = "" if privacy_mode else """
      <form method='post' action='/privacy/lock' class='inline-form'>
        <button type='submit'>Privacy aktivieren</button>
      </form>
    """
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""

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
      <a href='/verwaltung'>Verwaltung</a>
    </nav>
  </header>
  <section class='privacy-panel'>
    <strong>{privacy_label}</strong>
    {unlock_form}
    {lock_button}
    {error_html}
  </section>
  <main>{content}</main>
  <script src='/app.js'></script>
</body>
</html>""".encode("utf-8")


def load_patients() -> list[sqlite3.Row]:
    db = get_db()
    rows = db.execute(
        """
        SELECT p.patient_id, m.vor_nachname, p.geburtsdatum, p.geschlecht,
               v.krankenkasse, v.versicherungsnr,
               k.strasse_hausnummer, k.plz, k.ort, k.telefon_mobil, k.email
        FROM patient p
        JOIN mensch m ON m.mensch_id = p.mensch_id
        JOIN kontakt k ON k.kontakt_id = m.kontakt_id
        LEFT JOIN versichertendaten v ON v.versicherungsnr = p.versicherungsnr
        ORDER BY p.patient_id DESC
        """
    ).fetchall()
    db.close()
    return rows


def load_patient_extra(patient_id: int) -> dict[str, str]:
    db = get_db()
    be = db.execute(
        """
        SELECT b.behandlung_id, b.fachrichtung, b.datum
        FROM zo_praxis_patient zpp
        JOIN zo_patient_behandlung zpb ON zpb.zopp_id = zpp.zopp_id
        JOIN behandlung b ON b.behandlung_id = zpb.behandlung_id
        WHERE zpp.patient_id = ?
        ORDER BY b.datum DESC
        """,
        (patient_id,),
    ).fetchall()
    meds = db.execute(
        """
        SELECT DISTINCT m.name
        FROM rezept r
        JOIN zo_medikament_rezept zmr ON zmr.rezept_id = r.rezept_id
        JOIN medikament m ON m.medikament_id = zmr.medikament_id
        WHERE r.patient_id = ?
        """,
        (patient_id,),
    ).fetchall()
    db.close()

    return {
        "behandlungen": ", ".join(f"#{r['behandlung_id']} {r['fachrichtung'] or '-'} ({r['datum'] or '-'})" for r in be) or "-",
        "medikamente": ", ".join(r["name"] for r in meds) or "-",
    }


def index_page(privacy_mode: bool) -> bytes:
    patients = load_patients()

    if patients:
        rows = []
        for p in patients:
            extra = load_patient_extra(p["patient_id"])
            attrs = {
                "name": p["vor_nachname"],
                "geburtsdatum": p["geburtsdatum"] or "-",
                "geschlecht": p["geschlecht"] or "-",
                "krankenkasse": p["krankenkasse"] or "-",
                "versicherungsnr": p["versicherungsnr"] or "-",
                "adresse": f"{p['strasse_hausnummer']}, {p['plz']} {p['ort']}",
                "telefon": p["telefon_mobil"] or "-",
                "email": p["email"] or "-",
                "behandlungen": extra["behandlungen"],
                "medikamente": extra["medikamente"],
            }
            data_attrs = " ".join(
                f"data-{k}='{html.escape(v, quote=True)}'" for k, v in attrs.items()
            )
            rows.append(
                f"""<tr class='patient-row' {data_attrs}>
<td>{p['patient_id']}</td>
<td>{html.escape(mask(p['vor_nachname'], privacy_mode))}</td>
<td>{html.escape(mask(p['geburtsdatum'] or '-', privacy_mode))}</td>
<td>{html.escape(mask(p['geschlecht'] or '-', privacy_mode))}</td>
<td>{html.escape(mask(p['krankenkasse'] or '-', privacy_mode))}</td>
<td>{html.escape(mask(p['versicherungsnr'] or '-', privacy_mode))}</td>
</tr>"""
            )

        table = f"""
<section>
<h2>Patientenliste</h2>
<p>Klicke auf einen Patienten, um unten die InfoCard auszuklappen.</p>
<table>
<thead><tr><th>ID</th><th>Name</th><th>Geburtsdatum</th><th>Geschlecht</th><th>Krankenkasse</th><th>Vers.-Nr.</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
<div id='patient-card' class='info-card hidden'>
  <h3>Patienten-InfoCard</h3>
  <div class='card-grid'>
    <p><strong>Name:</strong> <span data-field='name'>-</span></p>
    <p><strong>Geburtsdatum:</strong> <span data-field='geburtsdatum'>-</span></p>
    <p><strong>Geschlecht:</strong> <span data-field='geschlecht'>-</span></p>
    <p><strong>Krankenkasse:</strong> <span data-field='krankenkasse'>-</span></p>
    <p><strong>Versicherungsnr:</strong> <span data-field='versicherungsnr'>-</span></p>
    <p><strong>Adresse:</strong> <span data-field='adresse'>-</span></p>
    <p><strong>Telefon:</strong> <span data-field='telefon'>-</span></p>
    <p><strong>E-Mail:</strong> <span data-field='email'>-</span></p>
    <p><strong>Behandlungen:</strong> <span data-field='behandlungen'>-</span></p>
    <p><strong>Medikamente:</strong> <span data-field='medikamente'>-</span></p>
  </div>
</div>
</section>
"""
    else:
        table = "<section><h2>Patientenliste</h2><p>Noch keine Patienten vorhanden.</p></section>"
    return base_layout(table, privacy_mode)


def patient_form_page(privacy_mode: bool) -> bytes:
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

    <button type='submit'>Patient speichern</button>
  </form>
</section>
""",
        privacy_mode,
    )


def verwaltung_page(privacy_mode: bool) -> bytes:
    db = get_db()
    patienten = db.execute("SELECT patient_id FROM patient ORDER BY patient_id DESC").fetchall()
    aerzte = db.execute("SELECT arzt_id FROM arzt ORDER BY arzt_id DESC").fetchall()
    praxen = db.execute("SELECT praxis_id, name FROM praxis ORDER BY praxis_id DESC").fetchall()
    behandlungen = db.execute("SELECT behandlung_id FROM behandlung ORDER BY behandlung_id DESC").fetchall()
    dokumente = db.execute("SELECT dokument_id, dokumentname FROM dokumente ORDER BY dokument_id DESC").fetchall()
    medikamente = db.execute("SELECT medikament_id, name FROM medikament ORDER BY medikament_id DESC").fetchall()
    db.close()

    def options(rows, idk, labelk=None):
        out = []
        for r in rows:
            if labelk is None:
                label = str(r[idk])
            else:
                label = f"{r[idk]} - {html.escape(r[labelk] or '-') }"
            out.append(f"<option value='{r[idk]}'>{label}</option>")
        return "".join(out)

    content = f"""
<section>
  <h2>Verwaltung aller DB-Funktionen</h2>
  <div class='cards'>
    <article>
      <h3>Praxis anlegen</h3>
      <form method='post' action='/praxis/new' class='form-grid'>
        <label>Praxisname <input name='name' required></label>
        <label>Straße + Hausnr. <input name='strasse' required></label>
        <label>PLZ <input name='plz' required></label>
        <label>Ort <input name='ort' required></label>
        <label>Telefon <input name='telefon'></label>
        <label>E-Mail <input name='email'></label>
        <button type='submit'>Praxis speichern</button>
      </form>
    </article>

    <article>
      <h3>Arzt anlegen</h3>
      <form method='post' action='/arzt/new' class='form-grid'>
        <label>Name <input name='name' required></label>
        <label>Fachrichtung <input name='fachrichtung'></label>
        <label>Straße + Hausnr. <input name='strasse' required></label>
        <label>PLZ <input name='plz' required></label>
        <label>Ort <input name='ort' required></label>
        <button type='submit'>Arzt speichern</button>
      </form>
    </article>

    <article>
      <h3>Behandlung anlegen</h3>
      <form method='post' action='/behandlung/new' class='form-grid'>
        <label>Patient-ID
          <select name='patient_id' required>{options(patienten, 'patient_id')}</select>
        </label>
        <label>Fachrichtung <input name='fachrichtung'></label>
        <label>Dauer <input name='behandlungsdauer'></label>
        <label>Datum <input type='date' name='datum'></label>
        <button type='submit'>Behandlung speichern</button>
      </form>
    </article>

    <article>
      <h3>Medikament anlegen</h3>
      <form method='post' action='/medikament/new' class='form-grid'>
        <label>Name <input name='name' required></label>
        <label>Wirkstoff <input name='wirkstoff'></label>
        <label>Hersteller <input name='hersteller'></label>
        <button type='submit'>Medikament speichern</button>
      </form>
    </article>

    <article>
      <h3>Dokument anlegen</h3>
      <form method='post' action='/dokument/new' class='form-grid'>
        <label>Dokumentname <input name='dokumentname' required></label>
        <label>Pfad <input name='pfad'></label>
        <label>Author <input name='author'></label>
        <button type='submit'>Dokument speichern</button>
      </form>
    </article>

    <article>
      <h3>Rezept + Medikament zuweisen</h3>
      <form method='post' action='/rezept/new' class='form-grid'>
        <label>Patient-ID
          <select name='patient_id' required>{options(patienten, 'patient_id')}</select>
        </label>
        <label>Medikament
          <select name='medikament_id' required>{options(medikamente, 'medikament_id', 'name')}</select>
        </label>
        <label>Anzahl <input type='number' min='1' name='anzahl' value='1'></label>
        <label>Hinweise <input name='hinweise'></label>
        <button type='submit'>Rezept speichern</button>
      </form>
    </article>

    <article>
      <h3>Arzt einer Praxis zuordnen</h3>
      <form method='post' action='/mapping/praxis-arzt' class='form-grid'>
        <label>Arzt-ID <select name='arzt_id'>{options(aerzte, 'arzt_id')}</select></label>
        <label>Praxis <select name='praxis_id'>{options(praxen, 'praxis_id', 'name')}</select></label>
        <label>Beschäftigungsstart <input type='date' name='beschaeftigungsstart'></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>

    <article>
      <h3>Dokument einer Behandlung zuordnen</h3>
      <form method='post' action='/mapping/behandlung-dokument' class='form-grid'>
        <label>Behandlung-ID <select name='behandlung_id'>{options(behandlungen, 'behandlung_id')}</select></label>
        <label>Dokument <select name='dokument_id'>{options(dokumente, 'dokument_id', 'dokumentname')}</select></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>
  </div>
</section>
"""
    return base_layout(content, privacy_mode)


def get_val(form_data: dict[str, list[str]], name: str) -> str:
    return form_data.get(name, [""])[0].strip()


def create_patient(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email) VALUES (?, ?, ?, ?, ?)",
        (get_val(form_data, "strasse"), get_val(form_data, "plz"), get_val(form_data, "ort"), get_val(form_data, "telefon"), get_val(form_data, "email")),
    )
    kontakt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO mensch (vor_nachname, kontakt_id) VALUES (?, ?)", (get_val(form_data, "name"), kontakt_id))
    mensch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    versicherungsnr = get_val(form_data, "versicherungsnr") or None
    if versicherungsnr:
        db.execute(
            "INSERT OR REPLACE INTO versichertendaten (versicherungsnr, kartennr, versicherungsart, krankenkasse) VALUES (?, ?, ?, ?)",
            (versicherungsnr, get_val(form_data, "kartennr"), get_val(form_data, "versicherungsart"), get_val(form_data, "krankenkasse")),
        )

    db.execute(
        "INSERT INTO patient (geburtsdatum, geschlecht, mensch_id, versicherungsnr) VALUES (?, ?, ?, ?)",
        (get_val(form_data, "geburtsdatum"), get_val(form_data, "geschlecht"), mensch_id, versicherungsnr),
    )
    db.commit()
    db.close()


def create_praxis(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email) VALUES (?, ?, ?, ?, ?)",
        (get_val(form_data, "strasse"), get_val(form_data, "plz"), get_val(form_data, "ort"), get_val(form_data, "telefon"), get_val(form_data, "email")),
    )
    kontakt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO praxis (name, kontakt_id) VALUES (?, ?)", (get_val(form_data, "name"), kontakt_id))
    db.commit()
    db.close()


def create_arzt(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email) VALUES (?, ?, ?, ?, ?)", (get_val(form_data, "strasse"), get_val(form_data, "plz"), get_val(form_data, "ort"), "", ""))
    kontakt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO mensch (vor_nachname, kontakt_id) VALUES (?, ?)", (get_val(form_data, "name"), kontakt_id))
    mensch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO arzt (fachrichtung, mensch_id) VALUES (?, ?)", (get_val(form_data, "fachrichtung"), mensch_id))
    db.commit()
    db.close()


def create_behandlung(form_data: dict[str, list[str]]) -> None:
    patient_id = int(get_val(form_data, "patient_id"))
    db = get_db()
    db.execute(
        "INSERT INTO behandlung (fachrichtung, behandlungsdauer, datum) VALUES (?, ?, ?)",
        (get_val(form_data, "fachrichtung"), get_val(form_data, "behandlungsdauer"), get_val(form_data, "datum")),
    )
    behandlung_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    zpp = db.execute("SELECT zopp_id FROM zo_praxis_patient WHERE patient_id = ? ORDER BY zopp_id DESC LIMIT 1", (patient_id,)).fetchone()
    if zpp is None:
        praxis = db.execute("SELECT praxis_id FROM praxis ORDER BY praxis_id ASC LIMIT 1").fetchone()
        if praxis is None:
            db.execute("INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email) VALUES ('Unbekannt', '00000', 'Unbekannt', '', '')")
            k_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute("INSERT INTO praxis (name, kontakt_id) VALUES ('Standardpraxis', ?)", (k_id,))
            praxis_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        else:
            praxis_id = praxis["praxis_id"]
        db.execute("INSERT INTO zo_praxis_patient (patient_id, praxis_id, erstbesuch) VALUES (?, ?, date('now'))", (patient_id, praxis_id))
        zopp_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    else:
        zopp_id = zpp["zopp_id"]

    db.execute("INSERT INTO zo_patient_behandlung (behandlung_id, zopp_id) VALUES (?, ?)", (behandlung_id, zopp_id))
    db.commit()
    db.close()


def create_medikament(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO medikament (name, wirkstoff, hersteller) VALUES (?, ?, ?)", (get_val(form_data, "name"), get_val(form_data, "wirkstoff"), get_val(form_data, "hersteller")))
    db.commit()
    db.close()


def create_dokument(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO dokumente (pfad, dokumentname, author) VALUES (?, ?, ?)", (get_val(form_data, "pfad"), get_val(form_data, "dokumentname"), get_val(form_data, "author")))
    db.commit()
    db.close()


def create_rezept(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO rezept (patient_id, ausstellungsdatum, hinweise) VALUES (?, date('now'), ?)", (int(get_val(form_data, "patient_id")), get_val(form_data, "hinweise")))
    rezept_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO zo_medikament_rezept (rezept_id, medikament_id, anzahl) VALUES (?, ?, ?)", (rezept_id, int(get_val(form_data, "medikament_id")), int(get_val(form_data, "anzahl") or "1")))
    db.commit()
    db.close()


def create_mapping_praxis_arzt(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO zo_praxis_arzt (arzt_id, praxis_id, beschaeftigungsstart) VALUES (?, ?, ?)", (int(get_val(form_data, "arzt_id")), int(get_val(form_data, "praxis_id")), get_val(form_data, "beschaeftigungsstart")))
    db.commit()
    db.close()


def create_mapping_behandlung_dokument(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute("INSERT INTO zo_behandlung_dokumente (behandlung_id, dokument_id) VALUES (?, ?)", (int(get_val(form_data, "behandlung_id")), int(get_val(form_data, "dokument_id"))))
    db.commit()
    db.close()


def styles_css() -> bytes:
    return (BASE_DIR / "static" / "styles.css").read_bytes()


def app_js() -> bytes:
    return (BASE_DIR / "static" / "app.js").read_bytes()


def parse_post(environ: dict) -> dict[str, list[str]]:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        size = 0
    body = environ["wsgi.input"].read(size).decode("utf-8")
    return parse_qs(body)


def redirect(start_response, location: str, headers: list[tuple[str, str]] | None = None):
    out_headers = [("Location", location)]
    if headers:
        out_headers.extend(headers)
    start_response("303 See Other", out_headers)
    return [b""]


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    privacy_mode = is_privacy_mode(environ)

    if path == "/styles.css":
        start_response("200 OK", [("Content-Type", "text/css; charset=utf-8")])
        return [styles_css()]

    if path == "/app.js":
        start_response("200 OK", [("Content-Type", "application/javascript; charset=utf-8")])
        return [app_js()]

    if path == "/" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [index_page(privacy_mode)]

    if path == "/patient/new" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [patient_form_page(privacy_mode)]

    if path == "/verwaltung" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [verwaltung_page(privacy_mode)]

    if path == "/privacy/unlock" and method == "POST":
        form_data = parse_post(environ)
        if get_val(form_data, "password") == PRIVACY_PASSWORD:
            return redirect(start_response, "/", [("Set-Cookie", build_privacy_set_cookie(False))])
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [base_layout("<section><p>Falsches Passwort.</p></section>", True, "Entsperren fehlgeschlagen")]

    if path == "/privacy/lock" and method == "POST":
        return redirect(start_response, "/", [("Set-Cookie", build_privacy_set_cookie(True))])

    handlers = {
        "/patient/new": create_patient,
        "/praxis/new": create_praxis,
        "/arzt/new": create_arzt,
        "/behandlung/new": create_behandlung,
        "/medikament/new": create_medikament,
        "/dokument/new": create_dokument,
        "/rezept/new": create_rezept,
        "/mapping/praxis-arzt": create_mapping_praxis_arzt,
        "/mapping/behandlung-dokument": create_mapping_behandlung_dokument,
    }

    if path in handlers and method == "POST":
        form_data = parse_post(environ)
        handlers[path](form_data)
        return redirect(start_response, "/verwaltung" if path != "/patient/new" else "/")

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Not Found"]


if __name__ == "__main__":
    init_db()
    with make_server("0.0.0.0", 5000, app) as server:
        print("Server running on http://0.0.0.0:5000")
        server.serve_forever()
