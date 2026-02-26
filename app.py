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
AUTH_DB_PATH = BASE_DIR / "user_logins.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"
COOKIE_NAME = "app_session"
APP_SECRET = os.environ.get("APP_SECRET", "schule-local-secret-change-me").encode("utf-8")
SESSION_TTL_SECONDS = 60 * 60 * 8


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def get_auth_db() -> sqlite3.Connection:
    connection = sqlite3.connect(AUTH_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        db.executescript(schema_file.read())
    db.commit()
    db.close()


def init_auth_db() -> None:
    db = get_auth_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS user_login (
          user_id INTEGER PRIMARY KEY AUTOINCREMENT,
          login_id TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL CHECK(role IN ('admin', 'arzt', 'patient')),
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          is_temp_password INTEGER NOT NULL DEFAULT 1,
          patient_id INTEGER,
          arzt_id INTEGER,
          mensch_id INTEGER,
          is_active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mail_outbox (
          mail_id INTEGER PRIMARY KEY AUTOINCREMENT,
          receiver TEXT NOT NULL,
          subject TEXT NOT NULL,
          body TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    columns = [row[1] for row in db.execute("PRAGMA table_info(user_login)").fetchall()]
    if "arzt_id" not in columns:
        db.execute("ALTER TABLE user_login ADD COLUMN arzt_id INTEGER")
    if "mensch_id" not in columns:
        db.execute("ALTER TABLE user_login ADD COLUMN mensch_id INTEGER")
    if "praxis_id" in columns and "arzt_id" in columns:
        db.execute("UPDATE user_login SET arzt_id = praxis_id WHERE arzt_id IS NULL")

    db.execute("UPDATE user_login SET user_id = -1 WHERE role = 'admin' AND user_id != -1 AND NOT EXISTS (SELECT 1 FROM user_login WHERE user_id = -1)")
    admin_exists = db.execute("SELECT 1 FROM user_login WHERE role = 'admin' LIMIT 1").fetchone()
    if not admin_exists:
        create_login_user(db, login_id="admin", role="admin", raw_password="Admin123!", is_temp=False, user_id=-1)
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
    return base64.urlsafe_b64encode(nonce + cipher + mac).decode("ascii")


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


def password_hash(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return digest.hex(), salt.hex()


def verify_password(password: str, pw_hash: str, salt_hex: str) -> bool:
    digest, _ = password_hash(password, salt_hex)
    return hmac.compare_digest(digest, pw_hash)


def build_session_cookie(payload: dict) -> str:
    exp = int(time.time()) + SESSION_TTL_SECONDS
    payload = payload | {"exp": exp}
    token = encrypt_cookie(payload)
    return f"{COOKIE_NAME}={token}; Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax"


def clear_session_cookie() -> str:
    return f"{COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"


def get_session(environ: dict) -> dict | None:
    cookies = parse_cookies(environ.get("HTTP_COOKIE", ""))
    token = cookies.get(COOKIE_NAME)
    if not token:
        return None
    payload = decrypt_cookie(token)
    if not payload:
        return None
    if int(payload.get("exp", 0)) <= int(time.time()):
        return None
    return payload


def get_val(form_data: dict[str, list[str]], name: str) -> str:
    return form_data.get(name, [""])[0].strip()


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


def create_login_user(
    db: sqlite3.Connection,
    login_id: str,
    role: str,
    raw_password: str,
    is_temp: bool = True,
    patient_id: int | None = None,
    arzt_id: int | None = None,
    mensch_id: int | None = None,
    user_id: int | None = None,
) -> None:
    pw_hash, salt = password_hash(raw_password)
    db.execute(
        """
        INSERT INTO user_login (user_id, login_id, role, password_hash, salt, is_temp_password, patient_id, arzt_id, mensch_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, login_id, role, pw_hash, salt, 1 if is_temp else 0, patient_id, arzt_id, mensch_id),
    )


def queue_mail(receiver: str, subject: str, body: str) -> None:
    db = get_auth_db()
    db.execute("INSERT INTO mail_outbox (receiver, subject, body) VALUES (?, ?, ?)", (receiver, subject, body))
    db.commit()
    db.close()


def ensure_praxis_login(praxis_id: int) -> None:
    return None


def base_layout(content: str, title: str = "Patientendaten", subtitle: str = "") -> bytes:
    subtitle_html = f"<p class='subtitle'>{html.escape(subtitle)}</p>" if subtitle else ""
    return f"""<!doctype html>
<html lang='de'>
<head>
  <meta charset='UTF-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1.0'>
  <title>{html.escape(title)}</title>
  <link rel='stylesheet' href='/styles.css'>
</head>
<body>
  <header>
    <h1>{html.escape(title)}</h1>
    {subtitle_html}
  </header>
  <main>{content}</main>
  <script src='/app.js'></script>
</body>
</html>""".encode("utf-8")


def login_frontpage(error: str = "") -> bytes:
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    return base_layout(
        f"""
<section class='narrow'>
  <h2>Login starten</h2>
  <p>Bitte geben Sie Ihre Login-ID ein. Danach werden Sie zur passenden Login-Seite weitergeleitet.</p>
  {error_html}
  <form method='post' action='/login/start'>
    <label>Login-ID
      <input name='login_id' required placeholder='z. B. admin oder pa-12'>
    </label>
    <button type='submit'>Weiter</button>
  </form>
</section>
""",
        title="Patientendaten Portal",
        subtitle="Einstieg über eine zentrale Login-Frontpage",
    )


def role_login_page(role: str, login_id: str, error: str = "") -> bytes:
    roles = {"patient": "Patient", "arzt": "Arzt", "admin": "Admin"}
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    return base_layout(
        f"""
<section class='narrow'>
  <h2>{roles[role]}-Login</h2>
  {error_html}
  <form method='post' action='/{role}/authenticate'>
    <label>Login-ID
      <input name='login_id' value='{html.escape(login_id, quote=True)}' readonly>
    </label>
    <label>Passwort
      <input type='password' name='password' required>
    </label>
    <button type='submit'>Anmelden</button>
  </form>
  <p><a href='/'>Zurück zur Frontpage</a></p>
</section>
""",
        title=f"{roles[role]} Login",
    )


def patient_first_login_page(login_id: str, error: str = "") -> bytes:
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
    return base_layout(
        f"""
<section class='narrow'>
  <h2>Erstanmeldung Patient</h2>
  <p>Bitte ändern Sie Ihr temporäres Passwort.</p>
  {error_html}
  <form method='post' action='/patienten/erstlogin'>
    <input type='hidden' name='login_id' value='{html.escape(login_id, quote=True)}'>
    <label>Neues Passwort
      <input type='password' name='new_password' required minlength='8'>
    </label>
    <button type='submit'>Passwort setzen</button>
  </form>
</section>
""",
        title="Patienten Erstanmeldung",
    )


def admin_dashboard() -> bytes:
    auth_db = get_auth_db()
    users = auth_db.execute(
        "SELECT user_id, login_id, role, patient_id, arzt_id, mensch_id, is_temp_password, is_active, created_at FROM user_login ORDER BY user_id DESC"
    ).fetchall()
    mails = auth_db.execute(
        "SELECT receiver, subject, body, created_at FROM mail_outbox ORDER BY mail_id DESC LIMIT 10"
    ).fetchall()
    auth_db.close()

    db = get_db()
    patienten = db.execute("SELECT patient_id FROM patient ORDER BY patient_id DESC").fetchall()
    aerzte = db.execute("SELECT arzt_id FROM arzt ORDER BY arzt_id DESC").fetchall()
    praxen = db.execute("SELECT praxis_id, name FROM praxis ORDER BY praxis_id DESC").fetchall()
    behandlungen = db.execute("SELECT behandlung_id FROM behandlung ORDER BY behandlung_id DESC").fetchall()
    dokumente = db.execute("SELECT dokument_id, dokumentname FROM dokumente ORDER BY dokument_id DESC").fetchall()
    medikamente = db.execute("SELECT medikament_id, name FROM medikament ORDER BY medikament_id DESC").fetchall()
    zobals = db.execute("SELECT zobal_id FROM zo_behandlung_arzt ORDER BY zobal_id DESC").fetchall()
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

    user_rows = "".join(
        f"<tr><td>{u['user_id']}</td><td>{html.escape(u['login_id'])}</td><td>{u['role']}</td><td>{u['patient_id'] or '-'}</td><td>{u['arzt_id'] or '-'}</td><td>{u['mensch_id'] or '-'}</td><td>{'Ja' if u['is_temp_password'] else 'Nein'}</td><td>{'Aktiv' if u['is_active'] else 'Inaktiv'}</td><td>{u['created_at']}</td></tr>"
        for u in users
    )
    mail_rows = "".join(
        f"<tr><td>{html.escape(m['receiver'])}</td><td>{html.escape(m['subject'])}</td><td><pre>{html.escape(m['body'])}</pre></td><td>{m['created_at']}</td></tr>"
        for m in mails
    )

    content = f"""
<section>
  <h2>Admin-Oberfläche</h2>
  <p><a href='/logout'>Abmelden</a></p>
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
      <h3>Patient anlegen (inkl. Login-Mail)</h3>
      <form method='post' action='/patient/new' class='form-grid'>
        <label>Name <input name='name' required></label>
        <label>Geburtsdatum <input type='date' name='geburtsdatum'></label>
        <label>Geschlecht <input name='geschlecht'></label>
        <label>Straße + Hausnr. <input name='strasse' required></label>
        <label>PLZ <input name='plz' required></label>
        <label>Ort <input name='ort' required></label>
        <label>Telefon <input name='telefon'></label>
        <label>E-Mail <input type='email' name='email' required></label>
        <label>Versicherungsnummer <input name='versicherungsnr'></label>
        <label>Kartennummer <input name='kartennr'></label>
        <label>Versicherungsart <input name='versicherungsart'></label>
        <label>Krankenkasse <input name='krankenkasse'></label>
        <button type='submit'>Patient speichern</button>
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
        <label>Telefon <input name='telefon'></label>
        <label>E-Mail <input type='email' name='email'></label>
        <button type='submit'>Arzt speichern</button>
      </form>
    </article>

    <article>
      <h3>Behandlung anlegen</h3>
      <form method='post' action='/behandlung/new' class='form-grid'>
        <label>Patient-ID <select name='patient_id' required>{options(patienten, 'patient_id')}</select></label>
        <label>Fachrichtung <input name='fachrichtung'></label>
        <label>Dauer <input name='behandlungsdauer'></label>
        <label>Datum <input type='date' name='datum'></label>
        <button type='submit'>Behandlung speichern</button>
      </form>
    </article>

    <article>
      <h3>Rezept anlegen</h3>
      <form method='post' action='/rezept/new' class='form-grid'>
        <label>Patient-ID <select name='patient_id'>{options(patienten, 'patient_id')}</select></label>
        <label>Medikament <select name='medikament_id'>{options(medikamente, 'medikament_id', 'name')}</select></label>
        <label>Anzahl <input type='number' name='anzahl' value='1' min='1'></label>
        <label>zobal-ID (Behandlung-Arzt) <select name='zobal_id' required>{options(zobals, 'zobal_id')}</select></label>
        <label>Hinweise <input name='hinweise'></label>
        <button type='submit'>Rezept speichern</button>
      </form>
    </article>

    <article>
      <h3>Medikament anlegen</h3>
      <form method='post' action='/medikament/new' class='form-grid'>
        <label>Name <input name='name' required></label>
        <label>Wirkstoff <input name='wirkstoff'></label>
        <label>Hersteller <input name='hersteller'></label>
        <button type='submit'>Speichern</button>
      </form>
    </article>

    <article>
      <h3>Dokument anlegen</h3>
      <form method='post' action='/dokument/new' class='form-grid'>
        <label>Dateipfad <input name='pfad'></label>
        <label>Dokumentname <input name='dokumentname'></label>
        <label>Author <input name='author'></label>
        <button type='submit'>Speichern</button>
      </form>
    </article>

    <article>
      <h3>Zuordnung Praxis ↔ Arzt</h3>
      <form method='post' action='/mapping/praxis-arzt' class='form-grid'>
        <label>Arzt-ID <select name='arzt_id'>{options(aerzte, 'arzt_id')}</select></label>
        <label>Praxis-ID <select name='praxis_id'>{options(praxen, 'praxis_id', 'name')}</select></label>
        <label>Beschäftigungsstart <input type='date' name='beschaeftigungsstart'></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>

    <article>
      <h3>Zuordnung Behandlung ↔ Dokument</h3>
      <form method='post' action='/mapping/behandlung-dokument' class='form-grid'>
        <label>Behandlung-ID <select name='behandlung_id'>{options(behandlungen, 'behandlung_id')}</select></label>
        <label>Dokument <select name='dokument_id'>{options(dokumente, 'dokument_id', 'dokumentname')}</select></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>

    <article>
      <h3>Zuordnung Praxis ↔ Patient (Diagramm)</h3>
      <form method='post' action='/mapping/praxis-patient' class='form-grid'>
        <label>Praxis-ID <select name='praxis_id'>{options(praxen, 'praxis_id', 'name')}</select></label>
        <label>Patient-ID <select name='patient_id'>{options(patienten, 'patient_id')}</select></label>
        <label>Erstbesuch <input type='date' name='erstbesuch'></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>

    <article>
      <h3>Zuordnung Behandlung ↔ Arzt (Diagramm)</h3>
      <form method='post' action='/mapping/behandlung-arzt' class='form-grid'>
        <label>Behandlung-ID <select name='behandlung_id'>{options(behandlungen, 'behandlung_id')}</select></label>
        <label>Arzt-ID <select name='arzt_id'>{options(aerzte, 'arzt_id')}</select></label>
        <button type='submit'>Zuordnung speichern</button>
      </form>
    </article>
  </div>
</section>
<section>
  <h3>User-Logins (separate DB)</h3>
  <table>
    <thead><tr><th>UserID</th><th>Login</th><th>Rolle</th><th>paID</th><th>arztID</th><th>menschID</th><th>Temp</th><th>Status</th><th>Erstellt</th></tr></thead>
    <tbody>{user_rows}</tbody>
  </table>
</section>
<section>
  <h3>Mail-Outbox (simulierte E-Mails)</h3>
  <table>
    <thead><tr><th>Empfänger</th><th>Betreff</th><th>Inhalt</th><th>Zeit</th></tr></thead>
    <tbody>{mail_rows}</tbody>
  </table>
</section>
"""
    return base_layout(content, title="Admin Verwaltung")


def arzt_dashboard(session: dict) -> bytes:
    arzt_id = session.get("arzt_id")
    db = get_db()
    arzt = db.execute(
        """
        SELECT a.arzt_id, a.fachrichtung, m.vor_nachname
        FROM arzt a
        JOIN mensch m ON m.mensch_id = a.mensch_id
        WHERE a.arzt_id = ?
        """,
        (arzt_id,),
    ).fetchone()
    behandlungen = db.execute(
        """
        SELECT zba.zobal_id, b.behandlung_id, b.fachrichtung, b.behandlungsdauer, b.datum,
               p.patient_id, m.vor_nachname AS patient_name
        FROM zo_behandlung_arzt zba
        JOIN behandlung b ON b.behandlung_id = zba.behandlung_id
        JOIN zo_patient_behandlung zpb ON zpb.behandlung_id = b.behandlung_id
        JOIN zo_praxis_patient zpp ON zpp.zopp_id = zpb.zopp_id
        JOIN patient p ON p.patient_id = zpp.patient_id
        JOIN mensch m ON m.mensch_id = p.mensch_id
        WHERE zba.arzt_id = ?
        ORDER BY b.datum DESC, b.behandlung_id DESC
        """,
        (arzt_id,),
    ).fetchall()
    medikamente = db.execute("SELECT medikament_id, name, wirkstoff, hersteller FROM medikament ORDER BY medikament_id DESC").fetchall()
    rezepte = db.execute(
        """
        SELECT r.rezept_id, r.patient_id, r.ausstellungsdatum, r.hinweise, zmr.zomr_id, zmr.medikament_id, zmr.anzahl, zmr.zobal_id
        FROM rezept r
        LEFT JOIN zo_medikament_rezept zmr ON zmr.rezept_id = r.rezept_id
        ORDER BY r.rezept_id DESC
        """
    ).fetchall()
    db.close()

    if not arzt:
        return base_layout("<section><p>Arzt nicht gefunden.</p></section>", title="Arztbereich")

    behandlung_rows = "".join(
        f"<tr><td>{b['zobal_id']}</td><td>{b['behandlung_id']}</td><td>{html.escape(b['patient_name'])} (pa-{b['patient_id']})</td><td>{html.escape(b['fachrichtung'] or '-')}</td><td>{b['datum'] or '-'}</td><td>{html.escape(b['behandlungsdauer'] or '-')}</td></tr>"
        for b in behandlungen
    )
    rezept_rows = "".join(
        f"<tr><td>{r['rezept_id']}</td><td>{r['patient_id']}</td><td>{r['medikament_id'] or '-'}</td><td>{r['anzahl'] or '-'}</td><td>{r['zobal_id'] or '-'}</td><td>{html.escape(r['hinweise'] or '-')}</td></tr>"
        for r in rezepte
    )
    behandlungs_options = "".join(
        f"<option value='{b['zobal_id']}'>{b['zobal_id']} · Beh {b['behandlung_id']} · pa-{b['patient_id']}</option>" for b in behandlungen
    )
    med_options = "".join(f"<option value='{m['medikament_id']}'>{m['medikament_id']} - {html.escape(m['name'])}</option>" for m in medikamente)

    return base_layout(
        f"""
<section>
  <h2>Arztbereich: {html.escape(arzt['vor_nachname'])}</h2>
  <p><a href='/logout'>Abmelden</a></p>
  <p><strong>Arzt-ID:</strong> {arzt['arzt_id']} · <strong>Fachrichtung:</strong> {html.escape(arzt['fachrichtung'] or '-')}</p>
</section>
<section>
  <h3>Meine Behandlungen</h3>
  <table>
    <thead><tr><th>zobalID</th><th>beID</th><th>Patient</th><th>Fachrichtung</th><th>Datum</th><th>Dauer</th></tr></thead>
    <tbody>{behandlung_rows}</tbody>
  </table>
</section>
<section>
  <h3>Rezept anlegen (mit Verknüpfung Behandlung ↔ Arzt)</h3>
  <form method='post' action='/arzt/rezept/new' class='form-grid'>
    <label>Patient-ID <input type='number' name='patient_id' required></label>
    <label>Medikament <select name='medikament_id' required>{med_options}</select></label>
    <label>Anzahl <input type='number' name='anzahl' value='1' min='1'></label>
    <label>Behandlung-Arzt (zobal_id) <select name='zobal_id' required>{behandlungs_options}</select></label>
    <label>Hinweise <input name='hinweise'></label>
    <button type='submit'>Rezept speichern</button>
  </form>
</section>
<section>
  <h3>Bearbeiten</h3>
  <div class='cards'>
    <article>
      <h4>Behandlung bearbeiten</h4>
      <form method='post' action='/arzt/behandlung/update' class='form-grid'>
        <label>Behandlung-ID <input type='number' name='behandlung_id' required></label>
        <label>Fachrichtung <input name='fachrichtung'></label>
        <label>Dauer <input name='behandlungsdauer'></label>
        <label>Datum <input type='date' name='datum'></label>
        <button type='submit'>Speichern</button>
      </form>
    </article>
    <article>
      <h4>Medikament bearbeiten</h4>
      <form method='post' action='/arzt/medikament/update' class='form-grid'>
        <label>Medikament-ID <input type='number' name='medikament_id' required></label>
        <label>Name <input name='name'></label>
        <label>Wirkstoff <input name='wirkstoff'></label>
        <label>Hersteller <input name='hersteller'></label>
        <button type='submit'>Speichern</button>
      </form>
    </article>
    <article>
      <h4>Rezept-Zuordnung bearbeiten</h4>
      <form method='post' action='/arzt/rezept-medikament/update' class='form-grid'>
        <label>zo_medikament_rezept-ID <input type='number' name='zomr_id' required></label>
        <label>Medikament-ID <input type='number' name='medikament_id' required></label>
        <label>Anzahl <input type='number' name='anzahl' min='1' required></label>
        <label>zobal_id (Behandlung-Arzt) <input type='number' name='zobal_id' required></label>
        <button type='submit'>Speichern</button>
      </form>
    </article>
  </div>
</section>
<section>
  <h3>Rezepte / Verordnungen</h3>
  <table>
    <thead><tr><th>Rezept</th><th>Patient</th><th>Medikament</th><th>Anzahl</th><th>zobalID</th><th>Hinweise</th></tr></thead>
    <tbody>{rezept_rows}</tbody>
  </table>
</section>
""",
        title="Arzt Dashboard",
    )


def patient_dashboard(session: dict) -> bytes:
    patient_id = session.get("patient_id")
    db = get_db()
    patient = db.execute(
        """
        SELECT p.patient_id, m.vor_nachname, p.geburtsdatum, p.geschlecht, k.email,
               v.krankenkasse, v.versicherungsnr
        FROM patient p
        JOIN mensch m ON m.mensch_id = p.mensch_id
        JOIN kontakt k ON k.kontakt_id = m.kontakt_id
        LEFT JOIN versichertendaten v ON v.versicherungsnr = p.versicherungsnr
        WHERE p.patient_id = ?
        """,
        (patient_id,),
    ).fetchone()
    behandlungen = db.execute(
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
    db.close()

    if not patient:
        return base_layout("<section><p>Patient nicht gefunden.</p></section>", title="Patientenbereich")

    be_rows = "".join(
        f"<tr><td>{b['behandlung_id']}</td><td>{html.escape(b['fachrichtung'] or '-')}</td><td>{b['datum'] or '-'}</td></tr>"
        for b in behandlungen
    )

    return base_layout(
        f"""
<section>
  <h2>Patientenbereich</h2>
  <p><a href='/logout'>Abmelden</a></p>
  <div class='card-grid'>
    <p><strong>paID:</strong> {patient['patient_id']}</p>
    <p><strong>Name:</strong> {html.escape(patient['vor_nachname'])}</p>
    <p><strong>Geburtsdatum:</strong> {patient['geburtsdatum'] or '-'}</p>
    <p><strong>Geschlecht:</strong> {patient['geschlecht'] or '-'}</p>
    <p><strong>E-Mail:</strong> {html.escape(patient['email'] or '-')}</p>
    <p><strong>Krankenkasse:</strong> {html.escape(patient['krankenkasse'] or '-')}</p>
    <p><strong>Versicherungsnummer:</strong> {html.escape(patient['versicherungsnr'] or '-')}</p>
  </div>
</section>
<section>
  <h3>Behandlungen</h3>
  <table>
    <thead><tr><th>ID</th><th>Fachrichtung</th><th>Datum</th></tr></thead>
    <tbody>{be_rows}</tbody>
  </table>
</section>
""",
        title="Patienten Dashboard",
    )


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
    patient_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit()
    db.close()

    login_id = f"pa-{patient_id}"
    temp_password = secrets.token_urlsafe(8)
    auth_db = get_auth_db()
    create_login_user(auth_db, login_id=login_id, role="patient", raw_password=temp_password, patient_id=patient_id, mensch_id=mensch_id, user_id=mensch_id)
    auth_db.commit()
    auth_db.close()

    email = get_val(form_data, "email") or "ohne-email@example.local"
    queue_mail(
        email,
        "Temporäre Login-Daten",
        f"Willkommen!\nLogin: {login_id}\nTemporäres Passwort: {temp_password}\nBitte beim ersten Login unter /patienten/login ändern.",
    )


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
    db.execute(
        "INSERT INTO kontakt (strasse_hausnummer, plz, ort, telefon_mobil, email) VALUES (?, ?, ?, ?, ?)",
        (get_val(form_data, "strasse"), get_val(form_data, "plz"), get_val(form_data, "ort"), get_val(form_data, "telefon"), get_val(form_data, "email")),
    )
    kontakt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO mensch (vor_nachname, kontakt_id) VALUES (?, ?)", (get_val(form_data, "name"), kontakt_id))
    mensch_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute("INSERT INTO arzt (fachrichtung, mensch_id) VALUES (?, ?)", (get_val(form_data, "fachrichtung"), mensch_id))
    arzt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit()
    db.close()

    temp_password = secrets.token_urlsafe(8)
    login_id = f"arzt-{arzt_id}"
    auth_db = get_auth_db()
    create_login_user(auth_db, login_id=login_id, role="arzt", raw_password=temp_password, arzt_id=arzt_id, mensch_id=mensch_id, user_id=mensch_id)
    auth_db.commit()
    auth_db.close()

    email = get_val(form_data, "email") or "arzt@example.local"
    queue_mail(email, "Arzt Login", f"Login: {login_id}\nTemporäres Passwort: {temp_password}")


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
    db.execute("INSERT INTO zo_medikament_rezept (rezept_id, medikament_id, anzahl, zobal_id) VALUES (?, ?, ?, ?)", (rezept_id, int(get_val(form_data, "medikament_id")), int(get_val(form_data, "anzahl") or "1"), int(get_val(form_data, "zobal_id"))))
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


def create_mapping_praxis_patient(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO zo_praxis_patient (patient_id, praxis_id, erstbesuch) VALUES (?, ?, ?)",
        (int(get_val(form_data, "patient_id")), int(get_val(form_data, "praxis_id")), get_val(form_data, "erstbesuch") or None),
    )
    db.commit()
    db.close()


def create_mapping_behandlung_arzt(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO zo_behandlung_arzt (behandlung_id, arzt_id) VALUES (?, ?)",
        (int(get_val(form_data, "behandlung_id")), int(get_val(form_data, "arzt_id")),),
    )
    db.commit()
    db.close()



def update_behandlung(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "UPDATE behandlung SET fachrichtung = ?, behandlungsdauer = ?, datum = ? WHERE behandlung_id = ?",
        (get_val(form_data, "fachrichtung"), get_val(form_data, "behandlungsdauer"), get_val(form_data, "datum"), int(get_val(form_data, "behandlung_id"))),
    )
    db.commit()
    db.close()


def update_medikament(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "UPDATE medikament SET name = ?, wirkstoff = ?, hersteller = ? WHERE medikament_id = ?",
        (get_val(form_data, "name"), get_val(form_data, "wirkstoff"), get_val(form_data, "hersteller"), int(get_val(form_data, "medikament_id"))),
    )
    db.commit()
    db.close()


def update_rezept_medikament(form_data: dict[str, list[str]]) -> None:
    db = get_db()
    db.execute(
        "UPDATE zo_medikament_rezept SET medikament_id = ?, anzahl = ?, zobal_id = ? WHERE zomr_id = ?",
        (int(get_val(form_data, "medikament_id")), int(get_val(form_data, "anzahl")), int(get_val(form_data, "zobal_id")), int(get_val(form_data, "zomr_id"))),
    )
    db.commit()
    db.close()

def styles_css() -> bytes:
    return (BASE_DIR / "static" / "styles.css").read_bytes()


def app_js() -> bytes:
    return (BASE_DIR / "static" / "app.js").read_bytes()


def route_login_start(environ, start_response):
    form_data = parse_post(environ)
    login_id = get_val(form_data, "login_id")
    db = get_auth_db()
    user = db.execute("SELECT role FROM user_login WHERE login_id = ? AND is_active = 1", (login_id,)).fetchone()
    db.close()
    if not user:
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [login_frontpage("Login-ID nicht gefunden.")]

    if user["role"] == "patient":
        return redirect(start_response, f"/patienten/login?login_id={login_id}")
    if user["role"] == "arzt":
        return redirect(start_response, f"/arzt/login?login_id={login_id}")
    return redirect(start_response, f"/admin/login?login_id={login_id}")


def authenticate(role: str, environ, start_response):
    form_data = parse_post(environ)
    login_id = get_val(form_data, "login_id")
    password = get_val(form_data, "password")

    db = get_auth_db()
    user = db.execute(
        "SELECT user_id, login_id, role, password_hash, salt, patient_id, arzt_id, is_temp_password FROM user_login WHERE login_id = ? AND role = ? AND is_active = 1",
        (login_id, role),
    ).fetchone()
    db.close()

    if not user or not verify_password(password, user["password_hash"], user["salt"]):
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [role_login_page(role, login_id, "Ungültige Login-Daten")]

    if role == "patient" and user["is_temp_password"]:
        return redirect(start_response, f"/patienten/erstlogin?login_id={login_id}")

    payload = {"role": role, "login_id": login_id, "patient_id": user["patient_id"], "arzt_id": user["arzt_id"]}
    return redirect(start_response, dashboard_for_role(role), headers=[("Set-Cookie", build_session_cookie(payload))])


def dashboard_for_role(role: str) -> str:
    if role == "admin":
        return "/admin"
    if role == "arzt":
        return "/arzt"
    return "/patienten"


def require_role(session: dict | None, role: str, start_response):
    if not session or session.get("role") != role:
        return redirect(start_response, "/")
    return None


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    session = get_session(environ)
    query = parse_qs(environ.get("QUERY_STRING", ""))

    if path == "/styles.css":
        start_response("200 OK", [("Content-Type", "text/css; charset=utf-8")])
        return [styles_css()]

    if path == "/app.js":
        start_response("200 OK", [("Content-Type", "application/javascript; charset=utf-8")])
        return [app_js()]

    if path == "/" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [login_frontpage()]

    if path == "/login/start" and method == "POST":
        return route_login_start(environ, start_response)

    if path == "/patienten/login" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [role_login_page("patient", query.get("login_id", [""])[0])]

    if path == "/arzt/login" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [role_login_page("arzt", query.get("login_id", [""])[0])]

    if path == "/admin/login" and method == "GET":
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [role_login_page("admin", query.get("login_id", [""])[0])]

    if path == "/patient/authenticate" and method == "POST":
        return authenticate("patient", environ, start_response)

    if path == "/arzt/authenticate" and method == "POST":
        return authenticate("arzt", environ, start_response)

    if path == "/admin/authenticate" and method == "POST":
        return authenticate("admin", environ, start_response)

    if path == "/patienten/erstlogin" and method == "GET":
        login_id = query.get("login_id", [""])[0]
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [patient_first_login_page(login_id)]

    if path == "/patienten/erstlogin" and method == "POST":
        form_data = parse_post(environ)
        login_id = get_val(form_data, "login_id")
        new_password = get_val(form_data, "new_password")
        if len(new_password) < 8:
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [patient_first_login_page(login_id, "Passwort muss mindestens 8 Zeichen lang sein.")]

        pw_hash, salt = password_hash(new_password)
        db = get_auth_db()
        user = db.execute("SELECT patient_id FROM user_login WHERE login_id = ? AND role='patient'", (login_id,)).fetchone()
        db.execute(
            "UPDATE user_login SET password_hash = ?, salt = ?, is_temp_password = 0 WHERE login_id = ? AND role = 'patient'",
            (pw_hash, salt, login_id),
        )
        db.commit()
        db.close()

        if not user:
            return redirect(start_response, "/")
        payload = {"role": "patient", "login_id": login_id, "patient_id": user["patient_id"], "arzt_id": None}
        return redirect(start_response, "/patienten", headers=[("Set-Cookie", build_session_cookie(payload))])

    if path == "/logout" and method == "GET":
        return redirect(start_response, "/", headers=[("Set-Cookie", clear_session_cookie())])

    if path == "/admin" and method == "GET":
        denied = require_role(session, "admin", start_response)
        if denied:
            return denied
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [admin_dashboard()]

    if path == "/arzt" and method == "GET":
        denied = require_role(session, "arzt", start_response)
        if denied:
            return denied
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [arzt_dashboard(session)]

    if path == "/patienten" and method == "GET":
        denied = require_role(session, "patient", start_response)
        if denied:
            return denied
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [patient_dashboard(session)]

    arzt_handlers = {
        "/arzt/rezept/new": create_rezept,
        "/arzt/behandlung/update": update_behandlung,
        "/arzt/medikament/update": update_medikament,
        "/arzt/rezept-medikament/update": update_rezept_medikament,
    }

    if path in arzt_handlers and method == "POST":
        denied = require_role(session, "arzt", start_response)
        if denied:
            return denied
        form_data = parse_post(environ)
        arzt_handlers[path](form_data)
        return redirect(start_response, "/arzt")

    admin_handlers = {
        "/patient/new": create_patient,
        "/praxis/new": create_praxis,
        "/arzt/new": create_arzt,
        "/behandlung/new": create_behandlung,
        "/medikament/new": create_medikament,
        "/dokument/new": create_dokument,
        "/rezept/new": create_rezept,
        "/mapping/praxis-arzt": create_mapping_praxis_arzt,
        "/mapping/behandlung-dokument": create_mapping_behandlung_dokument,
        "/mapping/praxis-patient": create_mapping_praxis_patient,
        "/mapping/behandlung-arzt": create_mapping_behandlung_arzt,
    }

    if path in admin_handlers and method == "POST":
        denied = require_role(session, "admin", start_response)
        if denied:
            return denied
        form_data = parse_post(environ)
        admin_handlers[path](form_data)
        return redirect(start_response, "/admin")

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Not Found"]


if __name__ == "__main__":
    init_db()
    init_auth_db()
    with make_server("0.0.0.0", 5000, app) as server:
        print("Server running on http://0.0.0.0:5000")
        server.serve_forever()
