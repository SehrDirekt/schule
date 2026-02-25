PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS kontakt (
  kontakt_id INTEGER PRIMARY KEY AUTOINCREMENT,
  strasse_hausnummer TEXT NOT NULL,
  plz TEXT NOT NULL,
  ort TEXT NOT NULL,
  telefon_mobil TEXT,
  email TEXT
);

CREATE TABLE IF NOT EXISTS mensch (
  mensch_id INTEGER PRIMARY KEY AUTOINCREMENT,
  vor_nachname TEXT NOT NULL,
  kontakt_id INTEGER NOT NULL,
  FOREIGN KEY (kontakt_id) REFERENCES kontakt(kontakt_id)
);

CREATE TABLE IF NOT EXISTS versichertendaten (
  versicherungsnr TEXT PRIMARY KEY,
  kartennr TEXT,
  versicherungsart TEXT,
  krankenkasse TEXT
);

CREATE TABLE IF NOT EXISTS patient (
  patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
  geburtsdatum TEXT,
  geschlecht TEXT,
  mensch_id INTEGER NOT NULL,
  versicherungsnr TEXT,
  FOREIGN KEY (mensch_id) REFERENCES mensch(mensch_id),
  FOREIGN KEY (versicherungsnr) REFERENCES versichertendaten(versicherungsnr)
);

CREATE TABLE IF NOT EXISTS praxis (
  praxis_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kontakt_id INTEGER NOT NULL,
  FOREIGN KEY (kontakt_id) REFERENCES kontakt(kontakt_id)
);

CREATE TABLE IF NOT EXISTS arzt (
  arzt_id INTEGER PRIMARY KEY AUTOINCREMENT,
  fachrichtung TEXT,
  mensch_id INTEGER NOT NULL,
  FOREIGN KEY (mensch_id) REFERENCES mensch(mensch_id)
);

CREATE TABLE IF NOT EXISTS behandlung (
  behandlung_id INTEGER PRIMARY KEY AUTOINCREMENT,
  fachrichtung TEXT,
  behandlungsdauer TEXT,
  datum TEXT
);

CREATE TABLE IF NOT EXISTS dokumente (
  dokument_id INTEGER PRIMARY KEY AUTOINCREMENT,
  pfad TEXT,
  dokumentname TEXT,
  author TEXT
);

CREATE TABLE IF NOT EXISTS medikament (
  medikament_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  wirkstoff TEXT,
  hersteller TEXT
);

CREATE TABLE IF NOT EXISTS zo_praxis_patient (
  zopp_id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER NOT NULL,
  praxis_id INTEGER NOT NULL,
  erstbesuch TEXT,
  FOREIGN KEY (patient_id) REFERENCES patient(patient_id),
  FOREIGN KEY (praxis_id) REFERENCES praxis(praxis_id)
);

CREATE TABLE IF NOT EXISTS zo_praxis_arzt (
  zopal_id INTEGER PRIMARY KEY AUTOINCREMENT,
  arzt_id INTEGER NOT NULL,
  praxis_id INTEGER NOT NULL,
  beschaeftigungsstart TEXT,
  FOREIGN KEY (arzt_id) REFERENCES arzt(arzt_id),
  FOREIGN KEY (praxis_id) REFERENCES praxis(praxis_id)
);

CREATE TABLE IF NOT EXISTS zo_patient_behandlung (
  zopb_id INTEGER PRIMARY KEY AUTOINCREMENT,
  behandlung_id INTEGER NOT NULL,
  zopp_id INTEGER NOT NULL,
  FOREIGN KEY (behandlung_id) REFERENCES behandlung(behandlung_id),
  FOREIGN KEY (zopp_id) REFERENCES zo_praxis_patient(zopp_id)
);

CREATE TABLE IF NOT EXISTS zo_behandlung_arzt (
  zobal_id INTEGER PRIMARY KEY AUTOINCREMENT,
  behandlung_id INTEGER NOT NULL,
  arzt_id INTEGER NOT NULL,
  FOREIGN KEY (behandlung_id) REFERENCES behandlung(behandlung_id),
  FOREIGN KEY (arzt_id) REFERENCES arzt(arzt_id)
);

CREATE TABLE IF NOT EXISTS zo_behandlung_dokumente (
  zobdl_id INTEGER PRIMARY KEY AUTOINCREMENT,
  behandlung_id INTEGER NOT NULL,
  dokument_id INTEGER NOT NULL,
  FOREIGN KEY (behandlung_id) REFERENCES behandlung(behandlung_id),
  FOREIGN KEY (dokument_id) REFERENCES dokumente(dokument_id)
);

CREATE TABLE IF NOT EXISTS zo_medikament_rezept (
  zomr_id INTEGER PRIMARY KEY AUTOINCREMENT,
  rezept_id INTEGER NOT NULL,
  medikament_id INTEGER NOT NULL,
  anzahl INTEGER DEFAULT 1,
  zobal_id INTEGER,
  FOREIGN KEY (medikament_id) REFERENCES medikament(medikament_id),
  FOREIGN KEY (zobal_id) REFERENCES zo_behandlung_arzt(zobal_id)
);
