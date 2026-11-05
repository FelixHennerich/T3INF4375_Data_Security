# GridVault Entwicklungsplan

## 1. Ziel und Vorgaben

GridVault ist eine lokal lauffähige FastAPI-Anwendung für die getrennten Mandanten
Stadtwerke Neckartal (SWN) und Stadtwerke Bergland (SWB). Die Anwendung verarbeitet
stündliche Verbrauchswerte je Haushalt und muss die Rollen- und Sicherheitsvorgaben aus
`BasisSzenario.md`, `M1-DONE.md` und `M2-TODO.md` nachweisbar umsetzen.

**Ziel für Meilenstein 2:** Teil A als funktionsfähiges Backend einschließlich Tests und
Teil B als reproduzierbar belegte schriftliche Ausarbeitung.

### Ist-Stand

- `app/main.py` stellt bisher nur `/` und `/health` bereit.
- `pyproject.toml` enthält bisher im Wesentlichen FastAPI.
- `docker-compose.yml` stellt eine lokale PostgreSQL-15-Datenbank bereit.
- `keys/`, `.env` und `.env.example` existieren; echte Schlüssel und Passwörter bleiben außerhalb des Quelltexts.

### Nicht verhandelbare Randbedingungen

- Keine externen Dienste zur Laufzeit; PostgreSQL, Schlüsseldateien und Auditdateien laufen lokal.
- Keine selbst entwickelten kryptografischen Verfahren.
- Jede fachliche Datenabfrage läuft durch genau ein zentrales Gateway.
- Keine Namen, Lastgänge, Passwörter, Schlüssel oder Freitextbegründungen im Audit-Log.
- Änderungen an bestehenden Nutzerdateien werden nicht vorausgesetzt; der Plan ergänzt den aktuellen Stand schrittweise.

## 2. Fachliche Zielarchitektur

### Mandanten, Daten und Rollen

| Bereich        | Umsetzung                                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------------------------- |
| Mandanten      | SWN und SWB; jedes Konto gehört genau einem Stadtwerk                                                             |
| Testdaten      | Mindestens 8 Zählpunkte, 4 je Stadtwerk, je 24 Stundenwerte                                                       |
| Vertragsdaten  | Name und Adresse verschlüsselt; Zählpunkt-ID, Stadtwerk, PLZ und Tarif bleiben für Routing/Kohortenbildung lesbar |
| Lastgänge      | Jeder Stundenwert einzeln authentifiziert verschlüsselt                                                           |
| Abrechnung     | Name, Zählpunkt, Tarif, Summe und Betrag; Einzelwerte verlassen das Gateway nicht                                 |
| Netzplanung    | Nur Kohortensummen je Stunde, `n >= k`, Standard `k = 3`; Exporte mit Pseudonymen                                 |
| Störungsdienst | Nur aktueller Wert eines freigegebenen Zählpunkts im freigegebenen PLZ-Segment; Name `[HIDDEN]`                   |
| Leitstelle     | Offene Anfragen sehen und freigeben; keinerlei Messdatenzugriff                                                   |
| Kunde          | Ausschließlich eigener Zählpunkt mit vollständigen Vertrags- und Lastgangdaten                                    |

### Angreifermodelle aus M1

1. Cloud-Administrator ohne Schlüssel darf weder Lastgänge lesen noch Audit-Manipulationen unbemerkt durchführen.
2. Ein Angreifer mit Schreibzugriff auf die Datenbank darf Manipulation, Vertauschung und Löschung von Chiffraten nicht unbemerkt durchführen.
3. Ein neugieriger Netzanalyst darf einzelne Haushalte nicht durch Kleinzellen- oder Differenzabfragen rekonstruieren.
4. Ein Nutzer von SWB darf niemals Daten oder Schlüssel von SWN erreichen und umgekehrt.

## 3. Modulstruktur

```text
backend/
├── app/
│   ├── main.py                 # FastAPI und Router
│   ├── config.py               # typisierte Umgebungs-Konfiguration
│   ├── database.py             # PostgreSQL-Verbindung und Transaktionen
│   ├── models/                 # User, Session, MeterPoint, Consumption, Request, Approval
│   ├── schemas/                # öffentliche Request-/Response-Modelle
│   ├── services/
│   │   ├── auth_service.py     # Passwortprüfung und Sitzungen
│   │   ├── key_service.py      # einziger Zugriff auf externe Schlüssel
│   │   ├── crypto_service.py   # AES-256-GCM, AAD und Integritätsfehler
│   │   ├── gateway_service.py  # zentrale Autorisierung und Ausgabeformung
│   │   ├── approval_service.py # Vier-Augen-Prinzip und Ablauf
│   │   ├── audit_service.py    # Hash-Kette und externer Anker
│   │   └── deletion_service.py # Aufbewahrung, Löschung und Restore-Lauf
│   └── routers/                # dünne HTTP-Schicht ohne eigene Fachlogik
├── scripts/
│   ├── generate_test_data.py
│   ├── verify_audit.py
│   └── backup_restore.py
├── tests/
├── keys/                       # lokal, nicht versioniert
├── audit/                      # lokal, nicht versioniert
├── init-sql/
└── README.md
```

Router dürfen keine Schlüssel laden, keine Rollen selbst prüfen und keine Chiffrate
entschlüsseln. Diese Regeln gehören in die Services, die Datenabfragen ausschließlich im
Gateway zusammenführen.

## 4. Sicherheitsdesign

### 4.1 Identität und Sitzung (A1)

- Passwort-Hashing mit Argon2id oder bcrypt einschließlich Salt über die Bibliotheks-API.
- Loginfehler verwenden unabhängig von Benutzerexistenz dieselbe Meldung; bei unbekanntem Benutzer wird eine Dummy-Hashprüfung ausgeführt.
- HTTP- und Testausgaben enthalten keine Passwörter. Konsolen-Eingaben verwenden maskierte Eingabe.
- Nach erfolgreichem Login wird ein zufälliges, opakes Sitzungstoken erzeugt. Serverseitig liegen Token-Hash, Nutzer-ID, Stadtwerk, Rolle, Ablaufzeit und Widerrufsstatus.
- Jede spätere Aktion liest Identität, Rolle und Mandant aus der Sitzung, nie aus Clientparametern.

### 4.2 Schlüssel und Verschlüsselung (A2)

- Je Stadtwerk ein AES-256-Hauptschlüssel in einem externen Verzeichnis, getrennt von Quelltext und Datenbank.
- Je Stadtwerk ein separater HMAC-Schlüssel für Pseudonyme; er ist nicht der Hauptschlüssel.
- `KeyService` ist die einzige Stelle, die Schlüsseldateien liest.
- Name, Adresse und jeder Stundenwert werden mit AES-GCM verschlüsselt.
- `meter_point_id` und kanonischer Zeitstempel werden als Additional Authenticated Data (AAD) verwendet. Dadurch schlägt das Lesen fehl, wenn zwei gültige Chiffrate vertauscht werden.
- Zählpunkt-ID, Stadtwerk, PLZ und Tarif bleiben lesbar, weil sie für Mandantenfilter, Objektprüfung und Kohortenbildung benötigt werden. Sie enthalten allein keine Namen oder Lastgangwerte.
- Ein falscher Stadtwerk-Schlüssel muss bei der Entschlüsselung eine Integritätsverletzung auslösen.

Der Bonus wird erst nach dem Pflichtumfang umgesetzt: Ein pro Zählpunkt erzeugter Datenschlüssel
wird mit dem Hauptschlüssel gewrappt. Beim Löschverlangen wird der Datenschlüssel zerstört,
sodass auch alte verschlüsselte Backups nicht mehr lesbar sind.

### 4.3 Zentrales Gateway (A3, A7, A8)

Jede Datenoperation folgt unveränderlich dieser Reihenfolge:

1. Sitzung und Ablaufzeit prüfen.
2. Rolle für die angeforderte Aktion prüfen.
3. Stadtwerk der Sitzung mit dem Zielobjekt abgleichen.
4. Objektbezug prüfen: eigener Zählpunkt, eigene Kohorte oder gültige Freigabe.
5. Erst danach mit Kontextbindung entschlüsseln.
6. Aggregieren oder maskieren; Einzelwerte bleiben bei Abrechnung und Analyse intern.
7. Minimalen Erfolg oder die Ablehnung auditieren.

HMAC-SHA-256 erzeugt stabile Pseudonyme für Exporte. Ein unkeyed SHA-256 wäre wegen
vorhersagbarer Zählpunkt-IDs für Vorberechnung und Zuordnung geeignet.

### 4.4 Störungsfreigabe (A4)

- Der Störungsdienst hat anfangs keinen Datenzugriff.
- Eine Anfrage benötigt PLZ, Ticketnummer und eine Mindestlänge für die Begründung.
- Die Begründung bleibt im geschützten Ticketsystem und wird nicht in Audit oder Fehlermeldungen kopiert.
- Nur eine Leitstellenperson desselben Stadtwerks darf eine offene Anfrage freigeben.
- Antragsteller und Freigebender müssen verschieden sein.
- Die Freigabe gilt exakt für das beantragte Segment und standardmäßig 30 Minuten; die Testdauer ist konfigurierbar.
- Ablauf, falsches Segment, falscher Mandant und fehlende Freigabe führen zu Ablehnung und Audit-Eintrag mit Ticketreferenz.

### 4.5 Audit-Trail (A5)

`audit_trail.log` wird ausschließlich im Append-Modus geöffnet. Jeder Eintrag enthält:

- Sequenznummer und UTC-Zeitstempel
- Stadtwerk, pseudonyme Nutzerkennung und Rolle
- Aktion, minimierte Objektkennung, Ergebnis und sichere Begründung
- Hash des Vorgängers und eigener Hash

Der letzte Hash wird zusätzlich in einer getrennten Ankerdatei gespeichert. Das ersetzt im
Prototyp den externen WORM-/Object-Lock-Speicher. `scripts/verify_audit.py` läuft ohne Login
und ohne neuen Logeintrag. Es muss zwischen Kettenbruch bzw. geändertem Eintrag und
abgeschnittenem Ende durch Ankervergleich unterscheiden.

### 4.6 Löschung und Wiederherstellung (A6)

- Aufbewahrungsfristen für Lastgänge und Analyseexporte sind konfigurierbar.
- Der Fristbeginn ist je Datenart nachvollziehbar gespeichert.
- Rechtliche Aufbewahrung oder Legal Hold verhindert die jeweilige Löschung.
- Ein Löschlauf löscht nur berechtigte Inhalte und auditert ausschließlich Zeitpunkt, Datenart, Anzahl und Ergebnis.
- Eine Backup-Wiederherstellung wird simuliert und der Löschlauf erneut angewendet, ohne gelöschte Inhalte ins Audit zu schreiben.

## 5. Geplante HTTP-Schnittstelle

Die Router bleiben dünn und delegieren jede fachliche Operation an das Gateway:

| Endpunkt                                     | Zweck                                   |
| -------------------------------------------- | --------------------------------------- |
| `POST /auth/login`, `POST /auth/logout`      | Sitzung starten/beenden                 |
| `GET /me`                                    | Sitzungsdaten ohne Geheimnisse anzeigen |
| `GET /customer/meter/{id}`                   | eigener Zählpunkt                       |
| `GET /billing/meter/{id}`                    | Abrechnungsausgabe                      |
| `GET /analyst/cohort/{plz}`                  | Kohortensumme                           |
| `POST /analyst/export/{plz}`                 | pseudonymisierter Export                |
| `POST /fault/requests`                       | Störungsanfrage                         |
| `GET /control-center/requests`               | offene Anfragen desselben Stadtwerks    |
| `POST /control-center/requests/{id}/approve` | Freigabe                                |
| `GET /fault/meter/{id}`                      | freigegebener aktueller Wert            |

Administrations-, Lösch- und Restore-Kommandos werden getrennt von den normalen Fachrouten
geschützt. Fehlerantworten bleiben generisch und enthalten keine sensiblen Inhalte.

## 6. Umsetzung in Phasen

### Phase 0: Projektbasis

- Abhängigkeiten für PostgreSQL, ORM/Migrationen, Passwort-Hashing, `cryptography` und pytest ergänzen.
- `.gitignore` für `.env`, Schlüssel, Auditdateien, Exporte, Dumps und Testartefakte prüfen.
- Konfiguration für Datenbank, Schlüsselpfade, Sitzungsdauer, `k`, Freigabedauer, Auditpfade und Aufbewahrung anlegen.
- `/health` als Smoke-Test behalten.

### Phase 1: Datenmodell und Generator

- Tabellen für Mandanten, Nutzer, Sitzungen, Zählpunkte, Stundenwerte, Anfragen, Freigaben und Exporte anlegen.
- Eindeutigkeit von Zählpunkt plus Zeitstempel erzwingen.
- Generator für zwei Stadtwerke, mindestens acht Zählpunkte, 24 Werte und sechs Nutzer schreiben.
- Testdaten mit mindestens einer Kohorte `n < 3` und einer Kohorte `n >= 3` erzeugen.

### Phase 2: Authentifizierung und Kryptografie

- A1 implementieren und mit Unit-Tests absichern.
- Externe Schlüsselverwaltung, AES-GCM/AAD und HMAC-Pseudonyme implementieren.
- Testen: Roundtrip, falscher Schlüssel, veränderte Bytes und vertauschte Chiffrate.

### Phase 3: Gateway und Rollen

- Gateway mit fester Prüf-Reihenfolge implementieren.
- Alle fünf Rollenausgaben und Mandantentrennung umsetzen.
- Analyse-Kleinzellenschutz und pseudonymisierte Exporte ergänzen.
- Danach dünne FastAPI-Router anbinden.

### Phase 4: Freigabe, Audit und Löschung

- Vier-Augen-Workflow mit Segmentbindung und Ablaufzeit implementieren.
- Hash-Kette, externen Anker und unabhängiges Prüfskript implementieren.
- Löschlauf, Ausnahmebehandlung und Restore-Simulation implementieren.
- Datenarme Audit- und Fehlermeldungen durch Tests prüfen.

### Phase 5: Abgabe und Nachweis

- T1–T6 und zusätzliche Sicherheitsregressionstests ausführen.
- Konsolenausgaben/Screenshots und passende Audit-Einträge für B4 sichern.
- README, Teil-B-Ausarbeitung, Datenschutzhinweis als PDF, M1-Anhang und KI-Deklaration fertigstellen.
- Clean-Install aus frischem Checkout und Secret-Scan durchführen.

## 7. Test- und Abnahmekriterien

| Test | Durchführung                                                        | Erwartung                                                                                                |
| ---- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| T1   | Falsches und danach richtiges Passwort                              | Einheitliche Ablehnung; danach Rolle und Stadtwerk; beide Ereignisse auditert                            |
| T2   | Abrechnung: eigener Zählpunkt, fremdes Stadtwerk, Analyst-Aktion    | Eigene Summe/Betrag mit maskiertem Lastgang; Fremdmandant und falsche Rolle abgelehnt                    |
| T3   | Analyst: `n < 3`, `n >= 3`, Export                                  | Kleinzelle mit `n` und `k` abgelehnt; Stundensummen erlaubt; Export nur mit Pseudonymen                  |
| T4   | Störung ohne Freigabe, Anfrage, Freigabe, Segmentabweichung, Ablauf | Richtige Reihenfolge von Ablehnung, offen, Freigabe, Zugriff, Ablehnung, Ablauf; Ticketreferenz im Audit |
| T5   | Zwei Stundenwert-Chiffrate in der Datenbank vertauschen             | AAD-Prüfung meldet Integritätsverletzung mit Zählpunkt/Zeitstempel; Audit-Eintrag entsteht               |
| T6   | Mittleren Audit-Eintrag löschen, Ende abschneiden                   | Kettenbruch mit Position; abgeschnittenes Ende über Anker erkannt                                        |

Zusätzlich verpflichtend:

- Sitzung abgelaufen oder widerrufen: nächste Aktion abgelehnt.
- Kunde liest fremden Zählpunkt nicht, auch nicht im selben Stadtwerk.
- Leitstelle liest keine Messdaten und genehmigt keine eigene Anfrage.
- Analyst erhält nie Einzelwerte und keine Namen.
- SWB-Schlüssel und SWB-Sitzung funktionieren nicht für SWN.
- Audit und Fehlerausgaben enthalten keine Namen, Lastgänge oder Freitextbegründungen.
- Berechtigungsentzug wirkt vor der nächsten Abfrage.

## 8. Dokumentation für Teil B

Die Ausarbeitung umfasst 8–10 Seiten ohne Anhänge und behandelt:

1. **B1 Architekturabgleich:** M1 gegenüber Umsetzung für Technologie, Schlüsselablage, Kontextbindung, Mandantentrennung, Freigabe und Audit; mindestens zwei echte Reflexionen sowie drei verworfene Alternativen.
2. **B2 Schutzbedarf:** CIA-Tabelle, Lastgang versus Monatssumme, konkreter Differenzangriff und zwei Gegenmaßnahmen.
3. **B3 Cloud-Betrieb:** Shared Responsibility für PaaS, IaaS/SaaS-Verschiebungen, Cloud-Native/BYOK/HYOK, Hybridmodell und WORM/Object Lock.
4. **B4 Testprotokoll:** T1–T6 jeweils mit Ausgabe/Screenshot und Auditbeleg.
5. **B5 Transparenz:** Zwecke, Rechtsgrundlagen, erforderliche Datenfelder, Pseudonymisierung, Kundeninformation und Auskunftsanfrage; separater Datenschutzhinweis als PDF.
6. **B6 Löschung und Vorfall:** Fristentabelle, Restore-Verhalten, Rollenvergleiche und Bewertung des 20-Haushalte-Vorfalls.
7. **B7 EU/USA:** AVV, gemeinsame Verantwortlichkeit von SWN/SWB, mögliche US-Zugriffe, DPF/SCC/TIA und Kanada-Variante.
8. **KI-Deklaration:** eingesetzte Werkzeuge, Zweck, verworfene Vorschläge und Begründung.

## 9. Definition of Done

- Lokaler Start mit PostgreSQL und dokumentierten Befehlen funktioniert.
- Beide Mandanten, sechs Nutzer, fünf Rollen, acht Zählpunkte und 24 Werte je Zählpunkt sind reproduzierbar erzeugbar.
- Kein Geheimnis steht in Quelltext, Datenbank, Audit oder Git.
- Jede Datenabfrage läuft über das Gateway und erfüllt die festgelegte Prüf-Reihenfolge.
- A1–A9 sowie T1–T6 sind implementiert und durch Tests/Evidenz nachgewiesen.
- Falsche Schlüssel, Chiffratvertauschung, Kettenbruch und abgeschnittenes Audit-Ende werden erkannt.
- Löschung und Backup-Wiederherstellung sind demonstrierbar dokumentiert.
- README und Teil-B-Unterlagen erlauben eine Reproduktion aus einem frischen Checkout.
