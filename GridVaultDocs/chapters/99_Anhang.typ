= Anhang

== KI-Deklaration

Für die Bearbeitung der Aufgabe wurden folgende KI-Werkzeuge eingesetzt:

*1. Mistral Vibe (GLM 5.3): Code-Generierung* \
Dieses Modell wurde zur Generierung und Strukturierung des Codes verwendet. Dabei wurden Vorschläge des Modells für die Implementierung einzelner Programmteile sowie ganzer Klassen übernommen, geprüft und an die Aufgabenstellung angepasst.

*2. Mistral Large 4: Grammatikalische Korrektur und Fehlererkennung*\
Dieses Modell wurde abschließend zur sprachlichen Überarbeitung des Typst Dokuments eingesetzt. Es diente der Korrektur von Grammatik, Rechtschreibung und Zeichensetzung sowie der Erkennung inhaltlicher Unstimmigkeiten und unklarer Formulierungen im Text.

== Archtekturentwurf

=== Data Security

#image("../assets/archtekturentwurf/S01.png", height: 17cm)

#image("../assets/archtekturentwurf/S02.png", height: 17cm)

#image("../assets/archtekturentwurf/S03.png", height: 17cm)

#image("../assets/archtekturentwurf/S04.png", height: 17cm)

=== Data Protection

#image("../assets/archtekturentwurf/S05.png", height: 17cm)

#image("../assets/archtekturentwurf/S06.png", height: 17cm)

#image("../assets/archtekturentwurf/S07.png", height: 17cm)


#pagebreak()

== Testprotokolle (B4)

== T1 Login <protocol:login>

```text
$ uv run python test/t1_login.py
B4/T1 - Login mit falschem und dann korrektem Passwort
======================================================

[1] Login mit falschem Passwort (bekannter Nutzer)
    ok   HTTP 401
    ok   kein Session-Cookie bei Ablehnung
    Antwort: {"detail":"Invalid username or password"}
[2] Login mit unbekanntem Nutzer
    ok   Antwort: {"detail":"Invalid username or password"}
[3] Login mit korrektem Passwort
    ok   Login kunde_swn -> HTTP 200
    ok   Rolle im Sitzungszustand
    ok   Stadtwerk im Sitzungszustand
    ok   Session-Cookie HttpOnly
    ok   Ablehnung UND Erfolg im Audit-Trail
Audit-Eintraege dieses Tests (audit_trail.log):
  seq=386 ts=2026-11-25T16:05:27+00:00 tenant=SWN user=u1 role=kunde action=login object=user result=denied reason=password_wrong
  seq=387 ts=2026-11-25T16:05:28+00:00 tenant=- user=u0 role=unknown action=login object=user result=denied reason=user_unknown
  seq=388 ts=2026-11-25T16:05:28+00:00 tenant=SWN user=u1 role=kunde action=login object=user result=success reason=credentials_ok


ERGEBNIS: B4/T1 bestanden (8/8 Pruefungen)
```

#pagebreak()

== T2 Abrechnung <protocol:abrechnung>

```text
$ uv run python test/t2_abrechnung.py
B4/T2 - Abrechnung fragt eigenen / fremden Zählpunkt ab, versucht Rollenwechsel
===============================================================================

    ok   Login abrechnung_swn -> HTTP 200
[1] (a) Zählpunkt des EIGENEN Stadtwerks (SWN-001)  ->  GET /metering-points/SWN-001
    ok   HTTP 200
    ok   Summe = 18.17 kWh
    ok   Betrag vorhanden
    ok   Lastgang maskiert
    Antwort: {"mp_id":"SWN-001","name":"Erika Mustermann","tariff":"Haushaltsstrom","consumption_sum_kwh":18.17,"amount_eur":6.36,"lastprofil":"[NICHT FREIGEGEBEN]"}
[2] (b) Zählpunkt des ANDEREN Stadtwerks (SWB-001)  ->  GET /metering-points/SWB-001
    ok   HTTP 403
    ok   Access denied
[3] (c) Netzanalysten-Aktion als Abrechnung  ->  GET /analysis/plz/71543/hourly-sum
    ok   HTTP 403
    ok   Access denied

ERGEBNIS: B4/T2 bestanden (9/9 Pruefungen)
```

#pagebreak()


== T3 Kohorte <protocol:kohorte>

```text
$ uv run python test/t3_kohorte.py
B4/T3 - Netzanalyst: Kohorte n<3 und n>=3, Export
=================================================

    ok   Login netzanalyst_swn -> HTTP 200
[1] Kohorte mit n < 3  ->  GET /analysis/plz/71560/hourly-sum
    ok   HTTP 403
    ok   n angegeben
    ok   k angegeben
    Antwort: {"detail":"cohort too small (k-anonymity)","n":1,"k":3}
[2] Kohorte mit n >= 3  ->  GET /analysis/plz/71543/hourly-sum
    ok   HTTP 200
    ok   n = 3
    ok   24 Stundensummen
    ok   Stundensumme 07:00 = 2.4
    ok   keine Namen in der Antwort
    ok   keine Einzelwerte in der Antwort
    Stundensummen: [0.9, 0.75, 0.66, 0.6, 0.6, 0.75, 1.35, 2.4, 3.3, 2.85, 2.55, 2.7, 2.85, 2.7, 2.55, 2.4, 2.55, 3.0, 3.9, 4.35, 4.05, 3.15, 2.25, 1.35]
[3] Export fuer das Analyseverfahren  ->  POST /analysis/plz/71543/export
    ok   HTTP 200
    ok   3 Reihen
    ok   Pseudonym = 64 Hex-Zeichen
    ok   24 Stundenwerte je Reihe
    ok   keine Zählpunkt-IDs im Export
    ok   keine Namen im Export
    Pseudonyme: ['260a7d8b5f09c7a2...', '89b766aee9e8c063...', '3c71615e7e5678dd...']

ERGEBNIS: B4/T3 bestanden (16/16 Pruefungen)
```

#pagebreak()


== T4 Freigabe <protocol:freigabe>

```text
$ uv run python test/t4_freigabe.py
B4/T4 - Störungsdienst-Freigabekette inkl. ausserhalb/abgelaufen
================================================================

[1] ohne Freigabe  ->  GET /outages/plz/71543/metering-points
    ok   Login stoerung_swn -> HTTP 200
    ok   HTTP 403
    ok   generische Meldung
[2] Anfrage fuer das Segment stellen  ->  POST /outages/approval-requests
    ok   HTTP 200 - Anfrage offen
    Antwort: {"request_id":1,"state":"offen","plz":"71543","ticket_number":"T-2026-4242"}
    ok   Login leitstelle_swn -> HTTP 200
[3] Leitstelle sieht offene Anfrage  ->  GET /outages/approval-requests
    ok   Anfrage mit Ticket + Begründung sichtbar (Vier-Augen-Sicht)
    Ticket: T-2026-4242  PLZ: 71543
    Begruendung: Gemeldeter Spannungsabfall im Netzsegment, Pruefung vor Ort erforderlich.
[4] Freigabe durch die Leitstelle  ->  POST /outages/approval-requests/1/grant
    ok   HTTP 200 - genehmigt (30 Min. Gueltigkeit)
    Antwort: {"request_id":1,"state":"genehmigt","plz":"71543","ticket_number":"T-2026-4242","valid_until":"2026-11-25T16:35:29.952755"}
    ok   Login stoerung_swn -> HTTP 200
[5] Zugriff IM freigegebenen Segment  ->  GET /outages/plz/71543/metering-points
    ok   HTTP 200
    ok   3 Zählpunkte im Segment
    ok   Wert sichtbar, Name maskiert
    Zählpunkte: ['SWN-001', 'SWN-002', 'SWN-003']
    Name: [HIDDEN]  letzter Wert: {'timestamp': '2026-10-01T23:00:00', 'kwh': 0.45}
[6] Zugriff AUSSERHALB des Segments (PLZ 71560)
    ok   HTTP 403
[7] Zugriff nach Ablauf der Freigabe (Gueltigkeit verkuerzt)
    (Gueltigkeitsfenster im Ticket direkt in die Vergangenheit gezogen)
    ok   HTTP 403
ERGEBNIS: B4/T4 bestanden (13/13 Pruefungen)
```

#pagebreak()


== T5 Chiffrat-Swap <protocol:chiffre>

```text
$ uv run python test/t5_chiffrat_swap.py
B4/T5 - Integritätstest: vertauschte Chiffrate desselben Zählpunkts
===================================================================

    ok   Login abrechnung_swn -> HTTP 200
[1] Angreifer: zwei gueltige Chiffrate direkt in der DB vertauschen
    ok   Vertauschung durchgeführt (07:00 <-> 08:00)
[2] Zählpunkt als Abrechnung lesen  ->  GET /metering-points/SWN-001
    ok   HTTP 409 Integritätsverletzung
    ok   Zählpunkt in der Meldung
    ok   Zeitstempel in der Meldung
    Antwort: {"detail":"integrity violation: ciphertext does not match key or bound context 'SWN:SWN-001:2026-10-01T07:00:00'"}

ERGEBNIS: B4/T5 bestanden (5/5 Pruefungen)
```


#pagebreak()

== T6 Audit-Kette <protocol:audit>

```text
$ uv run python test/t6_audit_kette.py
B4/T6 - Audit-Trail: mittleren Eintrag löschen / Ende abschneiden
=================================================================

    ok   mindestens 10 Einträge im Audit-Trail
[1] (a) mittleren Eintrag löschen  ->  Zeile 206 (seq 206) entfernt -> Pruefwerkzeug:
TAMPERING DETECTED:
  - CHAIN BREAK at line 206: prev_hash does not match the hash of the previous entry - entry with seq 206 was deleted or reordered before this line
  - SEQUENCE GAP at line 206: expected seq 206, got 207 - an entry was deleted or reordered
    ok   Pruefwerkzeug Exit-Code 1
    ok   Kettenbruch mit Zeilenangabe (Zeile 206)

[2] Eintrag zurueckspielen -> Pruefwerkzeug:
OK: chain intact, anchor matches (410 entries)
    ok   Kette wieder intakt (Exit 0)

[3] (b) letzten Eintrag abschneiden  ->  seq 410 entfernt -> Pruefwerkzeug:
    ok   Hash-Kette allein erkennt (b) NICHT
TAMPERING DETECTED:
  - TRUNCATED TAIL detected via anchor: log ends at seq 409 (line 409), but the anchor records seq 410 - 1 trailing entry was cut off. The chain alone cannot show this: the removed entries took their evidence with them; only the external anchor exposes it.
    ok   Pruefwerkzeug Exit-Code 1
    ok   abschnittenes Ende nur über den ANKER erkannt

[4] Eintrag zurueckspielen -> Pruefwerkzeug:
OK: chain intact, anchor matches (410 entries)
    ok   Kette wieder intakt (Exit 0)


ERGEBNIS: B4/T6 bestanden (8/8 Pruefungen)
```
