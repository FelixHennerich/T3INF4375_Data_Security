#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries

= Testprotokoll (B4)

Alle Tests laufen als eigenständige Konsolenskripte gegen die lokale Umgebung
(`.env`: SQLite-Datenbank, Schlüsselverzeichnisse, Audit-Log); ein separater
Serverprozess ist nicht erforderlich. Vor dem Protokolldurchlauf wurde der
kanonische Datensatz mit `uv run python scripts/generate_testdata.py` erzeugt.
Jeder Befehl wurde einzeln ausgeführt; der Exit-Code 0 bestätigt jeweils das
erwartete Ergebnis. Jeder Test schreibt am Ende die während des Testlaufs
entstandenen Audit-Einträge in die Konsole. Die Manipulationen in T5 und T6
werden von den Skripten zurückgespielt, danach bestätigt
`uv run python scripts/verify_audit.py` erneut eine intakte Kette.

== T1 Login

Login mit falschem und dann korrektem Passwort: Ablehnung ohne Hinweis auf die
Existenz des Nutzers (identische Meldung für bekannten und unbekannten
Nutzernamen), Erfolg mit Rolle und Stadtwerk, beides im Audit-Trail.

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
  seq=442 ts=2026-11-26T06:57:52+00:00 tenant=SWN user=u1 role=kunde action=login object=user result=denied reason=password_wrong
  seq=443 ts=2026-11-26T06:57:52+00:00 tenant=- user=u0 role=unknown action=login object=user result=denied reason=user_unknown
  seq=444 ts=2026-11-26T06:57:52+00:00 tenant=SWN user=u1 role=kunde action=login object=user result=success reason=credentials_ok


ERGEBNIS: B4/T1 bestanden (8/8 Pruefungen)
```

== T2 Abrechnung

Abrechnung fragt (a) einen Zählpunkt des eigenen Stadtwerks ab: Summe und
Betrag, Lastgang maskiert; (b) ein Zählpunkt des anderen Stadtwerks und
(c) eine Netzanalysten-Aktion werden abgelehnt, nach außen generisch - die
wahren Ablehnungsgründe stehen nur im Audit-Trail.

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
    ok   wahre Ablehnungsgründe nur im Audit-Trail
Audit-Eintraege dieses Tests (audit_trail.log):
  seq=445 ts=2026-11-26T06:57:53+00:00 tenant=SWN user=u2 role=abrechnung action=login object=user result=success reason=credentials_ok
  seq=446 ts=2026-11-26T06:57:53+00:00 tenant=SWN user=u2 role=abrechnung action=read_metering_point object=mp:SWN-001 result=success reason=authorized
  seq=447 ts=2026-11-26T06:57:53+00:00 tenant=SWN user=u2 role=abrechnung action=read_metering_point object=mp:SWB-001 result=denied reason=tenant_mismatch
  seq=448 ts=2026-11-26T06:57:53+00:00 tenant=SWN user=u2 role=abrechnung action=read_cohort_hourly_sum object=plz:71543 result=denied reason=role_not_allowed


ERGEBNIS: B4/T2 bestanden (10/10 Pruefungen)
```

== T3 Kohorte

Netzanalyst: Kohorte mit n < 3 wird mit Angabe von n und k abgelehnt, Kohorte
mit n >= 3 liefert die Stundensummen, der Export enthält nur Pseudonyme.

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
    ok   Kleinzellen-Ablehnung UND Erfolg im Audit-Trail
Audit-Eintraege dieses Tests (audit_trail.log):
  seq=449 ts=2026-11-26T06:57:54+00:00 tenant=SWN user=u3 role=netzanalyst action=login object=user result=success reason=credentials_ok
  seq=450 ts=2026-11-26T06:57:54+00:00 tenant=SWN user=u3 role=netzanalyst action=read_cohort_hourly_sum object=plz:71560 result=denied reason=cohort_too_small
  seq=451 ts=2026-11-26T06:57:54+00:00 tenant=SWN user=u3 role=netzanalyst action=read_cohort_hourly_sum object=plz:71543 result=success reason=authorized
  seq=452 ts=2026-11-26T06:57:54+00:00 tenant=SWN user=u3 role=netzanalyst action=export_cohort object=plz:71543 result=success reason=authorized


ERGEBNIS: B4/T3 bestanden (17/17 Pruefungen)
```

== T4 Freigabe

Störungsdienst ohne Freigabe, Anfrage, Freigabe durch die Leitstelle,
Zugriff im Segment, Zugriff außerhalb des Segments, Zugriff nach Ablauf:
abgelehnt / offen / genehmigt / Wert sichtbar mit maskiertem Namen /
abgelehnt / abgelehnt. Die Freitext-Begründung bleibt im Ticketsystem, der
Audit-Trail führt nur die Ticket-Referenz.

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
    Antwort: {"request_id":1,"state":"genehmigt","plz":"71543","ticket_number":"T-2026-4242","valid_until":"2026-11-26T07:27:55.325796"}
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
    ok   Ablehnung UND Erfolg im Audit-Trail
Audit-Eintraege dieses Tests (Ticket-Referenz statt Freitext) (audit_trail.log):
  seq=453 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=login object=user result=success reason=credentials_ok
  seq=454 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=read_outage_segment object=plz:71543 result=denied reason=no_valid_grant
  seq=455 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=request_outage_access object=ticket:T-2026-4242 result=success reason=request_created
  seq=456 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=logout object=session result=success reason=user_logout
  seq=457 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u5 role=leitstelle action=login object=user result=success reason=credentials_ok
  seq=458 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u5 role=leitstelle action=list_outage_requests object=outage_list result=success reason=authorized
  seq=459 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u5 role=leitstelle action=grant_outage_access object=ticket:T-2026-4242 result=success reason=grant_issued
  seq=460 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u5 role=leitstelle action=logout object=session result=success reason=user_logout
  seq=461 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=login object=user result=success reason=credentials_ok
  seq=462 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=read_outage_segment object=plz:71543 result=success reason=authorized
  seq=463 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=read_outage_segment object=plz:71560 result=denied reason=no_valid_grant
  seq=464 ts=2026-11-26T06:57:55+00:00 tenant=SWN user=u4 role=stoerungsdienst action=read_outage_segment object=plz:71543 result=denied reason=grant_expired


ERGEBNIS: B4/T4 bestanden (14/14 Pruefungen)
```

== T5 Chiffrat-Swap

Vertauschung zweier gültiger Chiffrate desselben Zählpunkts direkt in der
Datenbank, danach Lesen als Abrechnung: Integritätsverletzung mit Angabe von
Zählpunkt und Zeitstempel. Authentifizierte Verschlüsselung allein erkennt
die Verlagerung nicht, da beide GCM-Tags an ihrem neuen Ort verifizieren;
erst die Kontextbindung (AAD) bindet jedes Chiffrat an Zählpunkt und
Zeitstempel. Das Skript spielt die Vertauschung zurück.

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
[3] Chiffrate zuruecktauschen
    ok   Vertauschung rueckgaengig
    ok   Zählpunkt wieder lesbar
    ok   Integritätsverletzung im Audit-Eintrag
Audit-Eintraege dieses Tests (audit_trail.log):
  seq=465 ts=2026-11-26T06:57:56+00:00 tenant=SWN user=u2 role=abrechnung action=login object=user result=success reason=credentials_ok
  seq=466 ts=2026-11-26T06:57:56+00:00 tenant=SWN user=u2 role=abrechnung action=read_metering_point object=mp:SWN-001:2026-10-01T07:00:00 result=denied reason=integrity_violation
  seq=467 ts=2026-11-26T06:57:56+00:00 tenant=SWN user=u2 role=abrechnung action=read_metering_point object=mp:SWN-001 result=success reason=authorized


ERGEBNIS: B4/T5 bestanden (8/8 Pruefungen)
```

== T6 Audit-Kette

Löschen eines mittleren Eintrags und Abschneiden des letzten Eintrags,
jeweils mit Prüfung durch das eigenständige Prüfwerkzeug: (a) Kettenbruch
mit Zeilenangabe, (b) Erkennung des abgeschnittenen Endes nur über den
externen Anker - die Hash-Kette selbst bleibt bei (b) stumm, da jeder
verbleibende Eintrag weiterhin korrekt verkettet. Das Prüfwerkzeug selbst
schreibt keine Audit-Einträge.

```text
$ uv run python test/t6_audit_kette.py
B4/T6 - Audit-Trail: mittleren Eintrag löschen / Ende abschneiden
=================================================================

    ok   mindestens 10 Einträge im Audit-Trail
[1] (a) mittleren Eintrag löschen  ->  Zeile 234 (seq 234) entfernt -> Pruefwerkzeug:
TAMPERING DETECTED:
  - CHAIN BREAK at line 234: prev_hash does not match the hash of the previous entry - entry with seq 234 was deleted or reordered before this line
  - SEQUENCE GAP at line 234: expected seq 234, got 235 - an entry was deleted or reordered
    ok   Pruefwerkzeug Exit-Code 1
    ok   Kettenbruch mit Zeilenangabe (Zeile 234)

[2] Eintrag zurueckspielen -> Pruefwerkzeug:
OK: chain intact, anchor matches (467 entries)
    ok   Kette wieder intakt (Exit 0)

[3] (b) letzten Eintrag abschneiden  ->  seq 467 entfernt -> Pruefwerkzeug:
    ok   Hash-Kette allein erkennt (b) NICHT
TAMPERING DETECTED:
  - TRUNCATED TAIL detected via anchor: log ends at seq 466 (line 466), but the anchor records seq 467 - 1 trailing entry was cut off. The chain alone cannot show this: the removed entries took their evidence with them; only the external anchor exposes it.
    ok   Pruefwerkzeug Exit-Code 1
    ok   abschnittenes Ende nur über den ANKER erkannt

[4] Eintrag zurueckspielen -> Pruefwerkzeug:
OK: chain intact, anchor matches (467 entries)
    ok   Kette wieder intakt (Exit 0)

    ok   Sequenznummern lueckenlos - rueckgespielte Eintraege vollstaendig
Audit-Eintraege dieses Tests (audit_trail.log):
  (keine neuen Eintraege)


ERGEBNIS: B4/T6 bestanden (9/9 Pruefungen)
```
