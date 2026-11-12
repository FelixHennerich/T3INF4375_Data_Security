#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries


= Architektur-Abgleich (B1)

== Abgleichstabelle

// kompakte Darstellung: kleinere Schrift, engere Zellabstände,  breite Umsetzungsspalte, schmale Statusspalte
#show table: set text(size: 9pt)

#table(
  columns: (1.0fr, 1.35fr, 1.9fr, 1.0fr, 1.25fr),
  stroke: 0.5pt,
  inset: (x: 4pt, y: 4pt),
  align: (x, y) => if y == 0 { center } else { left },
  table.header([Merkmal], [Klausur], [Umsetzung], [Gleich / Anders], [Grund]),
  [Sprache und Libs], [Python FastAPI mit PostgreSQL], [Python FastAPI mit SQLlite / argon2-cffi und cryptography / uv als Paketmanager], [PostgreSQL -> SQLlite], [Entwicklungsumgebung mit einfacher Möglichkeit der Migration],
  [Ablage des Hauptschlüssels], [Separater Schlüsseldienst in extra Service], [256-Bit-Hauptschlüssel je Stadtwerk als Hex-Datei in keys/<tenant>.key / Schlüsseldienst als Modul keys.py, kein eigener Prozess], [Kein extra service], [Extra service würde im produktivbetrieb mit der keys.py aufgebaut werden.],
  [Kontextbindung], [], [], [], [],
  [Mandantentrennung], [-], [Gateway prüft Stadtwerk Übereinstimmung vor jedem Objektzugriff & Mandant Hauptschlüssel benötigt], [-], [-],  
  [Störungsfreigabe], [Vier-Augen-Prinzip / Freigab läuft ab / Loggin], [Vier-Augen-Prinzip / Antragsteller kann nicht selber genehmigen / Freigabe 30 Minuten gültig], [-], [-],
  [Audit-Schutz], [], [Append Only bei Logs / SHA-256-Hash-Kette über alle Einträge / Externer Anker deckt abgeschnittenes Ende auf], [-], [-],
  [Löschlauf], [-], [Frist ab Messzeitstempel / Abgelaufene Daten werden gelöscht. Dry-Run zählt vorab / Einzelne Löschanfragen via DataKey löschung -> Daten unlesbar], [-], [-],
  [Berechtigungsprüfung], [-], [Zentrale Prüfkette im gateway.py], [-], [-],
)

