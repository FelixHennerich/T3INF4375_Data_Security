#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries

= Schutzbedarf und Risiken der Datenaggregation (B2)

== CIA-Tabelle

// kompakte Darstellung wie in Kapitel B1
#show table: set text(size: 9pt)

#table(
  columns: (1.2fr, 1.3fr, 1.3fr, 1.3fr),
  stroke: 0.5pt,
  inset: (x: 4pt, y: 4pt),
  align: (x, y) => if y == 0 { center } else { left },
  table.header([Datenklasse], [Confidentiallity], [Integrity], [Availability]),
  [Vertragsstammdaten (Name, Adresse, ...)], [*Hoch* \ Daten Identifizieren Kunden unmittelbar aber es ergeben sich noch keine Verhaltensprofile], [*Hoch* \ Manipulierte Adresse führt zu falschen Abrechnungen], [*Hoch* \ Ohne Stammdaten kann keine Zuordnung zwischen Zählpunkt und Kunde mehr stattfinden und Betrieb stockt.],
  [Lastgangdaten \ (Stundenwerte)], [*Sehr Hoch* \ Stündliche Lastgänge verraten Gewohnheiten von Menschen wie beispielsweise ob jemand zuhause ist. -> Nützliche infos für Einbrüche], [*Hoch* \ Falsche Werte verfälschen Rechnungen wodurch falsche Rechnungen geschrieben werden], [*Mittel* \ Fehlende Werte zwischendrin können aus Zählerstand dennoch ermittelt werden. Nur schlecht für Netzanalyse],
  [Abrechnungsdaten (Verbrauchssumme, ...)], [*Mittel* \ Monatssumme zeigt Verbrauchsverhalten weiterhin nur nicht stundenaktuell], [*Sehr Hoch* \ Abrechnungen sind rechtsverbindliche Forderungen -> Falschabrechnung muss ausgeschlossen werden], [*Hoch* \ Abrechnungen müssen fristgerecht enstehen sonst verzögert sich Zahlungseingang],
)

== Lastgang vs. Monatssumme

Der stündliche Lastgang ist wesentlich sensibler da er auf genaue Gewohnheitsmuster und Tagesabläufe eines Menschen Rückschlüsse ziehen lässt. Beispielsweise kann genau gesehen werden zu welchen Uhrzeiten ein Mensch bei der Arbeit ist und das Haus / die Wohnung damit perfekt für einen Einbruch wäre. Hier schlägt der DSGVO Grundsatz nach Art. 5 Abs. 1 der Datenminimierung ein. Die Daten müssen gemäß des Zwecks erhoben werden. Für den Abrechnungszweck ist lediglich die Summe notwendig. \ Technisch entschlüsselt das Gateway die Stundenwerte nur intern, um die Summe zu bilden und gibt der Abrechnungs-Rolle ausschließlich Summe und Betrag aus.

== Re-Identifikation trotz k-Anonymität

== Gegenmaßnahmen