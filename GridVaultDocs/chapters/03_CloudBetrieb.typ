#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries

= Cloud-Betrieb und Zusammenarbeit mit dem Provider (B3)

== Shared Responsibility

#figure(
  table(
  columns: 3,
  stroke: .02cm,
  table.header([Sicherheitsaufgabe], [Anbieter], [Kunde]),
  [Physische Sicherheit], [\u{2713}], [],
  [OS-Patching], [\u{2713}], [],
  [Laufzeitumgebung], [\u{2713}], [\u{2713}],
  [Gateway-Logik], [], [\u{2713}],
  [Verwahrung des Hauptschlüssels], [], [\u{2713}],
  [Anker des Audit Trails], [\u{2713}], [\u{2713}],
  [Backups], [\u{2713}], [\u{2713}],
  [Identitäten der Mitarbeiter], [], [\u{2713}],
),
caption: [ Shared Responsibility in PaaS],

)
\ 
*IaaS*: Der Anbieter hätte nur noch die Aufgabe die Physische Sicherheit zu gewährleisten. OS-Patching und komplette Laufzeitumgebung wandern zum Kunden (Anbieter Stellt weiterhin WORM für Audit Trail)

\ 

*SaaS*: Gateway-Logik-Konfiguration wandert von Stadtwerke zum Anbieter. Verwahrung des Hauptschlüssels sowie der Ankerabgleich bleibt beim Kunde. Verwahltung der Identitäten bleibt auch beim Kunde.

== Wer hat den Schlüssel?

== Public, Private oder Hybrid

== Audit-Trail in der Cloud