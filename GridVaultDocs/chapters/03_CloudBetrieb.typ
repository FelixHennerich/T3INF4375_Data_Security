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

Cloud-Native Keys verwaltet der Anbieter komplett selbst, bei BYOK importiert der Kunde seinen Schlüssel in die HSMs des Anbieters, bei HYOK bleibt der Schlüssel dauerhaft in Kundenhand. Die kundenverwalteten Varianten schützen alle Daten im Ruhezustand, da ein Plattform-Administrator ohne Schlüsselmaterial weder Chiffrate lesen noch das Crypto-Shredding eines Löschverlangens rückgängig machen kann. Nicht geschützt ist die Verarbeitung selbst, denn das Gateway hält Name, Adresse und Stundenwerte bei jeder Abfrage im Klartext im Arbeitsspeicher. Im Arbeitsspeicher gilt: Data in Use kann nur durch Laufzeithärtung, nicht durch Schlüsselverwahrung geschützt werden.

== Public, Private oder Hybrid

== Audit-Trail in der Cloud