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

In der Public Cloud können unter anderem die skalierbare API sowie das Support und Ticket System betrieben werden. Entscheidend ist dabei, dass ausschließlich anonymisierte Daten verarbeitet werden dürfen. Dies betrifft insbesondere die Aggregationen, etwa die Kohortenabfragen und die aggregierten Studensummen je Postleitzahlengebiet.

Ein rein auf die Public Cloud beschränktes Modell ist jedoch nicht ausreichend, sodass ein hybrides Betriebsmodell notwendig ist. Der Schlüsseldienst inklusive der Hauptschlüssel, der Anker des Audit Trails sowie die Datenbank mit den personenbezogenen Lastgängen sollten in einer Private Cloud oder einer On Premise Lösung betrieben werden, da in diesen Komponenten auch Werte im Klartext im Arbeitsspeicher verarbeitet werden.

== Audit-Trail in der Cloud

Die Hashkette schützt nicht vollständig, da durch sie nur herausgefunden werden kann, wenn der vorherige Wert der Kette geändert oder gelöscht wird, da dann die Hashes nicht übereinstimmen. Wird das Ende der Log-Datei abgeschnitten, kann dies nicht bemerkt werden. Für diesen Fall muss ein externer Anker implementiert werden. Der Anker muss in einem WORM-Speicher abgelegt werden, damit der Cloud-Administrator diesen nicht ändern kann. Der Anker ist ebenfalls ein Hash, und zwar der spezifische Hash des letzten Eintrags inklusive der Sequenznummer des Log-Eintrags. Bei einer Prüfung werden der Hash und die Sequenznummer des letzten Log-Eintrags mit dem Anker im WORM-Speicher abgeglichen. Stimmen sie nicht überein, so ist die Manipulation aufgeflogen.