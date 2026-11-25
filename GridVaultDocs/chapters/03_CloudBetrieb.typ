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

*Warum die Hash-Kette allein nicht reicht:* Ein Cloud-Administrator hat Zugriff auf Plattform, Dateisystem und Backups. Ändert oder löscht er einen Eintrag aus der Mitte, bricht die Kette und die Manipulation wird aufgedeckt (T6 a). Schneider er das Ende des Logs ab, bleiben alle vorhandenen Einträge gültig, und die Kette allein kann das abgeschnittene Ende nicht erkennen (T6 b). Da er auch die Backups kontrolliert, könnte er Log- und Ankerkopien gemeinsam kürzen, ohne dass eine Prüfung den Beweiskraftverlust bemerkt. Reine Integritätsprüfung im veränderbaren Speicher genügt also nicht.

*Gegenmaßnahme: WORM / Object Lock.* Audit-Daten werden daher in WORM-Speicher (Write Once Read Many) ausgelagert, in der Cloud typischerweise ein Objektspeicher mit Object Lock, etwa S3 im Compliance Mode. Ein einmal geschriebenes Objekt kann dort während der konfigurierten Retentionsperiode von niemandem gelöscht oder überschrieben werden, auch nicht vom Root-Account oder dem Cloud-Administrator selbst. Der Governance Mode genügt nicht, weil er privilegierten IAM-Rollen das Umgehen der Sperre erlaubt. Die Retentionsperiode wird mindestens so lange gewählt wie die Aufbewahrungspflicht für die Nachweisfähigkeit des Audit-Trails. Die Deployments schränken die IAM-Rechte zusätzlich ein: Die Anwendung erhält nur Schreib- und Leserecht auf das Bucket, Lösch- und Bypass-Berechtigungen existieren im Konto nicht.

*Rolle des Ankers aus dem Prototyp.* Im Prototyp spiegelt die Anwendung nach jedem Append die Sequenznummer und den Hash des letzten Eintrags in eine Anker-Datei in einem separaten Verzeichnis (`audit_anchor/`), bewusst getrennt vom Log und ohne Codepfad, den die Anwendung zum Umschreiben hätte. Damit ist der Anker der Platzhalter für WORM-Speicher, den ein Administrator nicht kontrolliert (M2). In der Cloud wird aus dem Platzhalter der echte Mechanismus: Jede Anker-Aktualisierung erzeugt eine neue, sofort verriegelte Objektversion im WORM-Bucket. Der Administrator kann das veränderbare Log-Ende und die Backups weiterhin kürzen, aber er kann die bereits verriegelten Anker-Versionen weder anpassen noch löschen. Das Prüfwerkzeug `verify_audit.py` prüft die gesamte Kette und vergleicht den berechneten End-Hash mit der Anker-Version der höchsten bekannten Sequenznummer. Eine Lücke, etwa ein gesperrter Anker mit Sequenznummer 223, während die geprüfte Kette vorher endet, beweist das Abschneiden. Da der Anker nur eine Sequenznummer und einen Hash enthält, keine personenbezogenen Daten, steht der Lösch- und Verwahrungszwang nicht mit dem Datenschutzkonzept in Konflikt.

