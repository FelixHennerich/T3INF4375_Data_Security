#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries

= Testprotokoll (B4)

Alle Tests laufen als eigenständige Skripte gegen die lokale Umgebung. Vor dem Protokolldurchlauf wurde der Datensatz mit `uv run python scripts/generate_testdata.py` erzeugt.

Alle Outputs sind im Anhang einsehbar unter folgender Nummerierung:

T1 Login (@protocol:login) \
T2 Abrechnung (@protocol:abrechnung) \
T3 Kohorte (@protocol:kohorte) \
T4 Freigabe (@protocol:freigabe) \
T5 Chiffrat-Swap (@protocol:chiffre) \
T6 Audit (@protocol:audit) \

