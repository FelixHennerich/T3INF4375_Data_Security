#import "../clean-dhbw-typst-template/lib.typ": *
#import "../glossary.typ": glossary-entries

= Testprotokoll (B4)

Alle Tests laufen als eigenständige Konsolenskripte gegen die lokale Umgebung. Vor dem Protokolldurchlauf wurde der
kanonische Datensatz mit `uv run python scripts/generate_testdata.py` erzeugt.

Alle Outputs sind im Anhang einsehbar unter folgender Nummerierung:

@protocol:login \
@protocol:abrechnung \
@protocol:kohorte \
@protocol:freigabe \
@protocol:chiffre \
@protocol:audit \

