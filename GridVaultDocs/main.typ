#import "clean-dhbw-typst-template/lib.typ": *
#import "glossary.typ": glossary-entries

#show: clean-dhbw.with(
  title: "Data Secruity - GridVault",
  authors: (
    (name: "Felix Hennerich", student-id: "2594549", 
     course: "TINF24F", course-of-studies: "Informatik Cybersecurity", 
    ),
  ),
  city: "Stuttgart",
  at-university: true, 
  type-of-thesis: "Dokumentation",
  show-declaration-of-authorship: true,
  bibliography: bibliography("sources.bib"),
  date: datetime.today(),
  glossary: glossary-entries,          // glossary terms from external file (see below)
  language: "de",                      // en, de
  supervisor: (
    university: "Florian Schüssler"
  ),
  university: "Duale Hochschule Baden-Württemberg",
  university-location: "Stuttgart",
  university-short: "DHBW",
  appendix: [#include "chapters/99_Anhang.typ"],

  // for more options check the package documentation (https://typst.app/universe/package/clean-dhbw)
)


#include "chapters/01_ArchitekturAbgleich.typ"
#include "chapters/02_Schutzbedarf.typ"
#include "chapters/03_CloudBetrieb.typ"
#include "chapters/04_Testprotokolle.typ"
#include "chapters/05_Zweck.typ"
#include "chapters/06_Loeschung.typ"
#include "chapters/07_EUHosting.typ"
