# ISA-Whois tazatel
Tento projekt sa zaoberá problematikou získavania DNS záznamov (SOA, MX, CNAME ...) a dalších rozšírených informacií z rôznych **WHOIS** serverov o zadanom **hostname** s využitím knižníc **BSD Sockets**, **resolv** a ďalších potrebných pre vytvorenie dns dotazov a ich parsovanie.

Program je rozdelený do niekoľkých cpp/h súborov podľa nasledujúcich kriterií:
* DNS query (sekcia zaoberujúca sa dotazovaním a parsovaním DNS záznamov)
* Whois_[Internet Service Providers] (niektoré su spojené do jednej triedy nakoľko požadujú rovnakú hodnotu v dotaze na záznam a taktiež vracajú výsledok v rovnakom formáte)
* Ostatné Whois servery

## Príklad spustenia
./whois **-q** hostname/IPv4/IPv6 **-w** hostname/IPv4/IPv6


* ./isa-tazatel -q www.fit.vutbr.cz -w whois.ripe.net
* ./isa-tazatel -q 147.229.9.23 -w whois.ripe.net
* ./isa-tazatel -q 2001:67c:1220:809::93e5:917 -w 193.0.6.135 (zatial nefunguje)


## Zoznam odovzdanych suborov
* Makefile
* cpp_sources - obsahuje všetky zdrojové súbory
* h_sources - obsahuje všetky hlavičkové súbory
* README
* manual.pdf
