# ISA-Whois tazatel
Tento projekt sa zaobera problematikou ziskavania DNS zaznamov (SOA, MX, CNAME ...) a dotazavia sa na **whois server** pre rozsirene informacie o zadanom hostname.

Program je rozdeleny do niekolkych cpp/h suborov podla nasledujucich kriterii:
* DNS query
* Internet service providers whois (niektore su spojene to jednej cpp Class nakolko pozaduju rovnaku hodnoty v query a vracaju response v rovnakom formate)
* Other whois servery

## Priklad spustenia
./whois **-q** hostname/IPv4/IPv6 **-w** hostname/IPv4/IPv6


* ./isa-tazatel -q www.fit.vutbr.cz -w whois.ripe.net
* ./isa-tazatel -q 147.229.9.23 -w whois.ripe.net
* ./isa-tazatel -q 2001:67c:1220:809::93e5:917 -w 193.0.6.135 (zatial nefunguje)


## Zoznam odovzdanych suborov
* Makefile
* cpp_sources - obsahuje vsetky zdrojove subory
* h_sources - obsahuje vsetky hlavickove subory
* README
