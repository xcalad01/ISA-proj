whois: main.cpp WhoisBase.cpp Whois_ApAfRi.cpp
	g++ -g -o whois main.cpp WhoisBase.cpp Whois_ApAfRi.cpp  Whois_ARIN.cpp Whois_LACNIC.cpp OtherWhois.cpp DNS_Query.cpp -lresolv

clean:
	rm whois
