//
// Created by Filip Caladi on 15/11/2019.
//

#include "../h_sources/Whois_IANA.h"

Whois_IANA::Whois_IANA(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6): WhoisBase(whois_ip, ip, NULL, whois_hostname, ipv6){
    sprintf(message, "%s\r\n",ip);
}

void Whois_IANA::parse_response() {
    response.append("\n");
    list <string> duplicates;
    printf("======== WHOIS ========\n");
    int idx;
    while(!response.empty()) {
        if ((idx = response.find('\n')) != string::npos) {
            string line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                response = response.erase(0, idx + 1);
                continue;
            }


            if ((line.find("inetnum")) != string::npos) {
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            } else if ((line.find("organisation")) != string::npos) {
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            } else if ((line.find("status")) != string::npos) {
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            } else if ((line.find("whois")) != string::npos) {
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            response = response.erase(0, idx + 1);
        }
    }
}