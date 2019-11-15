//
// Created by Filip Caladi on 27/10/2019.
//

#include "Whois_ARIN.h"

Whois_ARIN::Whois_ARIN(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6): WhoisBase(whois_ip, ip, NULL, whois_hostname, ipv6) {
    sprintf(message, "%s\r\n",ip);
}

void Whois_ARIN::parse_response() {
    response.append("\n");
    list <string> duplicates;

    printf("======== WHOIS ========\n");
    int idx;
    while(!response.empty()) {
        if((idx = response.find('\n')) != string::npos){
            int key_idx;

            string line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                response = response.erase(0, idx + 1);
                continue;
            }

            if((line.find("NetRange")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("NetName")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("OrgName")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("Country")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("Address")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("OrgTechPhone")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("OrgAbusePhone")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("OrgAbuseHandle")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("OrgTechHandle")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }

            response = response.erase(0, idx + 1);

        }
    }
}