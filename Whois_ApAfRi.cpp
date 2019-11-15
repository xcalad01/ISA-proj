//
// Created by Filip Caladi on 27/10/2019.
//

#include "Whois_ApAfRi.h"

Whois_ApAfRi::Whois_ApAfRi(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6): WhoisBase(whois_ip, ip, NULL, whois_hostname, ipv6) {
    sprintf(message, "%s\r\n",ip);
}

void Whois_ApAfRi::parse_response() {
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

            if((line.find("inetnum")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("netname")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("descr")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("country")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("address")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("phone")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("admin-c")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if ((line.find("% Information related to")) != string::npos){
                int prctg_idx = line.find('%');
                line = line.erase(0, prctg_idx);
                printf("\n%s\n", line.c_str());
                duplicates.clear();
                duplicates.push_front(line);
            }

            response = response.erase(0, idx + 1);

        }
    }
}