//
// Created by Filip Caladi on 27/10/2019.
//

#include "../h_sources/Whois_LACNIC.h"

Whois_LACNIC::Whois_LACNIC(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6): WhoisBase(whois_ip, ip, NULL, whois_hostname, ipv6) {
    sprintf(message, "%s\r\n",ip);
}

void Whois_LACNIC::parse_response() {
    string str_resp(response);
    // printf("%s\n", response.c_str());
    str_resp.append("\n");
    list <string> duplicates;

    printf("======== WHOIS ========\n");
    int idx;
    while(!str_resp.empty()) {
        if((idx = str_resp.find('\n')) != string::npos){
            int key_idx;

            string line = str_resp.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                str_resp = str_resp.erase(0, idx + 1);
                continue;
            }

            if((line.find("inetnum")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("owner")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("responsible")) != string::npos){
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
            else if((line.find("owner-c")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("ownerid")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }
            else if((line.find("changed")) != string::npos){
                printf("%s\n", line.c_str());
                duplicates.push_front(line);
            }

            str_resp = str_resp.erase(0, idx + 1);

        }
    }
}