//
// Created by Filip Caladi on 31/10/2019.
//

#include "../h_sources/OtherWhois.h"

OtherWhois::OtherWhois(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6): WhoisBase(whois_ip, ip, NULL, whois_hostname, ipv6){
    sprintf(message, "%s\r\n", hostname + 4);
}

void OtherWhois::parse_response() {
    response.append("\n");
    list <string> duplicates;

    printf("======== WHOIS ========\n");
    if (response.find("Registrant type:") != string::npos){
        parser1(response);
    }
    else if (response.find("Registry Domain ID:") != string::npos){
        parser2(response);
    }
    else if (response.find("holder-c:") != string::npos){
        parser3(response);
    }
    else if (response.find("Domain servers in listed order:") != string::npos ||
             response.find("** Sponsoring Organisation:") != string::npos ||
             response.find("Owner:") != string::npos){
        parser4(response);
    }
    else if (response.find("registrant-organization:") != string::npos){
        parser5(response);
    }
    else
        printf("%s\n", response.c_str());

}

void OtherWhois::prepare__print_key(string key) {
    key = key.substr(0, key.size()-1);
    key = std::regex_replace(key, std::regex("^ +| +$|( ) +"), "$1");
    printf("%s ", key.c_str());
}

string OtherWhois::get_line(string response, int idx) {
    response = response.erase(0, idx + 1);
    idx = response.find('\n');
    return response.substr(0, idx);
}

void OtherWhois::remove_trailing_print(string line) {
    line.erase(line.begin(), std::find_if(line.begin(), line.end(), std::bind1st(std::not_equal_to<char>(), ' ')));
    printf("%s\n", line.c_str());
}

void OtherWhois::parser1(string response) {
    int idx;
    list <string> duplicates;
    string line;
    while(!response.empty()) {
        if((idx = response.find('\n')) != string::npos){
            line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                response = response.erase(0, idx + 1);
                continue;
            }

            if((line.find("Registrant type:")) != string::npos ||
               (line.find("Registrant:")) != string::npos ||
               (line.find("Registrar:")) != string::npos ||
               (line.find("Relevant dates:")) != string::npos ||
               (line.find("Registration status:")) != string::npos) {

                duplicates.push_front(line);
                prepare__print_key(line);
                line = get_line(response, idx);
                remove_trailing_print(line);
                duplicates.push_front(line);

            }
            else if((line.find("Registrant's address:")) != string::npos){
                prepare__print_key(line);
                printf("\n");
                line = get_line(response, idx);
                while(line != "\r"){
                    printf("%s\n", line.c_str());
                    duplicates.push_front(line);
                    response = response.erase(0, idx + 1);
                    idx = response.find('\n');
                    line = response.substr(0, idx);
                }
            }
        }
        response = response.erase(0, idx + 1);
    }
}

void OtherWhois::parser2(string response) {
    int idx;
    list <string> duplicates;
    string line;
    while(!response.empty()) {
        if((idx = response.find('\n')) != string::npos) {
            line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                response = response.erase(0, idx + 1);
                continue;
            }

            if ((line.find("Registrar:")) != string::npos ||
                (line.find("Registrant ")) != string::npos||
                (line.find("Admin ")) != string::npos ||
                (line.find("Tech ")) != string::npos ||
                (line.find("Billing ")) != string::npos){
                duplicates.push_front(line);
                printf("%s\n", line.c_str());
            }

        }
        response = response.erase(0, idx + 1);
    }
}

void OtherWhois::parser3(string response) {
    int idx;
    list<string> duplicates;
    string line;
    while (!response.empty()) {
        if ((idx = response.find('\n')) != string::npos) {
            line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                if(line.find("nic-hdl:") != string::npos)
                    while(!line.empty()){
                        response = response.erase(0, idx + 1);
                        idx = response.find('\n');
                        line = response.substr(0, idx);
                    }
                response = response.erase(0, idx + 1);
                continue;
            }

            if ((line.find("-c:")) != string::npos ||
                (line.find("registrar:")) != string::npos ||
                (line.find("source:")) != string::npos ||
                (line.find("type:")) != string::npos){
                //(line.find("Billing ")) != string::npos) {
                duplicates.push_front(line);
                printf("%s\n", line.c_str());
            }
            else if ((line.find("nic-hdl:")) != string::npos) {
                duplicates.push_front(line);
                printf("\n%s\n", line.c_str());
                response = response.erase(0, idx + 1);
                idx = response.find('\n');
                line = line = response.substr(0, idx);
                while (!line.empty()) {
                    printf("%s\n", line.c_str());
                    response = response.erase(0, idx + 1);
                    idx = response.find('\n');
                    line = line = response.substr(0, idx);
                }
                printf("\n");
            }
        }
        response = response.erase(0, idx + 1);
    }
}

void OtherWhois::parser4(string response) {
    int idx;
    list <string> duplicates;
    string line;
    while(!response.empty()) {
        if ((idx = response.find('\n')) != string::npos) {
            line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                while (!line.empty()) {
                    response = response.erase(0, idx + 1);
                    idx = response.find('\n');
                    line = response.substr(0, idx);
                }
                response = response.erase(0, idx + 1);
                continue;
            }
        }

        if((line.find("Registrant:")) != string::npos ||
           (line.find("Administrative Contact:")) != string::npos ||
           (line.find("Technical Contact:")) != string::npos ||
           (line.find("Billing Contact:")) != string::npos ||
           (line.find("Sponsoring Organisation:")) != string::npos ||
           (line.find("Owner:")) != string::npos){
            duplicates.push_front(line);
            printf("\n%s\n", line.c_str());
            response = response.erase(0, idx + 1);
            idx = response.find('\n');
            line = line = response.substr(0, idx);
            while(!line.empty()){
                printf("%s\n", line.c_str());
                response = response.erase(0, idx + 1);
                idx = response.find('\n');
                line = line = response.substr(0, idx);
            }
        }
        response = response.erase(0, idx + 1);
    }
}

void OtherWhois::parser5(string response) {
    int idx;
    list <string> duplicates;
    string line;
    while(!response.empty()) {
        if ((idx = response.find('\n')) != string::npos) {
            line = response.substr(0, idx);
            if (!check_duplicates(duplicates, line)) {
                response = response.erase(0, idx + 1);
                continue;
            }
        }

        if ((line.find("Registrar:")) != string::npos ||
            (line.find("registrant-")) != string::npos ||
            (line.find("admin-")) != string::npos ||
            (line.find("tech-")) != string::npos ||
            (line.find("billing-")) != string::npos){
            duplicates.push_front(line);
            printf("%s\n", line.c_str());
        }
        response = response.erase(0, idx + 1);
    }
}