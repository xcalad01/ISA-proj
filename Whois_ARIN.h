//
// Created by Filip Caladi on 27/10/2019.
//

#ifndef UNTITLED_WHOIS_ARIN_H
#define UNTITLED_WHOIS_ARIN_H

#include "WhoisBase.h"

class Whois_ARIN: public WhoisBase {
public:
    Whois_ARIN(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6);

    void parse_response();
};

#endif //UNTITLED_WHOIS_ARIN_H
