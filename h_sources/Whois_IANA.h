//
// Created by Filip Caladi on 15/11/2019.
//
#include "WhoisBase.h"

#ifndef UNTITLED_WHOIS_IANA_H
#define UNTITLED_WHOIS_IANA_H


class Whois_IANA: public WhoisBase {
public:
    /**
     * Constructor.
     * @param whois_ip IP address  of whois server
     * @param ip IP address of specified  hostname
     * @param hostname
     * @param whois_hostname
     */
    Whois_IANA(char *whois_ip, char *ip, char* hostname, char *whois_hostname, bool ipv6);

    /**
     * Parse response and print out result.
     */
    void parse_response();
};


#endif //UNTITLED_WHOIS_IANA_H
