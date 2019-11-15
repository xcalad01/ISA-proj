//
// Created by Filip Caladi on 27/10/2019.
//

#ifndef UNTITLED_WHOIS_LACNIC_H
#define UNTITLED_WHOIS_LACNIC_H

#include "WhoisBase.h"

/**
 * Latin America, Caribean
 */
class Whois_LACNIC: public WhoisBase {
public:
    /**
     * Constructor.
     * @param whois_ip IP address  of whois server
     * @param ip IP address of specified  hostname
     * @param hostname
     * @param whois_hostname
     */
    Whois_LACNIC(char *whois_ip, char *ip, char* hostname, char *whois_hostname, bool ipv6);

    /**
     * Parse response and print out result.
     */
    void parse_response();

};


#endif //UNTITLED_WHOIS_LACNIC_H
