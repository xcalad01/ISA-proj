//
// Created by Filip Caladi on 27/10/2019.
//

#ifndef UNTITLED_WHOIS_APAFRI_H
#define UNTITLED_WHOIS_APAFRI_H

#include "WhoisBase.h"

/**
 * APNIC, AFRINIC whois server handle
 */
class Whois_ApAfRi: public WhoisBase{
public:
    /**
     * Constructor.
     * @param whois_ip IP address  of whois server
     * @param ip IP address of specified  hostname
     * @param hostname
     * @param whois_hostname
     */
    Whois_ApAfRi(char *whois_ip, char *ip, char* hostname, char *whois_hostname,  bool ipv6);

    /**
     * Parse response and print out result.
     */
    void parse_response();

};


#endif //UNTITLED_WHOIS_APAFRI_H
