//
// Created by Filip Caladi on 27/10/2019.
//

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <list>
#include <errno.h>
#include <cstring>

#ifndef WHOISBASE_H
#define WHOISBASE_H

using namespace std;

/**
 * Base class for  all whois handles.
 */
class WhoisBase {
public:
    /**
     * Constructor.
     * @param whois_ip IP address  of whois server
     * @param ip IP address of specified  hostname
     * @param hostname
     * @param whois_hostname
     */
    WhoisBase(char *whois_ip, char *ip, char* hostname, char *whois_hostname, bool ipv6);

    /**
     * Function for querying whois server.
     */
    void whois_query();

    /**
     * Free resources
     */
    void free_resources();

private:
    char *ip_whois;
    char *whois_name;
    int sock;
    struct sockaddr_in destAddr;
    struct sockaddr_in6 destAddr6;
    bool IPV6;
    char buffer[1000];

protected:
    string response;
    char *message;
    int idx;
    list <string> duplicates;
    string line;

    /**
     * Checks for lines already printed out, bcs. of whois's server duplicate lines in response.
     * @param dupl List of already printed out lines.
     * @param elem Actual processing line.
     * @return True if line was not processed already.
     */
    bool check_duplicates(list <string> dupl, string elem);
};



#endif // WHOISBASE_H
