//
// Created by Filip Caladi on 09/11/2019.
//

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <string>
#include <cstring>
#include <list>
#include <arpa/inet.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

using namespace std;
#ifndef UNTITLED_DNS_QUERY_H
#define UNTITLED_DNS_QUERY_H

/**
 * Class for work with DNS queries
 */
class DNS_Query {
public:
    /**
     * Constructor
     * @param host queyring hostname
     * @param ip queyring ip
     * @param ipv6 True if ip is IPv6 type
     */
    DNS_Query(char* host, char *ip, bool ipv6);

    /**
     * Main function of class
     */
    void run_dns();


private:
    /**
     * Parse name_server record from section
     * @param handle
     * @param section
     * @return
     */
    string extract_name_server(ns_msg handle, ns_sect section);

    /**
     * Queries for name_server record of given domain
     * @param domain
     * @return
     */
    string query_for_ns(string domain);

    /**
     * Main function of querying for hostname info
     * @param query_value what will be queried
     * @param query_type ns_t_ptr,  ns_t_mx .....
     * @param name_ser nameserver
     */
    void query_for_hostname_info(char* query_value, int query_type, struct hostent* name_ser);

    /**
     * Handler for parsing SOA record
     * @param resource_record
     * @param handler
     */
    void parse_soa(ns_rr resource_record, ns_msg handler);

    /**
     * Handler for parsing MX record
     * @param resource_record
     * @param handler
     */
    void parse_mx(ns_rr resource_record, ns_msg handler);

    /**
     * Handler for parsing PTR record
     * @param resource_record
     * @param handler
     */
    void parse_ptr(ns_rr resource_record, ns_msg handler);

    /**
     * Handler for parsing CNAME record
     * @param resource_record
     * @param handler
     */
    void parse_cname(ns_rr resource_record, ns_msg handler);

    /**
     * Reverse given string(IPv4) for ptr record
     * @param str
     * @return
     */
    char* reverse_ip_for_ptr(string str);

    char *hostname;
    char *host_ip;
    bool ipv6;
    int query_types[4] = {ns_t_soa, ns_t_cname, ns_t_mx, ns_t_ptr};

};


#endif //UNTITLED_DNS_QUERY_H
