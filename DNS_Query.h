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


class DNS_Query {
public:
    DNS_Query(char* host, char *ip, bool ipv6);
    void run_dns();


private:
    string extract_name_server(ns_msg handle, ns_sect section);
    string query_for_ns(string domain);
    void query_for_hostname_info(char* query_value, int query_type, struct hostent* name_ser);
    void parse_soa(ns_rr resource_record, ns_msg handler);
    void parse_mx(ns_rr resource_record, ns_msg handler);
    void parse_ptr(ns_rr resource_record, ns_msg handler);
    void parse_cname(ns_rr resource_record, ns_msg handler);
    char* reverseStr(string str);

    char *hostname;
    char *host_ip;
    bool ipv6;
    int query_types[4] = {ns_t_soa, ns_t_cname, ns_t_mx};

};


#endif //UNTITLED_DNS_QUERY_H
