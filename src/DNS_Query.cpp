//
// Created by Filip Caladi on 09/11/2019.
// Code inspired by: https://docstore.mik.ua/orelly/networking_2ndEd/dns/ch15_02.htm
//

#include "../h_sources/DNS_Query.h"

DNS_Query::DNS_Query(char *host, char* ip, bool ip_type) {
    hostname = (char*)malloc(strlen(host));
    strcpy(hostname, host);

    host_ip = (char*)malloc(strlen(ip));
    strcpy(host_ip, ip);

    ipv6 = ip_type;
}

char* DNS_Query::reverse_ip_for_ptr(string str)
{
    int pos;
    vector <string> substrs;
    char *reverse_ip = (char*)malloc(28);
    string tmp = str;
    char delimeter;

    delimeter = '.';

    while((pos = tmp.find(delimeter)) != string::npos){
        substrs.push_back(tmp.substr(0, pos));
        tmp = tmp.substr(pos + 1, tmp.size() - 1);
    }
    substrs.push_back(tmp);


    sprintf(reverse_ip, "%s.%s.%s.%s.in-addr.arpa", substrs.at(3).c_str(), substrs.at(2).c_str(),
            substrs.at(1).c_str(), substrs.at(0).c_str());
    return reverse_ip;


}

void DNS_Query::run_dns() {
    string name_ser = query_for_ns(hostname);
    string host(hostname);
    struct hostent *name_ser_ip;
    name_ser_ip = gethostbyname(name_ser.c_str());
    if(name_ser_ip == NULL){
        printf("get_host_by_name failed: %s\nExiting ...", name_ser.c_str());
        exit(-1);
    }

    if(host.find("www.") != string::npos)
        host = host.substr(4);

    for(int query_type : query_types) {
        if(query_type == ns_t_ptr) {
            string str(host_ip);
            if(ipv6)
                continue;
            query_for_hostname_info(reverse_ip_for_ptr(str), query_type, name_ser_ip);
        }
        else {
            if(query_type == ns_t_cname)
                query_for_hostname_info((char*)host.insert(0, "www.").c_str(), query_type, name_ser_ip);
            else
                query_for_hostname_info((char*)host.c_str(), query_type,  name_ser_ip);

        }

    }
}

string DNS_Query::extract_name_server(ns_msg handle, ns_sect section) {
    ns_rr res_record;

    if (ns_parserr(&handle, section, 0, &res_record)){
        printf("ERROR:Failed to parse name_server response\nExiting ...\n");
        exit(-1);
    }

    char *response = (char*)malloc(MAXDNAME);
    if (ns_rr_type(res_record) == ns_t_ns){
        if (ns_name_uncompress(
                ns_msg_base(handle),
                ns_msg_end(handle),
                ns_rr_rdata(res_record),
                response,
                MAXDNAME) < 0)
        {
            printf("Failed to uncompress ns_record\nExiting ...\n");
            exit(-1);
        }
    }

    printf("NS: %s\n", response);
    return string(response);
}

string DNS_Query::query_for_ns(string domain) {
    int responseLen;
    ns_msg handler;

    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;

    if (domain.find("www.") != string::npos){
        domain = domain.substr(4);
    }

    if((responseLen =
                res_query(
                        domain.c_str(),
                        ns_c_in,
                        ns_t_ns,
                        (u_char*)&response,
                        sizeof(response)
                )) < 0) {
        printf("Could not execute query for %s\nExiting ...\n", domain.c_str());
        exit(-1);
    }

    if (ns_initparse(response.buf, responseLen, &handler) < 0){
        printf("Whoops something went wrong. Try again or check input parametres\n");
        exit(-1);
    }

    return extract_name_server(handler, ns_s_an);
}

void DNS_Query::query_for_hostname_info(char *query_value, int query_type, struct hostent *host) {
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response, query;

    int responseLen, queryLen;
    ns_msg handle; /* handle for response message */
    ns_rr resource_record; /* expanded resource record */

    _res.options &= ~(RES_DNSRCH | RES_DEFNAMES);

    (void) memcpy((void *)&_res.nsaddr_list[0].sin_addr, (void *)host->h_addr_list[0], (size_t)host->h_length);
    _res.nscount = 1;
    _res.retry = 2;

    _res.options &= ~RES_RECURSE;
    queryLen = res_mkquery(
            ns_o_query,
            query_value,
            ns_c_in,
            query_type,
            (u_char*)NULL,
            0,
            (u_char*)NULL,
            (u_char*)&query,
            sizeof(query)
    );
    errno = 0;
    if((responseLen = res_send((u_char*)&query,
                               queryLen,
                               (u_char *)&response,
                               sizeof(response)))
       < 0){
        if(errno == ECONNREFUSED){
            return;
        }
        else {
            return;
        }
    }

    if (ns_initparse(response.buf, responseLen, &handle) < 0){
        return;
    }

    if(ns_msg_getflag(handle, ns_f_rcode) != ns_r_noerror){
        return;
    }

    if(!ns_msg_getflag(handle, ns_f_aa)){
        return;
    }

    if (ns_parserr(&handle, ns_s_an, 0, &resource_record)){
        if (errno != ENODEV){
            return;
        }
    }

    if (ns_rr_type(resource_record) != query_type){
        return;
    }

    switch(query_type){
        case ns_t_soa:
            parse_soa(resource_record, handle);
            break;

        case ns_t_mx:
            parse_mx(resource_record, handle);
            break;

        case ns_t_ptr:
            parse_ptr(resource_record, handle);
            break;

        case ns_t_cname:
            parse_cname(resource_record, handle);
            break;
    }
}

void DNS_Query::parse_soa(ns_rr resource_record, ns_msg handler) {
    char *buf = (char *)malloc(MAXDNAME);
    ns_name_uncompress(
            ns_msg_base(handler),
            ns_msg_end(handler),
            ns_rr_rdata(resource_record),
            buf,
            MAXDNAME);
    printf("SOA: %s\n", buf);
}

void DNS_Query::parse_mx(ns_rr resource_record, ns_msg handler) {
    char resp[4096];
    ns_sprintrr(&handler, &resource_record, NULL, NULL, (char*)resp, sizeof (resp));

    string str_resp(resp);
    int pos;
    while((pos=str_resp.find(' ')) != string::npos){
        if (pos == 0)
            pos++;
        str_resp = str_resp.substr(pos, str_resp.size()-1);
    }

    printf("MX: %s\n", str_resp.c_str());

}

void DNS_Query::parse_ptr(ns_rr resource_record, ns_msg handler) {
    char resp[4096];
    ns_sprintrr(&handler, &resource_record, NULL, NULL, (char*)resp, sizeof (resp));
    printf("PTR: %s\n",resp);
}

void DNS_Query::parse_cname(ns_rr resource_record, ns_msg handler) {
    char resp[4096];
    ns_sprintrr(&handler, &resource_record, NULL, NULL, (char*)resp, sizeof (resp));
    printf("CNAME: %s\n",resp);
}