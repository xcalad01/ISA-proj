//
// Created by Filip Caladi on 27/10/2019.
//

#include "../h_sources/WhoisBase.h"

WhoisBase::WhoisBase(char *whois_ip, char *ip, char *hostname, char *whois_hostname, bool ipv6) {
    whois_name = (char*)malloc(strlen(whois_hostname));
    strcpy(whois_name, whois_hostname);

    ip_whois = (char *)malloc(strlen(whois_ip));
    strcpy(ip_whois, whois_ip);

    message = (char*)malloc(strlen(ip));
    IPV6 = ipv6;

    if (ipv6){
        sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        destAddr6.sin6_family = AF_INET6;
        destAddr6.sin6_port = htons(43);
        inet_pton(AF_INET6, whois_ip, &destAddr6.sin6_addr);
    }
    else {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(43);
        destAddr.sin_addr.s_addr = inet_addr(whois_ip);
    }
}

void WhoisBase::whois_query() {
    int err;
    if(IPV6)
        err = connect(sock, (const struct sockaddr*)(&destAddr6), sizeof(destAddr6));
    else
        err = connect(sock, (const struct sockaddr*)(&destAddr), sizeof(destAddr));

    if (err < 0 ){
        printf("Could not connect to whois server\nExiting ...\n");
        exit(-1);
    }

    err = send(sock, message, 100, 0);
    if (err < 0){
        printf("Could not send data to whois server\nExiting ...\n");
        exit(-1);
    }

    while(recv(sock, buffer, 1000, 0)){
        response.append(buffer);
    }
}

void WhoisBase::free_resources() {
    free(ip_whois);
    free(message);
}

bool WhoisBase::check_duplicates(list <string> dupl, string elem){
    list <string> :: iterator element;
    for(element = dupl.begin(); element != dupl.end(); element++) {
        if (*element == elem)
            return false;
    }

    return true;
}