//
// Created by Filip Caladi on 31/10/2019.
//
#include <string>
#include <regex>

#include "WhoisBase.h"
using namespace std;

#ifndef UNTITLED_OTHERWHOIS_H
#define UNTITLED_OTHERWHOIS_H


class Whois_Other: public WhoisBase{
public:
    Whois_Other(char *whois_ip, char *ip, char* hostname, char *whois_hostname, bool ipv6);
    void parse_response();

private:
    void prepare__print_key(string key);
    string get_line(string response, int idx);
    void remove_trailing_print(string line);
    void parser1(string response);
    void parser2(string response);
    void parser3(string response);
    void parser4(string response);
    void parser5(string response);
    void parser6(string response);

};


#endif //UNTITLED_OTHERWHOIS_H
