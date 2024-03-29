#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <resolv.h>
#include <errno.h>


#include "../h_sources/WhoisBase.h"
#include "../h_sources/Whois_ApAfRi.h"
#include "../h_sources/Whois_ARIN.h"
#include "../h_sources/Whois_LACNIC.h"
#include "../h_sources/Whois_IANA.h"
#include "../h_sources/Whois_Other.h"
#include "../h_sources/DNS_Query.h"
using namespace std;

/**
 * Class for parsing arguments
 */
class Arguments {
public:
    char *hostname = NULL;
    char *whois_hostname = NULL;
    char *dns_hostname = NULL;

    Arguments(int argc, char **argv, char *parse_string){
        int opt;
        while ((opt = getopt (argc, argv, parse_string)) != -1){
            switch (opt){
                case 'q':
                    qflag = true;
                    hostname = optarg;
                    break;

                case 'w':
                    wflag = true;
                    whois_hostname = optarg;
                    break;

                case 'd':
                    dns_hostname = optarg;
                    break;

                case '?':
                    if (optopt == 'q' || optopt == 'w' || optopt == 'd'){
                        printf("Option %c requires argument \n", optopt);
                    }
                    else {
                        printf("Unknown option %c \n", optopt);
                        exit(-1);
                    }

                default:
                    exit(-1);
            }
        }

        check_params();
    }

private:
    bool qflag = false;
    bool wflag = false;

    void check_params(){
        if (!qflag){
            printf("q option required!\n");
            exit(0);
        }
        else if (!wflag){
            printf("w option required\n");
            exit(0);
        }
    }
};

/**
 * Gets IP address of given server, and prints A or/and AAAA record.
 * @param server
 * @param ip
 * @param print
 */
void get_ip_address(char *server, char *ip, bool print) {
    struct addrinfo *res;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags |= AI_CANONNAME;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;


    if (getaddrinfo(server, "0", &hints, &res) != 0) {
        printf("%s   Wrong IPv4/IPv6 address or hostname\nExiting ...\n", server);
        exit(-1);
    }
    void *ptr;
    void *to_return = NULL;
    int to_return_fam = -1;

    while(res) {
        inet_ntop(res->ai_family, res->ai_addr->sa_data, ip, 100);

        switch (res->ai_family) {
            case AF_INET:
                ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                if(print)
                 printf("A: ");
                if (to_return == NULL) {
                    to_return = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                    to_return_fam = res->ai_family;
                }
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                if(print)
                 printf("AAAA: ");
                if (to_return == NULL) {
                    to_return = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                    to_return_fam = res->ai_family;
                }
                break;
        }
        if(print) {
            inet_ntop(res->ai_family, ptr, ip, 100);
            printf("%s\n", ip);
            res = res->ai_next;
        }
        else
            break;
    }

    if (to_return_fam != -1)
        inet_ntop(to_return_fam, to_return, ip, 100);
    else {
        printf("Get ip address  of hostname failed!\nExiting\n");
        exit(-1);
    }
}

/**
 * Checks what whois class should be instanciated, inits it and runs the class.
 * @param whois_ip
 * @param ip
 * @param hostname
 * @param whois_hostname
 * @param ipv6
 */
void runWhois(char *whois_ip, char *ip, char* hostname, char *whois_hostname, bool ipv6) {
    string wh(whois_hostname);

    if ((wh.find(".arin.")) != string::npos) {
        Whois_ARIN whois(whois_ip, ip, hostname, whois_hostname, ipv6);
        whois.whois_query();
        whois.parse_response();
        whois.free_resources();
    } else if ((wh.find(".iana.")) != string::npos) {
        Whois_IANA whois(whois_ip, ip, hostname, whois_hostname, ipv6);
        whois.whois_query();
        whois.parse_response();
        whois.free_resources();
    } else if ((wh.find(".apnic.")) != string::npos ||
               (wh.find(".afrinic.")) != string::npos ||
               (wh.find(".ripe.")) != string::npos) {
        Whois_ApAfRi whois(whois_ip, ip, hostname, whois_hostname, ipv6);
        whois.whois_query();
        whois.parse_response();
        whois.free_resources();
    } else if ((wh.find(".lacnic.")) != string::npos) {
        Whois_LACNIC whois(whois_ip, ip, hostname, whois_hostname, ipv6);
        whois.whois_query();
        whois.parse_response();
        whois.free_resources();
    } else {
        Whois_Other whois(whois_ip, ip, hostname, whois_hostname, ipv6);
        whois.whois_query();
        whois.parse_response();
        whois.free_resources();
    }
}

/**
 * Converts given IPv4 to hostname
 * @param ip
 * @param ret
 */
void ip4_to_hostname(char *ip, char *ret){
    struct hostent *host;
    struct in_addr addr;
    inet_pton(AF_INET,ip, &addr);
    errno = 0;
    host = gethostbyaddr(&addr, sizeof(ip), AF_INET);
    if (host == NULL){
        printf("Cant resolve %s to hostname\nExiting...\n", ip);
        exit(-1);
    }
    strcpy(ret, host->h_name);
}
/**
 * Converts given IPv6 to hostname
 * @param ip
 * @param ret
 */
void ip6_to_hostname(char *ip, char *ret){
    struct hostent *host;
    struct in6_addr addr;
    inet_pton(AF_INET6,ip, &addr);
    errno = 0;
    host = gethostbyaddr(&addr, sizeof(addr), AF_INET6);
    if (host == NULL){
        printf("Cant resolve %s to hostname\nExiting...\n", ip);
        exit(-1);
    }
    strcpy(ret, host->h_name);
}

/**
 * Checks if given string is valid IPv4 address
 * @param str
 * @return True if given string is valid IPv4 address
 */
bool is_ipv4_address(const char* str)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str, &(sa.sin_addr))!=0;

}
/**
 * Checks if given string is valid IPv6 address
 * @param str
 * @return True if given string is valid IPv6 address
 */
bool is_ipv6_address(const char *str) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str, &(sa.sin6_addr)) != 0;
}

/**
 * Main funtion
 * @param argc number of input arguments
 * @param argv arguments
 */
int main(int argc, char **argv) {
    Arguments arguments(argc, argv, (char *) "q:w:d:");

    char ip[100];
    char whois_ip[100];

    printf("######## DNS ########\n");
    char *hostname = (char*)malloc(NI_MAXHOST);
    if (is_ipv4_address(arguments.hostname)) {
        ip4_to_hostname(arguments.hostname, hostname);
        printf("A: %s\n", arguments.hostname);
        strcpy(ip, arguments.hostname);
    }
    else if(is_ipv6_address(arguments.hostname)) {
        ip6_to_hostname(arguments.hostname, hostname);
        printf("AAAA: %s\n", arguments.hostname);
        strcpy(ip, arguments.hostname);
    }
    else {
        strcpy(hostname, arguments.hostname);
        get_ip_address(arguments.hostname, ip, true);

    }

    bool ipv6 = false;
    char *whois_hostname = (char*)malloc(NI_MAXHOST);
    if (is_ipv4_address(arguments.whois_hostname))
        ip4_to_hostname(arguments.whois_hostname, whois_hostname);
    else if((ipv6 = is_ipv6_address(arguments.whois_hostname)))
        ip6_to_hostname(arguments.whois_hostname, whois_hostname);
    else {
        strcpy(whois_hostname, arguments.whois_hostname);
        get_ip_address(arguments.whois_hostname, whois_ip, false);
    }

    DNS_Query dns_query(hostname, ip, is_ipv6_address(arguments.hostname));

    dns_query.run_dns();

    runWhois(whois_ip, ip, hostname, whois_hostname, ipv6);


    return 0;
}
