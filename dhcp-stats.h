/**
 * @file dhcp-stats.h
 * @author Marian Taragel (xtarag01)
 * @brief Interface of dhcp-stats program
 * @date 17.10.2023
 */

#ifndef DHCP_STATS_H
#define DHCP_STATS_H

const char usage[] =
    "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n"
    "\n"
    "   -r <filename>   stats will be generated from a pcap file\n"
    "   -i <interface>  interface to listen on\n"
    "   <ip-prefix>     net range for which stats will be generated\n";

typedef struct ip_address
{
    uint32_t address;
    unsigned int mask;
    long int num_of_valid_ipaddr;
    unsigned int allocated_ipaddr;
    int is_logged;
} ip_t;

typedef struct cmd_options
{
    char *filename;
    char *interface;
    ip_t *ip_prefixes;
    int count_ip_prefixes;
} cmd_options_t;

struct dhcphdr
{
    unsigned char op;
    unsigned char htype;
    unsigned char hlen;
    unsigned char hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    unsigned char chaddr[16];
    unsigned char sname[64];
    unsigned char file[128];
    uint32_t magic_cookie;
    unsigned char options[];
};

typedef struct ip_addr_list
{
    uint32_t *list;
    int len;
} ip_addr_list_t;

#define TRUE 1
#define FALSE 0
#define DHCP_ACK 5
#define UDP_HDR_LEN 8
#define IP_ADDR_BIT_LEN 32

void clean(void *pointer);
int string_to_ip_address(char *string, ip_t *ip);
int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options);
long int count_valid_ip_addresses(unsigned int net_mask);
int comparator(const void *a, const void *b);
pcap_t *open_pcap(cmd_options_t cmd_options);
int is_ipaddr_in_subnet(uint32_t yiaddr, ip_t *subnet);
int is_ipaddr_in_list(uint32_t ip_addr, ip_addr_list_t ip_addr_list);
int print_stats(cmd_options_t cmd_options);
int get_dhcp_msg_type(const unsigned char *options, int dhcp_options_length);
int apply_filter(pcap_t *handle);
void sig_handler(int signum);
int read_packets(cmd_options_t cmd_options, pcap_t *handle);
int create_log(ip_t *prefix);
float calc_alloc_precent(ip_t ip_prefix);
int parse_packet(const unsigned char *packet, cmd_options_t cmd_options, ip_addr_list_t *ip_addr_list);

#endif