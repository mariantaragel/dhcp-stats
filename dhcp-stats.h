/**
 * @file dhcp-stats.h
 * @author Marian Taragel (xtarag01)
 * @brief Interface of dhcp-stats program
 * @date 7.10.2023
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
    unsigned char *options;
};

#define UDP_HDR_LEN 8
#define IP_ADDR_BIT_LEN 32

void handle_error(char *error);
void clean(cmd_options_t cmd_options);
ip_t get_ip_address(char *ip_address_str);
int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options);
int count_valid_ip_addresses(unsigned int net_mask);
int comparator (const void *a, const void *b);
pcap_t *open_pcap(cmd_options_t cmd_options);
void print_ip_address(uint32_t ip_address, char *end);

#endif