/**
 * @file dhcp-stats.h
 * @author Marian Taragel (xtarag01)
 * @brief Interface of dhcp-stats program
 * @date 22.10.2023
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

/**
 * @brief 
 * 
 * @param pointer 
 */
void clean(void *pointer);

/**
 * @brief 
 * 
 * @param string 
 * @param ip 
 * @return int 
 */
int string_to_ip_address(char *string, ip_t *ip);

/**
 * @brief 
 * 
 * @param argc 
 * @param argv 
 * @param cmd_options 
 * @return int 
 */
int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options);

/**
 * @brief 
 * 
 * @param net_mask 
 * @return long int 
 */
long int count_valid_ip_addresses(unsigned int net_mask);

/**
 * @brief 
 * 
 * @param a 
 * @param b 
 * @return int 
 */
int comparator(const void *a, const void *b);

/**
 * @brief 
 * 
 * @param cmd_options 
 * @return pcap_t* 
 */
pcap_t *open_pcap(cmd_options_t cmd_options);

/**
 * @brief 
 * 
 * @param yiaddr 
 * @param subnet 
 * @return int 
 */
int is_ipaddr_in_subnet(uint32_t yiaddr, ip_t *subnet);

/**
 * @brief 
 * 
 * @param ip_addr 
 * @param ip_addr_list 
 * @return int 
 */
int is_ipaddr_in_list(uint32_t ip_addr, ip_addr_list_t ip_addr_list);

/**
 * @brief 
 * 
 * @param cmd_options 
 * @return int 
 */
int print_stats(cmd_options_t cmd_options);

/**
 * @brief Get the dhcp msg type object
 * 
 * @param options 
 * @param dhcp_options_length 
 * @return int 
 */
int get_dhcp_msg_type(const unsigned char *options, int dhcp_options_length);

/**
 * @brief 
 * 
 * @param handle 
 * @return int 
 */
int apply_filter(pcap_t *handle);

/**
 * @brief 
 * 
 * @param signum 
 */
void sig_handler(int signum);

/**
 * @brief 
 * 
 * @param cmd_options 
 * @param handle 
 * @return int 
 */
int read_packets(cmd_options_t cmd_options, pcap_t *handle);

/**
 * @brief Create a log object
 * 
 * @param prefix 
 * @return int 
 */
int create_log(ip_t *prefix);

/**
 * @brief 
 * 
 * @param ip_prefix 
 * @return float 
 */
float calc_alloc_precent(ip_t ip_prefix);

/**
 * @brief 
 * 
 * @param packet 
 * @param cmd_options 
 * @param ip_addr_list 
 * @return int 
 */
int parse_packet(const unsigned char *packet, cmd_options_t cmd_options, ip_addr_list_t *ip_addr_list);

#endif