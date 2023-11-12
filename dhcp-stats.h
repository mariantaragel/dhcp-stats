/**
 * @file dhcp-stats.h
 * @author Marián Tarageľ (xtarag01)
 * @brief Interface of dhcp-stats program
 * @date 12.11.2023
 */

#ifndef DHCP_STATS_H
#define DHCP_STATS_H

const char usage[] =
    "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n"
    "\n"
    "   -r <filename>   stats will be generated from a pcap file\n"
    "   -i <interface>  interface to listen on\n"
    "   <ip-prefix>     net range for which stats will be generated\n";

const char version[] = "dhcp-stats 1.0\n\nWritten by Marián Tarageľ.\n";

typedef struct ip_address
{
    uint32_t address;
    uint32_t network_ipaddr;
    unsigned int mask;
    long int num_of_useable_ipaddr;
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

#define FALSE 0
#define TRUE 1
#define DHCP_ACK 5
#define UDP_HDR_LEN 8
#define ETHER_HDR_LEN 14
#define IP_ADDR_BIT_LEN 32
#define OPT_MSG_TYPE 53
#define DHCP_HDR_LEN 240
#define OPT_END 255

#define LOG_MSG "prefix %s/%d exceeded 50%% of allocations\n"

/**
 * @brief Free allocted memory
 * 
 * @param pointer Generic pointer on allocated memory block
 */
void clean(void *pointer);

/**
 * @brief Convert string to IPv4 address binary format
 * 
 * @param string String to convert
 * @param ip Structure for storing result
 * @return 0 on success, 1 on error
 */
int string_to_ip_address(char *string, ip_t *ip);

/**
 * @brief Parse -h, --help and --version flags
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 */
void parse_extra_options(int argc, char *argv[]);

/**
 * @brief Parse command-line arguments 
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @param cmd_options Structure for storing results of parsing
 * @return 0 on success, 1 on error
 */
int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options);

/**
 * @brief Calculate number of useable IPv4 addresses in subnet
 * 
 * @param net_mask Network subnet mask
 * @return Number of useable IPv4 addresses
 */
long int count_useable_ip_addresses(unsigned int net_mask);

/**
 * @brief Compare net masks of IP prefixes
 * 
 * @param ip_prefix_a First IP prefix
 * @param ip_prefix_b Second IP prefix
 * @return Difference between net masks
 */
int comparator(const void *ip_prefix_a, const void *ip_prefix_b);

/**
 * @brief Open connection for sniffing or open a pcap file
 * 
 * @param cmd_options Entered command-line arguments
 * @return (pcap_t *) coonection on success, NULL on error
 */
pcap_t *open_pcap(cmd_options_t cmd_options);

/**
 * @brief Bbitwise and between network mask and the IP addresss
 * 
 * @param ip_addr IP address
 * @param mask_len Length of the network subnet (0 - 32)
 * @return Masked IP address 
 */
uint32_t bit_mask_address(uint32_t ip_addr, unsigned int mask_len);

/**
 * @brief Check whether IP is in network subnet
 * 
 * @param ip_addr IP address to check
 * @param subnet Network subnet (mask and network ip address)
 * @return TRUE when ip address is in network subnet, else FALSE 
 */
int is_ipaddr_in_subnet(uint32_t ip_addr, ip_t *subnet);

/**
 * @brief Check whether IP address was already seen
 * 
 * @param ip_addr IP address to check
 * @param ip_addr_list List of seen ip addresses
 * @return TRUE when IP address is in list, else FALSE
 */
int is_ipaddr_in_list(uint32_t ip_addr, ip_addr_list_t ip_addr_list);

/**
 * @brief Print DHCP traffic stats
 * 
 * @param cmd_options Entered command-line arguments
 * @return 0 on success, 1 on error
 */
int print_stats(cmd_options_t cmd_options);

/**
 * @brief Get the DHCP message type
 * 
 * @param options Pointer to options array
 * @param dhcp_options_size Size of DHCP options
 * @return DHCP message type
 */
int get_dhcp_msg_type(const unsigned char *options, int dhcp_options_size);

/**
 * @brief Filter network trafic to only udp port 67 or port 68 packets
 * 
 * @param handle Opened (pcap_t *) connection
 * @return 0 on success, 1 on error
 */
int apply_filter(pcap_t *handle);

/**
 * @brief End program and free used resources
 * 
 * @param signum Number of the received signal
 */
void signal_handler(int signum);

/**
 * @brief Read packets from pcap file or listen on network interface
 * 
 * @param cmd_options Entered command-line arguments
 * @param handle Opened (pcap_t *) connection
 * @return 0 on success, 1 on error
 */
int read_packets(cmd_options_t cmd_options, pcap_t *handle);

/**
 * @brief Create a record in system log, that ip prefix exceeded 50% of allocations
 * 
 * @param prefix IP prefix that will be logged
 * @return 0 on success, 1 on error
 */
int create_log(ip_t *prefix);

/**
 * @brief Calculate percentage of allocated ip addresses in ip prefix
 * 
 * @param ip_prefix IP prefix used for calculation
 * @return Precentage of allocated ip addresses
 */
float calc_alloc_precent(ip_t ip_prefix);

/**
 * @brief If IP address is in IP prefix refresh stats and add IP address to seen ones
 * 
 * @param dhcp Pointer to the DHCP ACK data
 * @param ip_addr_list List of seen ip addresses
 * @param cmd_options Entered command-line arguments
 * @return 0 on success, 1 on error
 */
int parse_packet(const struct dhcphdr *dhcp, ip_addr_list_t *ip_addr_list, cmd_options_t cmd_options);

/**
 * @brief Extract only DHCP ACK packets
 * 
 * @param packet Pointer to the packet data
 * @param cmd_options Entered command-line arguments
 * @param ip_addr_list List of seen ip addresses
 * @return 0 on success, 1 on error
 */
int extract_dhcp_packet(const unsigned char *packet, cmd_options_t cmd_options, ip_addr_list_t *ip_addr_list);

#endif