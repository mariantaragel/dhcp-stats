/**
 * @file dhcp-stats.c
 * @author Marián Tarageľ (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 23.10.2023
 */

#include <stdio.h> // fprintf(), perror()
#include <stdlib.h> // exit(), realloc(), free(), qsort(), EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // strcmp(), strtok()
#include <math.h> // pow()
#include <stdint.h> // uint8_t, uint16_t, uint32_t
#include <signal.h> // signal()
#include <ncurses.h> // initscr(), mvprintw(), refresh(), endwin()
#include <syslog.h> // openlog(), syslog(), closelog()
#include <pcap/pcap.h> // pcap_open_live(), pcap_open_offline(), pcap_datalink(),
                       // pcap_compile(), pcap_setfilter(), pcap_next_ex(), pcap_close()
#include <arpa/inet.h> // inet_pton(), inet_ntop(), htonl(), ntohs()
#include <netinet/ip.h> // struct iphdr
#include <netinet/udp.h> // struct udphdr
#include "dhcp-stats.h"

// global variables for cleaning purpose in signal hendler
cmd_options_t cmd_options;
ip_addr_list_t ip_addr_list;

void clean(void *pointer)
{
    if (pointer != NULL) {
        free(pointer);
        pointer = NULL;
    }
}

int string_to_ip_address(char *string, ip_t *ip)
{
    // divide string by "/"
    char *address = strtok(string, "/");
    char *mask = strtok(NULL, "/");
    if (mask == NULL) {
        fprintf(stderr, "Missing net mask\n");
        return 1;
    }

    // convert ip address from string to binary
    int s = inet_pton(AF_INET, address, &ip->address);
    if (s <= 0) {
        if (s == 0)
            fprintf(stderr, "IP address is not in correct format\n");
        else
            perror("inet_pton");
        return 1;
    }

    // convert network mask to integer
    char *endptr;
    int net_mask = strtol(mask, &endptr, 10);
    
    if (*endptr != '\0') {
        fprintf(stderr, "Not a number\n");
        return 1;
    }

    if (net_mask < 0 || net_mask > 32) {
        fprintf(stderr, "Net mask is out of range (0 - 32)\n");
        return 1;
    }

    ip->mask = net_mask;
    ip->num_of_useable_ipaddr = count_useable_ip_addresses(net_mask);
    ip->allocated_ipaddr = 0;
    ip->is_logged = FALSE;

    return 0;
}

int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options)
{
    for (int optind = 1; optind < argc; optind++) { // skip program name
        if (strcmp(argv[optind], "-r") == 0 && optind + 1 < argc) {
            cmd_options->filename = argv[optind + 1]; // take filename from next position
            optind++;
        } else if (strcmp(argv[optind], "-i") == 0 && optind + 1 < argc) {
            cmd_options->interface = argv[optind + 1]; // take intefrace name from next position
            optind++;
        } else if (strcmp(argv[optind], "-h") == 0 || strcmp(argv[optind], "--help") == 0) { // help flag
            printf("%s", usage);
            clean(cmd_options->ip_prefixes);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[optind], "--version") == 0) { // version flag
            printf("dhcp-stats 1.0\n\nWritten by Marián Tarageľ.\n");
            clean(cmd_options->ip_prefixes);
            exit(EXIT_SUCCESS);
        } else { // argument is not flag, than consider it as ip prefix 
            ip_t ip_prefix;
            if (string_to_ip_address(argv[optind], &ip_prefix)) {
                return 1;
            }

            cmd_options->count_ip_prefixes++;
            cmd_options->ip_prefixes = (ip_t *) realloc(cmd_options->ip_prefixes, cmd_options->count_ip_prefixes * sizeof(ip_t));
            if (cmd_options->ip_prefixes == NULL) {
                free(cmd_options->ip_prefixes);
                perror("realloc");
                exit(EXIT_FAILURE);
            }

            cmd_options->ip_prefixes[cmd_options->count_ip_prefixes - 1] = ip_prefix;
        }
    }

    if (argc < 4) {
        fprintf(stderr, "Incorrect number of arguments\n");
        return 1;
    }

    // At least filename or inteface name must be set
    // Both arguments cannot be set
    if ((cmd_options->filename == NULL && cmd_options->interface == NULL) ||
        (cmd_options->filename != NULL && cmd_options->interface != NULL)) {
        fprintf(stderr, "Invalid argument combination\n");
        return 1;
    }

    qsort(cmd_options->ip_prefixes, cmd_options->count_ip_prefixes, sizeof(ip_t), comparator);

    return 0;
}

long int count_useable_ip_addresses(unsigned int net_mask)
{
    int host_bits = IP_ADDR_BIT_LEN - net_mask;
    long int num_of_useable_ipaddr = pow(2, host_bits) - 2;
    
    // Correction of result (for ip prefixes 32 and 31)
    if (num_of_useable_ipaddr <= 0)
        num_of_useable_ipaddr += 2;
    
    return num_of_useable_ipaddr;
}

int comparator (const void *ip_prefix_a, const void *ip_prefix_b)
{
    ip_t *ip_prefix_A = (ip_t *)ip_prefix_a;
    ip_t *ip_prefix_B = (ip_t *)ip_prefix_b;
    return ip_prefix_A->mask - ip_prefix_B->mask;
}

pcap_t *open_pcap(cmd_options_t cmd_options)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    if (cmd_options.filename != NULL){
        handle = pcap_open_offline(cmd_options.filename, errbuf);
    } else if (cmd_options.interface != NULL) {
        handle = pcap_open_live(cmd_options.interface, BUFSIZ, 1, 1000, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device doesn't provide Ethernet headers - not supported\n");
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

int is_ipaddr_in_subnet(uint32_t ip_addr, ip_t *subnet)
{
    uint32_t net_mask = 0xFFFFFFFF << (IP_ADDR_BIT_LEN - subnet->mask); // Create network mask
    if ((ip_addr & htonl(net_mask)) == subnet->address) // Bitwise and between ip address and network mask
        return TRUE;
    else
        return FALSE;
}

int is_ipaddr_in_list(uint32_t ip_addr, ip_addr_list_t ip_addr_list)
{
    for (int i = 0; i < ip_addr_list.len; i++) {
        if (ip_addr_list.list[i] == ip_addr)
            return TRUE;
    }

    return FALSE;
}

int print_stats(cmd_options_t cmd_options)
{
    mvprintw(0, 0,"IP-Prefix Max-hosts Allocated addresses Utilization\n");

    // Print stats for each ip prefix
    for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
        ip_t ip_prefix = cmd_options.ip_prefixes[i];
        float allocation_precentage = calc_alloc_precent(ip_prefix);

        // convert ip address from binary to string
        char ipaddr_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &ip_prefix.address, ipaddr_str, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            return 1;
        }

        mvprintw(i + 1, 0, "%s/%d %ld %d %.2f%%\n", ipaddr_str, ip_prefix.mask,
                            ip_prefix.num_of_useable_ipaddr,
                            ip_prefix.allocated_ipaddr,
                            allocation_precentage);
    }
    
    refresh();
    
    return 0;
}

int get_dhcp_msg_type(const unsigned char *options, int dhcp_options_size)
{
    int dhcp_msg_type = -1;
    
    for (int i = 0; i < dhcp_options_size; i++) {
        uint8_t optcode = options[i];
        if (optcode == OPT_MSG_TYPE) { // DHCP message type
            dhcp_msg_type = options[i + 2]; // [i+2] because first is option length and then option value
        } else if (optcode == 0) { // padding
            continue;
        } else if (optcode == OPT_END) { // end of options
            break;
        }
        i += options[i + 1] + 1; // [i+1] is option length and +1 for skiping option code 
    }

    return dhcp_msg_type;
}

int apply_filter(pcap_t *handle)
{
    struct bpf_program fp;
    char filter_exp[] = "udp port 67 or 68";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Cannot compile filter expresion\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter\n");
        return 1;
    }

    return 0;
}

void signal_handler(int signum)
{
    clean(cmd_options.ip_prefixes);
    clean(ip_addr_list.list);
    endwin();
    exit(EXIT_SUCCESS);
}

int read_packets(cmd_options_t cmd_options, pcap_t *handle)
{
    initscr();

    if (print_stats(cmd_options)) {
        endwin();
        return 1;
    }

    ip_addr_list_t ip_addr_list = {NULL, 0};

    while (TRUE) {
        struct pcap_pkthdr *header;
        const unsigned char *packet;
        
        // read next packet
        int ret_val = pcap_next_ex(handle, &header, &packet);
        
        if (ret_val == 1) { // Packet was read without problems
            if (extract_dhcp_packet(packet, cmd_options, &ip_addr_list)) {
                clean(ip_addr_list.list);
                endwin();
                return 1;
            }
        } else if (ret_val == 0) { // Packet buffer timeout expired
            continue;
        } else if (ret_val == PCAP_ERROR_BREAK) { // No more packets to read
            getch();
            break;
        } else { // Generic pcap error
            clean(ip_addr_list.list);
            endwin();
            return 1;
        }
    }

    clean(ip_addr_list.list);
    endwin();
    return 0;
}

int create_log(ip_t *prefix)
{
    if (prefix->is_logged == FALSE) { // check whether ip address was alredy logged
        openlog("dhcp-stats", LOG_PID | LOG_NDELAY, LOG_USER);

        // convert ip address from binary to string
        char ipaddr_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &prefix->address, ipaddr_str, INET_ADDRSTRLEN) == NULL) {
            closelog();
            perror("inet_ntop");
            return 1;
        }

        syslog(LOG_NOTICE, "prefix %s/%d exceeded 50%% of allocations", ipaddr_str, prefix->mask);
        closelog();

        prefix->is_logged = TRUE; // ip address will be logged only once
    }

    return 0;
}

float calc_alloc_precent(ip_t ip_prefix)
{
    return (float) ip_prefix.allocated_ipaddr / (float) ip_prefix.num_of_useable_ipaddr * 100.0;
}

int parse_packet(const struct dhcphdr *dhcp, ip_addr_list_t *ip_addr_list, cmd_options_t cmd_options)
{
    if (is_ipaddr_in_list(dhcp->yiaddr, *ip_addr_list) == FALSE) {
        // add new ip address to list of seen addresses
        (* ip_addr_list).len++;
        (* ip_addr_list).list = (uint32_t *) realloc((* ip_addr_list).list, sizeof(uint32_t) * (* ip_addr_list).len);
        if ((* ip_addr_list).list == NULL) {
            perror("realloc");
            return 1;
        }
        
        (* ip_addr_list).list[(* ip_addr_list).len - 1] = dhcp->yiaddr;

        // loop through all ip prefixes
        for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {

            if (is_ipaddr_in_subnet(dhcp->yiaddr, &cmd_options.ip_prefixes[i])) {

                cmd_options.ip_prefixes[i].allocated_ipaddr++; // count ip address to allocated addresses
                
                // check whether ip prefix exceeded 50% of allocations
                if (calc_alloc_precent(cmd_options.ip_prefixes[i]) > 50.0) {
                    if (create_log(&cmd_options.ip_prefixes[i])) {
                        return 1;
                    }
                }
            }
        }

        if (print_stats(cmd_options)) {
            return 1;
        }
    }

    return 0;
}

int extract_dhcp_packet(const unsigned char *packet, cmd_options_t cmd_options, ip_addr_list_t *ip_addr_list)
{
    // extract IP packet
    const struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
    unsigned int size_ip = ip->ihl * 4;

    // extract UDP packet
    const struct udphdr *udp = (struct udphdr *) (packet + ETHER_HDR_LEN + size_ip);
    unsigned int size_udp_payload = (ntohs(udp->len) - UDP_HDR_LEN);

    // extract DHCP packet
    const struct dhcphdr *dhcp = (struct dhcphdr *) (packet + ETHER_HDR_LEN + size_ip + UDP_HDR_LEN);
    unsigned int size_dhcp_options = size_udp_payload - DHCP_HDR_LEN;

    if (get_dhcp_msg_type(dhcp->options, size_dhcp_options) == DHCP_ACK) {
        if (parse_packet(dhcp, ip_addr_list, cmd_options)) {
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    cmd_options_t cmd_options = {NULL, NULL, NULL, 0};
    if (parse_arguments(argc, argv, &cmd_options)){
        clean(cmd_options.ip_prefixes);
        return EXIT_FAILURE;
    }

    pcap_t *handle = open_pcap(cmd_options);
    if (handle == NULL) {
        clean(cmd_options.ip_prefixes);
        return EXIT_FAILURE;
    }

    if (apply_filter(handle)) {
        clean(cmd_options.ip_prefixes);
        pcap_close(handle);
        return EXIT_FAILURE;
    }


    if (read_packets(cmd_options, handle)) {
        clean(cmd_options.ip_prefixes);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);
    clean(cmd_options.ip_prefixes);

    return EXIT_SUCCESS;
}
