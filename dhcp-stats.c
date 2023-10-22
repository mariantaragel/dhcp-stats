/**
 * @file dhcp-stats.c
 * @author Marian Taragel (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 22.10.2023
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <ncurses.h>
#include <signal.h>
#include <syslog.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dhcp-stats.h"

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
    char *address = strtok(string, "/");
    char *mask = strtok(NULL, "/");
    if (mask == NULL) {
        fprintf(stderr, "Missing net mask\n");
        return 1;
    }

    int s = inet_pton(AF_INET, address, &ip->address);
    if (s <= 0) {
        if (s == 0)
            fprintf(stderr, "IP address is not in correct format\n");
        else
            perror("inet_pton");
        return 1;
    }

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
    ip->num_of_valid_ipaddr = count_valid_ip_addresses(net_mask);
    ip->allocated_ipaddr = 0;
    ip->is_logged = FALSE;

    return 0;
}

int parse_arguments(int argc, char *argv[], cmd_options_t *cmd_options)
{
    if (argc < 4) {
        fprintf(stderr, "Incorrect number of arguments\n");
        return 1;
    }

    for (int optind = 1; optind < argc; optind++) {
        if (strcmp(argv[optind], "-r") == 0 && optind + 1 < argc) {
            cmd_options->filename = argv[optind + 1];
            optind++;
        } else if (strcmp(argv[optind], "-i") == 0 && optind + 1 < argc) {
            cmd_options->interface = argv[optind + 1];
            optind++;
        } else if (strcmp(argv[optind], "-h") == 0 || strcmp(argv[optind], "--help") == 0) {
            printf("%s", usage);
            clean(cmd_options->ip_prefixes);
            exit(EXIT_SUCCESS);
        } else {
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

    if ((cmd_options->filename == NULL && cmd_options->interface == NULL) ||
        (cmd_options->filename != NULL && cmd_options->interface != NULL)) {
        fprintf(stderr, "Invalid argument combination\n");
        return 1;
    }

    qsort(cmd_options->ip_prefixes, cmd_options->count_ip_prefixes, sizeof(ip_t), comparator);

    return 0;
}

long int count_valid_ip_addresses(unsigned int net_mask)
{
    int host_bits = IP_ADDR_BIT_LEN - net_mask;
    long int num_of_valid_ipaddr = pow(2, host_bits) - 2;
    
    if (num_of_valid_ipaddr <= 0)
        num_of_valid_ipaddr += 2;
    
    return num_of_valid_ipaddr;
}

int comparator (const void *a, const void *b)
{
    ip_t *ipA = (ip_t *)a;
    ip_t *ipB = (ip_t *)b;
    return ipA->mask - ipB->mask;
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
        fprintf(stderr, "Device doesn't provide Ethernet headers - not supported");
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

int is_ipaddr_in_subnet(uint32_t yiaddr, ip_t *subnet)
{
    uint32_t net_mask = 0xFFFFFFFF << (IP_ADDR_BIT_LEN - subnet->mask);
    if ((yiaddr & htonl(net_mask)) == subnet->address)
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

    for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
        ip_t ip_prefix = cmd_options.ip_prefixes[i];
        float allocation_precentage = calc_alloc_precent(ip_prefix);

        char ipaddr_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &ip_prefix.address, ipaddr_str, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            return 1;
        }

        mvprintw(i + 1, 0, "%s/%d %ld %d %.2f%%\n", ipaddr_str, ip_prefix.mask,
                            ip_prefix.num_of_valid_ipaddr,
                            ip_prefix.allocated_ipaddr,
                            allocation_precentage);
    }
    
    refresh();
    
    return 0;
}

int get_dhcp_msg_type(const unsigned char *options, int dhcp_options_length)
{
    int dhcp_msg_type = -1;
    
    for (int i = 0; i < dhcp_options_length; i++) {
        uint8_t opcode = options[i];
        if (opcode == 53) {
            dhcp_msg_type = options[i + 2];
        } else if (opcode == 0) {
            continue;
        } else if (opcode == 255) {
            break;
        }
        i += options[i + 1] + 1;
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

void sig_handler(int signum)
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
        
        int ret_val = pcap_next_ex(handle, &header, &packet);
        
        if (ret_val == 1) {
            if (parse_packet(packet, cmd_options, &ip_addr_list)) {
                clean(ip_addr_list.list);
                endwin();
                return 1;
            }
        } else if (ret_val == 0) {
            continue;
        } else if (ret_val == PCAP_ERROR_BREAK) {
            continue;
        } else {
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
    if (prefix->is_logged == FALSE) {
        openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

        char ipaddr_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &prefix->address, ipaddr_str, INET_ADDRSTRLEN) == NULL) {
            closelog();
            perror("inet_ntop");
            return 1;
        }

        syslog(LOG_NOTICE, "prefix %s/%d exceeded 50%% of allocations", ipaddr_str, prefix->mask);
        closelog();

        prefix->is_logged = TRUE;
    }

    return 0;
}

float calc_alloc_precent(ip_t ip_prefix)
{
    return (float) ip_prefix.allocated_ipaddr / (float) ip_prefix.num_of_valid_ipaddr * 100.0;
}

int parse_packet(const unsigned char *packet, cmd_options_t cmd_options, ip_addr_list_t *ip_addr_list)
{
    const struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
    unsigned int size_ip = ip->ihl * 4;

    const struct udphdr *udp = (struct udphdr *) (packet + ETHER_HDR_LEN + size_ip);
    unsigned int size_udp_payload = (ntohs(udp->len) - UDP_HDR_LEN);

    const struct dhcphdr *dhcp = (struct dhcphdr *) (packet + ETHER_HDR_LEN + size_ip + UDP_HDR_LEN);
    unsigned int size_dhcp_options = size_udp_payload - sizeof(struct dhcphdr);

    if (get_dhcp_msg_type(dhcp->options, size_dhcp_options) == DHCP_ACK) {
        if (is_ipaddr_in_list(dhcp->yiaddr, *ip_addr_list) == FALSE) {
            
            (* ip_addr_list).len++;
            (* ip_addr_list).list = (uint32_t *) realloc((* ip_addr_list).list, sizeof(uint32_t) * (* ip_addr_list).len);
            if ((* ip_addr_list).list == NULL) {
                perror("realloc");
                return 1;
            }
            
            (* ip_addr_list).list[(* ip_addr_list).len - 1] = dhcp->yiaddr;
        
            for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
                if (is_ipaddr_in_subnet(dhcp->yiaddr, &cmd_options.ip_prefixes[i])) {
                    cmd_options.ip_prefixes[i].allocated_ipaddr++;
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
    }

    return 0;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);

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
