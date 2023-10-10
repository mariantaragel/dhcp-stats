/**
 * @file dhcp-stats.c
 * @author Marian Taragel (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 10.10.2023
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <ncurses.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dhcp-stats.h"

void handle_error(char *error)
{
    perror(error);
    exit(EXIT_FAILURE);
}

void clean(cmd_options_t cmd_options)
{
    if (cmd_options.ip_prefixes != NULL) {
        free(cmd_options.ip_prefixes);
        cmd_options.ip_prefixes = NULL;
    }
}

ip_t get_ip_address(char *ip_address_str)
{
    char *address = strtok(ip_address_str, "/");
    char *mask = strtok(NULL, "/");
    if (mask == NULL) {
        printf("Missing net prefix\n");
        exit(EXIT_FAILURE);
    }

    ip_t ip;
    int s = inet_pton(AF_INET, address, &ip.address);
    if (s <= 0) {
        if (s == 0)
            fprintf(stderr, "IP address is not in correct format\n");
        else
            perror("inet_pton");
        exit(EXIT_FAILURE);
    }
    char *endptr;
    int net_mask = strtol(mask, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "Not a number\n");
        exit(EXIT_FAILURE);
    }
    ip.mask = net_mask;
    ip.num_of_valid_ipaddr = count_valid_ip_addresses(net_mask);
    ip.allocated_ipaddr = 0;

    return ip;
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
        } else if (strcmp(argv[optind], "-h") == 0) {
            printf("%s", usage);
            clean(*cmd_options);
            exit(EXIT_SUCCESS);
        } else {
            cmd_options->count_ip_prefixes++;
            ip_t ip_prefix = get_ip_address(argv[optind]);
            cmd_options->ip_prefixes = (ip_t *) realloc(cmd_options->ip_prefixes, cmd_options->count_ip_prefixes * sizeof(ip_t));
            if (cmd_options->ip_prefixes == NULL) {
                free(cmd_options->ip_prefixes);
                handle_error("realloc");
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

int count_valid_ip_addresses(unsigned int net_mask)
{
    int host_bits = IP_ADDR_BIT_LEN - net_mask;
    return pow(2, host_bits) - 2;
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
        clean(cmd_options);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device doesn't provide Ethernet headers - not supported");
        pcap_close(handle);
        clean(cmd_options);
        exit(EXIT_FAILURE);
    }

    return handle;
}

void is_ipaddr_in_subnet(uint32_t yiaddr, ip_t *subnet)
{
    uint32_t net_mask = 0xFFFFFFFF << (IP_ADDR_BIT_LEN - subnet->mask);
    if ((yiaddr & htonl(net_mask)) == subnet->address)
        subnet->allocated_ipaddr++;
}

int is_addr_in_list(uint32_t ip_addr, ip_addr_list_t ip_addr_list)
{
    for (int i = 0; i < ip_addr_list.len; i++) {
        if (ip_addr_list.list[i] == ip_addr)
            return TRUE;
    }
    return FALSE;
}

void print_stats(cmd_options_t cmd_options)
{
    mvprintw(0, 0,"IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
        char str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &cmd_options.ip_prefixes[i].address, str, INET_ADDRSTRLEN) == NULL) {
            handle_error("inet_ntop");
        }
        mvprintw(i + 1, 0, "%s %d %d %d %.2f%%\n", str, cmd_options.ip_prefixes[i].mask,
                            cmd_options.ip_prefixes[i].num_of_valid_ipaddr,
                            cmd_options.ip_prefixes[i].allocated_ipaddr,
                            (float) cmd_options.ip_prefixes[i].allocated_ipaddr / (float) cmd_options.ip_prefixes[i].num_of_valid_ipaddr * 100);
    }
    refresh();
}

int get_dhcp_msg_type(unsigned char *options, int dhcp_options_length)
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

int main(int argc, char *argv[])
{
    cmd_options_t cmd_options = {NULL, NULL, NULL, 0};
    if (parse_arguments(argc, argv, &cmd_options)){
        clean(cmd_options);
        return EXIT_FAILURE;
    }

    pcap_t *handle = open_pcap(cmd_options);
    if (apply_filter(handle)) {
        clean(cmd_options);
        return EXIT_FAILURE;
    }

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int ret_val;
    ip_addr_list_t ip_addr_list = {NULL, 0};
    initscr();
    print_stats(cmd_options);
    while ((ret_val = pcap_next_ex(handle, &header, &packet)) == 1) {
        const struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
        unsigned int size_ip = ip->ihl * 4;
        const struct udphdr *udp = (struct udphdr *) (packet + ETHER_HDR_LEN + size_ip);
        struct dhcphdr *dhcp = (struct dhcphdr *) (packet + ETHER_HDR_LEN + size_ip + UDP_HDR_LEN);
        size_t size_udp_payload = (ntohs(udp->len) - UDP_HDR_LEN);
        size_t size_dhcp_options = size_udp_payload - sizeof(struct dhcphdr);
        if (get_dhcp_msg_type(dhcp->options, size_dhcp_options) == DHCP_ACK) {
            if (is_addr_in_list(dhcp->yiaddr, ip_addr_list) == FALSE) {
                ip_addr_list.len++;
                ip_addr_list.list = (uint32_t *) realloc(ip_addr_list.list, sizeof(uint32_t) * ip_addr_list.len);
                if (ip_addr_list.list == NULL) {
                    free(ip_addr_list.list);
                    clean(cmd_options);
                    handle_error("realloc");
                }
                ip_addr_list.list[ip_addr_list.len - 1] = dhcp->yiaddr;
            
                for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
                    is_ipaddr_in_subnet(dhcp->yiaddr, &cmd_options.ip_prefixes[i]);
                }
                print_stats(cmd_options);
            }
        }
    }
    getch();
    endwin();

    pcap_close(handle);
    clean(cmd_options);
    free(ip_addr_list.list);

    return EXIT_SUCCESS;
}
