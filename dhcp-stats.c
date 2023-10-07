/**
 * @file dhcp-stats.c
 * @author Marian Taragel (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 7.10.2023
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
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
    return *(int *) a - *(int *) b;
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

void print_ip_address(uint32_t ip_address, char *end)
{
    char str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &ip_address, str, INET_ADDRSTRLEN) == NULL) {
        handle_error("inet_ntop");
    }
    printf("%s%s", str, end);
}

int main(int argc, char *argv[])
{
    cmd_options_t cmd_options = {NULL, NULL, NULL, 0};
    if (parse_arguments(argc, argv, &cmd_options) == 1){
        clean(cmd_options);
        return EXIT_FAILURE;
    }

    pcap_t *handle = open_pcap(cmd_options);
    
    printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    for (int i = 0; i < cmd_options.count_ip_prefixes; i++) {
        print_ip_address(cmd_options.ip_prefixes[i].address, " ");
        printf("%d %d\n", cmd_options.ip_prefixes[i].mask, count_valid_ip_addresses(cmd_options.ip_prefixes[i].mask));
    }

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int ret_val;
    while ((ret_val = pcap_next_ex(handle, &header, &packet)) == 1) {
        if (ret_val == 1) {
            const struct iphdr *ip = (struct iphdr *) (packet + ETHER_HDR_LEN);
            unsigned int size_ip = ip->ihl * 4;
            const struct dhcphdr *dhcp = (struct dhcphdr *) (packet + ETHER_HDR_LEN + size_ip + UDP_HDR_LEN);
            print_ip_address(dhcp->yiaddr, "\n");
        }
    }

    pcap_close(handle);
    clean(cmd_options);

    return EXIT_SUCCESS;
}