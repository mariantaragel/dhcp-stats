/**
 * @file dhcp-stats.h
 * @author Marian Taragel (xtarag01)
 * @brief Interface of dhcp-stats program
 * @date 2023-09-27
 */

#ifndef DHCP_STATS_H
#define DHCP_STATS_H

const char usage[] =
    "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]\n"
    "\n"
    "   -r <filename>   stats will be generated from a pcap file\n"
    "   -i <interface>  interface to listen on\n"
    "   <ip-prefix>     net range for which stats will be generated\n";

typedef struct cmd_options
{
    char *filename;
    char *interface;
    char **ip_prefixes;
    int count_ip_prefixes;
} cmd_options_t;

#endif