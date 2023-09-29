/**
 * @file dhcp-stats.c
 * @author Marian Taragel (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 2023-09-29
 */

#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include "dhcp-stats.h"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Incorrect number of arguments\n");
        return 1;
    }

    char *filename = NULL;

    for (int optind = 0; optind < argc; optind++) {
        if (strcmp(argv[optind], "-r") == 0 && optind + 1 < argc) {
            filename = argv[optind + 1];
        } else if (strcmp(argv[optind], "-h") == 0) {
            printf("%s", usage);
            return 0;
        }
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        return 1;
    } else {
        printf("%s is opened\n", filename);
    }

    return 0;
}