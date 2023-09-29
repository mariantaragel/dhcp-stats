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

    return 0;
}