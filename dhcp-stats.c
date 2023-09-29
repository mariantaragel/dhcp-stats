/**
 * @file dhcp-stats.c
 * @author Marian Taragel (xtarag01)
 * @brief Monitoring of DHCP communication
 * @date 2023-09-29
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
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
            cmd_options->ip_prefixes = (char **) realloc(cmd_options->ip_prefixes, cmd_options->count_ip_prefixes * sizeof(char *));
            if (cmd_options->ip_prefixes == NULL) {
                free(cmd_options->ip_prefixes);
                handle_error("realloc");
            }
            cmd_options->ip_prefixes[cmd_options->count_ip_prefixes - 1] = argv[optind];
        }
    }

    if ((cmd_options->filename == NULL && cmd_options->interface == NULL) ||
        (cmd_options->filename != NULL && cmd_options->interface != NULL)) {
        fprintf(stderr, "Invalid argument combination\n");
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    cmd_options_t cmd_options = {NULL, NULL, NULL, 0};
    if (parse_arguments(argc, argv, &cmd_options) == 1){
        clean(cmd_options);
        return EXIT_FAILURE;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(cmd_options.filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        return EXIT_FAILURE;
    } else {
        printf("%s is opened\n", cmd_options.filename);
    }

    pcap_close(handle);
    clean(cmd_options);

    return EXIT_SUCCESS;
}