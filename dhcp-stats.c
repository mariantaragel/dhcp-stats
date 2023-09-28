#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>

int main(int argc, char *argv[])
{
    char *filename = argv[2];
    
    if (strcmp(argv[1], "-r") == 0) {
        printf("Filename: %s\n", filename);
    }

    return 0;
}