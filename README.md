# DHCP stats

**Name and surname:** Marián Tarageľ<br>
**Login:** xtarag01<br>
**Date:** 22.10.2023

## Project description
The program will monitor DHCP traffic and show stats about IP prefix utilization. When the IP prefix exceeds 50 % of the allocated IP addressed, the program will notify the administrator through syslog. The program can generate stats from a pcap file. It can also listen on a network interface.

## CLI Syntax
```
./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]
```

**-r filename** - stats will be generated from a pcap file<br>
**-i interface** - interface to listen on<br>
**ip-prefix** - net range for which stats will be generated\n

### Example
```sh
$ ./dhcp-stats -i eth0 192.168.1.0/24 192.168.0.0/22 172.16.32.0/24
```

## Files included
dhcp-stats.c<br>
dhcp-stats.h<br>
dhcp-stats.1<br>
Makefile<br>
README.md<br>
manual.pdf
