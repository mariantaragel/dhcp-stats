# DHCP stats

**Name and surname:** Marián Tarageľ<br>
**Login:** xtarag01<br>
**Date:** 22.10.2023

## Project description
krátký textový popis programu s případnými rozšířeními či omezeními

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
