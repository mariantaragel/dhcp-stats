CC = gcc
CFLAGS = -Wall -Werror -pedantic -g -std=gnu17
LDLIBS = -lpcap -lm -lncurses

dhcp-stats: dhcp-stats.o

clean:
	rm -f dhcp-stats *.o