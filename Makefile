# Project: Monitoring of DHCP communication
# Author: Marián Tarageľ (xtarag01)
# Date: 14.11.2023

EXECUTABLE = dhcp-stats
LOGIN = xtarag01
SERVER = merlin.fit.vutbr.cz
SERVER_DIR = ~/tmp
TAR_FILE = $(LOGIN).tar

CC = gcc
CFLAGS = -Wall -Werror -pedantic -g -std=gnu17
LDLIBS = -lpcap -lm -lncurses

.PHONY = all pack clean

all: $(EXECUTABLE)

$(EXECUTABLE): dhcp-stats.o

pack: $(TAR_FILE)

$(TAR_FILE): *.c *.h Makefile manual.pdf $(EXECUTABLE).1
	tar cvf $@ $^

upload: $(TAR_FILE)
	scp $^ $(SERVER):$(SERVER_DIR)
	ssh $(LOGIN)@$(SERVER) \
		"cd $(SERVER_DIR) && tar xvf $^"

clean:
	rm -f $(EXECUTABLE) *.o $(TAR_FILE)
