#
# FILE:		Makefile
#
# PURPOSE:	Compile the program.
#

# Location of the BPF Assembler
BPFA = ./bpfa/bpfa

# Compiler flags
CC = gcc
CFLAGS	= -Wall -g -I.
LDFLAGS = -L.

all: httpfilter.h webspy

webspy: webspy.o packet.o
	$(CC) $(CFLAGS) -o webspy webspy.o packet.o $(LDFLAGS) -lpcap

httpfilter.h: http.bpf
	$(BPFA) $< > $@

#
# Maintainence Targets
#
clean:
	rm -f *.o httpfilter.h

clobber: clean
	rm -f webspy
