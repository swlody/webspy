#
# FILE:		Makefile
#
# PURPOSE:	Compile the program.
#

CC = gcc

# Location of the BPF Assembler
BPFA = ./bpfa/bpfa
# Compiler flags
CFLAGS	= -Wall -g -I.
LDFLAGS = -L.
LDLIBS = -lpcap

all: httpfilter.h webspy

webspy: webspy.o packet.o

httpfilter.h: http.bpf
	$(BPFA) $< > $@

#
# Maintainence Targets
#
clean:
	rm -f *.o *.core httpfilter.h

clobber: clean
	rm -f webspy
