/*
 * This file was generated by the BPF Assember Version 0.9.1.
 * Avoid hand editing this file if possible.
 */

#include <pcap.h>

#ifndef HTTPFilter_H
#define HTTPFilter_H

static struct bpf_insn HTTPFilter_array [] = 
{
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 7),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x06, 0, 5),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 36),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0050, 1, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01BB, 1, 2),
	BPF_STMT(BPF_RET+BPF_K, 80),
	BPF_STMT(BPF_RET+BPF_K, 443),
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct bpf_program HTTPFilter = {10, &(HTTPFilter_array[0])};

#endif
