/*
 * Standard C includes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/*
 * Standard UNIX includes
 */
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * Other includes
 */
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

/*
 * Includes for BPF
 */
#include <sys/time.h>
#include <sys/ioctl.h>

/*
 * Local include files
 */
#include "webspy.h"
#include "httpfilter.h"

/*
 * The descriptor of the output file.
 */
FILE *outfile;

/*
 * Function Prototypes
 */
void 
process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

/*
 * Function: init_pcap()
 *
 * Purpose:
 *	This function initializes the packet capture library for reading
 *	packets from a packet capturing program.
 */
pcap_t *
init_pcap(FILE *thefile, char *filename)
{
	char error[PCAP_ERRBUF_SIZE];	/* Error buffer */
	pcap_t *pcapd;				    /* Pcap descriptor */

	/*
	 * Setup the global file pointer.
	 */
	outfile = thefile;

	/*
	 * Open the dump file and get a pcap descriptor.
	 */
	if ((pcapd = pcap_open_offline(filename, error)) == NULL) {
		fprintf(stderr, "Error is %s\n", error);
		return NULL;
	}

	return pcapd;
}

/*
 * Function: print_ether
 *
 * Description:
 *   Print the Ethernet header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the Ethernet
 *             header.
 */
void
print_ether(FILE *outfile, const unsigned char **packet)
{
	struct ether_header header;
	int index;

	/*
	 * Align the data by copying it into a Ethernet header structure.
	 */
	memcpy(&header, *packet, sizeof(struct ether_header));

	/*
	 * Print out the Ethernet information.
	 */
	fprintf(outfile, "================= ETHERNET HEADER ==============\n");
	fprintf(outfile, "Source Address:\t\t");
	for (index=0; index < ETHER_ADDR_LEN; index++)
		fprintf(outfile, "%x", header.ether_shost[index]);
	fprintf(outfile, "\n");

	fprintf(outfile, "Destination Address:\t");
	for (index=0; index < ETHER_ADDR_LEN; index++)
		fprintf (outfile, "%x", header.ether_dhost[index]);
	fprintf(outfile, "\n");

	fprintf(outfile, "Protocol Type:\t\t");
	switch (ntohs(header.ether_type)) {
		case ETHERTYPE_PUP:
			fprintf(outfile, "PUP Protocol\n");
			break;

		case ETHERTYPE_IP:
			fprintf(outfile, "IP Protocol\n");
			break;

		case ETHERTYPE_ARP:
			fprintf(outfile, "ARP Protocol\n");
			break;

		case ETHERTYPE_REVARP:
			fprintf(outfile, "RARP Protocol\n");
			break;

		default:
			fprintf(outfile, "Unknown Protocol: %x\n", header.ether_type);
			break;
	}

	/*
	 * Adjust the pointer to point after the Ethernet header.
	 */
	*packet += sizeof(struct ether_header);

	/*
	 * Return indicating no errors.
	 */
	return;
}

/*
 * Function: print_ip
 *
 * Description:
 *   Print the IPv4 header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the IPv4
 *             header.
 */
void
print_ip(FILE *outfile, const unsigned char **packet)
{
	// This is where all our code goes
	struct ip ip_header;

	/*
	 * After reading comments in tcpdump source code, I discovered that
	 * the dump file does not guarantee that the IP header is aligned
	 * on a word boundary.
	 *
	 * This is apparently what's causing me problems, so I will word align
	 * it just like tcpdump does.
	 */
	memcpy(&ip_header, *packet, sizeof(struct ip));

	/********* Get size of header ************/
	// both of these return 20 bytes for all packets in httpdump and httpsdump
	// TODO will they ever be different?
	int ip_length = ip_header.ip_hl * 4;
	// int ip_length = sizeof(struct ip);

	// The header should be a TCP header (0x06), otherwise our BPF failed
	assert(ip_header.ip_p == 0x06);

	/********** Get src and dst IP addresses **********/
	printf("\n================= IP Header ==============\n");
	// These are in network byte order, so use ntohl() here?
	uint32_t source_ip = ntohl(ip_header.ip_src.s_addr);
	printf("Source IP: %d.%d.%d.%d\n", (source_ip >> 24) & 0xFF, (source_ip >> 16) & 0xFF, (source_ip >> 8) & 0xFF, (source_ip & 0xFF));

	uint32_t dest_ip = ntohl(ip_header.ip_dst.s_addr);
	printf("Dest IP: %d.%d.%d.%d\n\n", (dest_ip >> 24) & 0xFF, (dest_ip >> 16) & 0xFF, (dest_ip >> 8) & 0xFF, (dest_ip & 0xFF));

	/************* convert address to hostname ***************/
	// After getting the src and dest ip from the header
	// we can use getnameinfo() from netdb.h to get the URL
	*packet += ip_length;

	struct tcphdr tcp_header;
	memcpy(&tcp_header, *packet, sizeof(struct tcphdr));

	bool ssl;
	if (ntohs(tcp_header.th_dport) == 80)
		ssl = false;
	else if (ntohs(tcp_header.th_dport) == 443)
		ssl = true;
	else
		return;

	struct sockaddr_in sa = {AF_INET, tcp_header.th_dport, ip_header.ip_dst};

	char host[1024];
	// TODO Handle error
	getnameinfo((struct sockaddr*) &sa, sizeof(sa), host, 1024, NULL, 0, NI_NAMEREQD);

	printf("%s%s\n\n", ssl ? "https://" : "http://", host);

	/*********** TODO Read HTTP request to determine requested file *************/
	// Now we should advance our pointer (packet)
	// by the sizeof the TCP header to reach the
	// HTTP request so we can read it
	// But we shouldn't do anything for HTTPS
	*packet += sizeof(struct tcphdr);

	// We should be able to read the HTTP request now

	/*
	 * Return indicating no errors.
	 */
	return;
}

/*
 * Function: process_packet()
 *
 * Purpose:
 *	This function is called each time a packet is captured.  It will
 *	determine if the packet is one that is desired, and then it will
 *	print the packet's information into the output file.
 *
 * Inputs:
 *	thing         - I have no idea what this is.
 *	packet_header - The header that libpcap precedes a packet with.  It
 *	                indicates how much of the packet was captured.
 *	packet        - A pointer to the captured packet.
 */
void
process_packet(u_char *user,
               const struct pcap_pkthdr *h,
               const u_char *bytes)
{
	/* Determine where the IP Header is */
	const unsigned char *pointer;

	/* Length of the data */
	// what data?
	long packet_length;

	/*
	 * Filter the packet using our BPF filter.
	 */
	if ((pcap_offline_filter(&HTTPFilter, h, bytes) == 0))
		return;

	/*
	 * Print the Ethernet Header
	 */
	pointer = bytes;
	print_ether(outfile, &pointer);

	/*
	 * Find the pointer to the IP header.
	 */
	print_ip(outfile, &pointer);
	return;
}
