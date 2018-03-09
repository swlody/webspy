/*
 * Standard C includes
 */
#include <stdio.h>
#include <errno.h>
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

#define PRINT_ERROR

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
 * Function: process_packet()
 *
 * Purpose:
 *	This function is called each time a packet is captured.  It will
 *	determine if the packet is one that is desired, and then it will
 *	print the packet's information into the output file.
 *
 * Inputs:
 *	user          - I have no idea what this is.
 *	packet_header - The header that libpcap precedes a packet with.  It
 *	                indicates how much of the packet was captured.
 *	packet        - A pointer to the captured packet.
 */
void
process_packet(u_char *user,
               const struct pcap_pkthdr *h,
               const u_char *packet)
{
	/*
	 * Filter the packet using our BPF filter.
	 */

	// http.bpf is configured to return the port if we see an HTTP/S request, otherwise 0
	int dest_port = pcap_offline_filter(&HTTPFilter, h, packet);
	if (dest_port == 0)
		return;

	/*
	 * Move pointer past the ethernet header (we don't care about the source or destination MAC addresses)
	 */
	packet += sizeof(struct ether_header);

	/*
	 * Read the IP header into its struct representation
	 * Must be aligned on a word boundary - so use memcpy
	 */
	struct ip ip_header;
	memcpy(&ip_header, packet, sizeof(struct ip));

	/********* Get size of header ************/
	// This is already in the correct endianness as defined by ip.h
	int ip_header_length    = ip_header.ip_hl * 4;
	// Now advance the pointer past the IP header
	packet += ip_header_length;

	// Get the length of the entire packet (including payload and IP, TCP, and ethernet headers)
	int total_packet_length = ntohs(ip_header.ip_len);

	// Now we read the tcp header into its struct
	struct tcphdr tcp_header;
	memcpy(&tcp_header, packet, sizeof(struct tcphdr));

	// We already filtered out all non TCP requests using the BPF filter
	assert(ip_header.ip_p == IPPROTO_TCP);

	// Create sockaddr struct for passage to getnameinfo() - hostname resolution
	unsigned long int sockaddr_size = sizeof(struct sockaddr_in);
	struct sockaddr_in *sa = (struct sockaddr_in *)malloc(sockaddr_size);
	sa->sin_family = AF_INET;
	sa->sin_port   = tcp_header.th_dport;
	sa->sin_addr   = ip_header.ip_dst;

	// More set up for hostname resolution
	char host[1024];
	int  retries = 0;
	bool keep_retrying   = true;
	bool resolve_success = false;
	uint32_t dest_ip = ip_header.ip_dst.s_addr;

	// Try to resolve the hostname
	do {
		errno = 0;
		int errorcode = getnameinfo((struct sockaddr *)sa, sockaddr_size, host, 1024, NULL, 0, NI_NAMEREQD);
		if (errorcode == 0) {
			resolve_success = true;
			break;
		}

		switch (errorcode) {
			case EAI_AGAIN:    // Try again!!
				errno = 0;
				retries++;
				break;
			case EAI_SYSTEM:   // errno has been set - do something about it
				#ifdef PRINT_ERROR
				fprintf(stderr, "%s\n", strerror(errno));
				#endif
			case EAI_BADFLAGS: // should never happen - not passing flags
			case EAI_FAIL:     // nonrecoverable error
			case EAI_FAMILY:   // family not recognized - should never happen
			case EAI_MEMORY:   // out of memory
			case EAI_NONAME:   // hostname could not be resolved
			case EAI_OVERFLOW: // host buffer too small
			default:
				#ifdef PRINT_ERROR
				fprintf(stderr, "Unable to resolve hostname for address for IP address %d.%d.%d.%d\n", 
						(dest_ip & 0xFF), (dest_ip >> 8) & 0xFF, (dest_ip >> 16) & 0xFF, (dest_ip >> 24));
				#endif
				keep_retrying = false;
				break;
		}
	} while (keep_retrying && retries <= MAX_RESOLUTION_RETRIES);

	/*********** Read HTTP request to determine requested file *************/
	// First get the length of the tcp header
	int tcp_header_length = tcp_header.th_off * 4;

	// Now we can compute the length of the payload itself
	// from the size of the packet minus the size of the headers
	int payload_length = total_packet_length - (ip_header_length + tcp_header_length);

	// No payload - don't do anything
	if (payload_length == 0)
		return;

	// Otherwise we keep going
	// advance our packet pointer to the start of the payload
	packet += tcp_header_length;

	// Now we will try to read in the path of the file being requested from the server
	char *path;

	char payload[payload_length];
	if (dest_port == 443) {
		// If the request was an SSL request - the packet is encrypted, so we can't read it
		path = "/OMITTED";
	} else {
		// Otherwise, the file path is at the top of the payload e.g.
		// GET /foo/bar.html HTTP/1.1
		memcpy(&payload, packet, payload_length);
		// We just want the second token ("/foo/bar.html"), so skip the first one ("GET")
		strtok(payload, " ");
		path = strtok(NULL, " ");
	}

	fprintf(outfile, "%s", dest_port == 443 ? "https://" : "http://");

	if (resolve_success) {
		// If we resolved the hostname, print it
		fprintf(outfile, "%s", host);
	} else {
		// Otherwise we just print the IP address that we saw - not every server has a hostname
		fprintf(outfile, "%d.%d.%d.%d", (dest_ip & 0xFF), (dest_ip >> 8) & 0xFF, (dest_ip >> 16) & 0xFF, (dest_ip >> 24));
	}

	// Finally print the path
	fprintf(outfile, "%s\n", path);

	/*
	 * Return indicating no errors.
	 */
	return;
}
