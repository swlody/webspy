Tim Chu & Sam Wlody - mp2
CSC 278 - Computer Security Systems
Spring 2018

Compile with:
make

(Make sure you make clean first)

Run with:
./webspy [tcpdump_output_file]

Note the compiler flag at the top of packet.c which tells the program whether or not to print an error to stderr when a hostname could not be resolved for an IP address. Regardless of whether this flag is set, the IP address will be printed instead of the unresolved hostname.

1. Does using HTTPS obscure the URL being requested? If so, why?
2. Does using HTTPS prevent hackers from knowing which web site a user is browsing? Why or why not?

HTTPS obscures the full requested URL, but can not obscure the domain or subdomains. In other words, an attacker can know which server is requesting data from, as well as the length of the request, but knows nothing about the content of the request. This is because the initial TLS handshake takes place before the HTTP GET request itself. Obviously, some communication with the server must happen in order to set up the TLS connection, which is why we can still see the server that is being contacted, even if we can't see the content of the connection.
