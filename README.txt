Tim Chu & Sam Wlody - mp2
CSC 278 - Computer Security Systems
Spring 2018

Compile with:
make

Run with:
./webspy [tcpdump_output_file]

Or pipe output of tcpdump to program
tcpdump -U -w - | ./webspy

1. Does using HTTPS obscure the URL being requested? If so, why?
2. Does using HTTPS prevent hackers from knowing which web site a user is browsing? Why or why not?

HTTPS obscures the full requested URL, but can not obscure the domain or subdomains. In other words, an attacker can know which server is requesting data from, as well as the length of the request, but knows nothing about the content of the request. This is because the initial TLS handshake takes place before the HTTP GET request itself.
