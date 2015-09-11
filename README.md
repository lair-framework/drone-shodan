# drone-shodan

Provided a file containing a new line delimited file containing cidr netblocks or ip
addresses, this drone uses shodan's 'net' and 'host' search to identify and import available
services into lair. Requests are made to shodan concurrently using a pool of 10 goroutines.
