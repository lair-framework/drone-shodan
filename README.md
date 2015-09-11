# drone-shodan
Provided a newline delimited file containing cidr netblocks or ip addresses, this drone uses shodan's 'net' and 'host' search operators to identify and import available services into lair. Requests are made to shodan concurrently using a pool of 10 goroutines.

## Install
Download a compiled binary for supported operating systems from [here](https://github.com/lair-framework/drone-shodan/releases/latest).

```
$ mv drone-shodan* drone-shodan
$ ./drone-shodan -h
```


## Shodan API Key
This drone requires a shodan API key. The key is provided using an environment variable.
```
$ export SHODAN_KEY='yourkeygoeshere'
```
