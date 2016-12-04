package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/tomsteele/go-shodan"
)

const (
	version  = "1.0.2"
	tool     = "shodan"
	osWeight = 50
	usage    = `
Provided a newline delimited file containing cidr netblocks or ip
addresses, this drone uses shodan's 'net' and 'host' search operators to identify and import available
services into lair. Requests are made to shodan concurrently using a pool of 10 goroutines.

Usage:
  drone-shodan [options] <id> <filename>
  export LAIR_ID=<id>; drone-shodan [options] <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -force-ports    disable data protection in the API server for excessive ports
  -tags           a comma separated list of tags to add to every host that is imported
`
)

func removeDuplicates(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, i := range in {
		if i == "" {
			continue
		}
		if _, ok := m[i]; ok {
			continue
		}
		m[i] = true
		out = append(out, i)
	}
	return out
}

func shodanIPsFromShodanNetSearch(client *shodan.Client, netblock string) ([]string, error) {
	ips := []string{}
	result, err := client.HostSearch("net:"+netblock, []string{}, url.Values{})
	if err != nil {
		return ips, err
	}
	for _, m := range result.Matches {
		ips = append(ips, m.IPStr)
	}
	return ips, nil
}

func gatherIPsToSearch(sclient *shodan.Client, filename string) ([]string, error) {
	ips := []string{}
	cidrs := []string{}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		_, _, err := net.ParseCIDR(line)
		if err != nil {
			ip := net.ParseIP(line)
			if ip == nil {
				log.Fatalf("Fatal: %s in file is not an ip or cidr netblock", ip)
			}
			ips = append(ips, line)
		} else {
			cidrs = append(cidrs, line)
		}
	}

	if len(cidrs) > 0 {
		lk := sync.Mutex{}
		wg := sync.WaitGroup{}
		wg.Add(10)
		cidrsChan := make(chan string, 10)

		for i := 0; i < 10; i++ {
			go func(s shodan.Client) {
				for cidr := range cidrsChan {
					hostCount, err := s.HostCount("net:"+cidr, []string{})
					if err != nil {
						log.Fatalf("Fatal: Error returned from shodan. Error %s", err.Error())
					}
					time.Sleep(5*time.Second)
					if hostCount.Total > 0 {
						if netIPs, err := shodanIPsFromShodanNetSearch(sclient, cidr); err != nil {
							log.Fatalf("Fatal: Error returned from shodan. Error %s", err.Error())
						} else {
							lk.Lock()
							ips = append(ips, netIPs...)
							lk.Unlock()
						}
					}
					time.Sleep(5*time.Second)
				}
				wg.Done()
			}(*sclient)
		}

		for _, cidr := range cidrs {
			cidrsChan <- cidr
		}
		close(cidrsChan)
		wg.Wait()
	}

	return ips, nil
}

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")

	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	if lairPID == "" {
		log.Fatal("Fatal: Missing LAIR_ID")
	}
	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})
	if err != nil {
		log.Fatalf("Fatal: Error setting up client: Error %s", err.Error())
	}
	hostTags := []string{}
	if *tags != "" {
		hostTags = strings.Split(*tags, ",")
	}
	l := lair.Project{
		ID:   lairPID,
		Tool: tool,
		Commands: []lair.Command{lair.Command{
			Tool:    tool,
			Command: "",
		}},
	}

	shodanKey := os.Getenv("SHODAN_KEY")
	if shodanKey == "" {
		log.Fatal("Fatal: Missing SHODAN_KEY environment variable")
	}

	sclient := shodan.New(shodanKey)
	serviceMap, err := sclient.Services()
	if err != nil {
		log.Fatalf("Fatal: Error getting services from shodan. Error %s", err.Error())
	}

	ips := []string{}
	ips, err = gatherIPsToSearch(sclient, filename)
	if err != nil {
		log.Fatalf("Fatal: Can't gather IPs from file %s: error %s", filename, err.Error())
	}

	lk := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(10)
	ipChan := make(chan string, 10)

	for i := 0; i < 10; i++ {
		go func(s shodan.Client) {
			for ip := range ipChan {
				time.Sleep(10*time.Second)
				host, err := s.Host(ip, url.Values{})
				if err != nil {
					log.Printf("Error: Error returned from shodan for %s. Error %s", ip, err.Error())
					continue
				}
				h := lair.Host{
					Hostnames:      host.Hostnames,
					IPv4:           ip,
					LastModifiedBy: tool,
					Tags:           hostTags,
				}
				for _, d := range host.Data {
					service := lair.Service{
						Port:     d.Port,
						Protocol: "tcp",
						Service:  serviceMap[strconv.Itoa(d.Port)],
						Product:  d.Product,
						Notes: []lair.Note{lair.Note{
							Title:          "Shodan Banner",
							Content:        d.Data,
							LastModifiedBy: tool,
						}},
					}
					if fingerprint, ok := d.Os.(string); ok {
						h.OS = lair.OS{
							Fingerprint: fingerprint,
							Weight:      osWeight,
							Tool:        tool,
						}
					}
					h.Hostnames = removeDuplicates(append(h.Hostnames, d.Hostnames...))
					h.Services = append(h.Services, service)
				}
				lk.Lock()
				l.Hosts = append(l.Hosts, h)
				lk.Unlock()
			}
			wg.Done()
		}(*sclient)
	}

	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)
	wg.Wait()

	res, err := c.ImportProject(&client.DOptions{ForcePorts: *forcePorts}, &l)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err)
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}
