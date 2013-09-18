package main

import (
	"log"
	"strings"
)

type EmailAddress struct {
	Name string
	Host string
}

func (addr *EmailAddress) String() string {
	return addr.Name + "@" + addr.Host
}

func (addr *EmailAddress) IsHashAddress() bool {
	return regexHash.MatchString(addr.Name)
}

// "foo@bar.com" -> EmailAddress
func ParseEmailAddress(addr string) EmailAddress {
	parts := strings.Split(strings.TrimSpace(addr), "@")
	if len(parts) != 2 {
		log.Panicf("Invalid email address %s", addr)
	}
	return EmailAddress{parts[0], parts[1]}
}

// "foo@bar.com,baz@boo.com" -> []EmailAddress
func ParseEmailAddresses(addrList string) EmailAddresses {
	addrParts := strings.Split(addrList, ",")
	addrs := make([]EmailAddress, 0)
	for _, addrPart := range addrParts {
		addrs = append(addrs, ParseEmailAddress(addrPart))
	}
	return addrs
}

// "foo@bar.com,baz@boo.com" -> {<host>:[]EmailAddress}
func GroupAddrsByHost(addrList string) map[string]EmailAddresses {
	addrs := strings.Split(addrList, ",")
	hostAddrs := map[string]EmailAddresses{}
	for _, addr := range addrs {
		addr = validateAddress(addr)
		match := regexAddress.FindStringSubmatch(addr)
		name := match[1]
		host := match[2]
		hostAddrs[host] = append(hostAddrs[host], EmailAddress{name, host})
	}
	return hostAddrs
}

// This lets us add convenience methods to []EmailAddress
type EmailAddresses []EmailAddress

// -> "foo@bar.com,baz@boo.com"
func (addrs EmailAddresses) String() string {
	return strings.Join(addrs.Strings(), ",")
}

// -> "<foo@bar.com>,<baz@boo.com>"
func (addrs EmailAddresses) AngledString() string {
	if len(addrs) == 0 {
		return ""
	}
	return "<"+strings.Join(addrs.Strings(), ">,<")+">"
}

// -> ["foo@bar.com","baz@boo.com"]
func (addrs EmailAddresses) Strings() []string {
	addrsList := []string{}
	for _, addr := range addrs {
		addrsList = append(addrsList, addr.String())
	}
	return addrsList
}

// Returns those addresses that have given host
func (addrs EmailAddresses) FilterByHost(host string) EmailAddresses {
	filtered := []EmailAddress{}
	for _, addr := range addrs {
		if addr.Host == host {
			filtered = append(filtered, addr)
		}
	}
	return filtered
}
