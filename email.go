package main

import (
	"log"
	"strings"
)

type EmailAddress struct {
	Name string
	Hash string
	Host string
}

func (addr *EmailAddress) String() string {
	if addr.Hash == "" {
		return addr.Name + "@" + addr.Host
	} else {
		return addr.Name + "#" + addr.Hash + "@" + addr.Host
	}
}

func (addr *EmailAddress) StringNoHash() string {
	return addr.Name + "@" + addr.Host
}

// "foo@bar.com" -> EmailAddress
func ParseEmailAddress(addr string) EmailAddress {
	match := regexHashAddress.FindStringSubmatch(addr)
	if match == nil {
		log.Panicf("Invalid email address %s", addr)
	}
	return EmailAddress{match[1], match[2], match[3]}
}

// "foo@bar.com,baz@boo.com" -> []EmailAddress
func ParseEmailAddresses(addrList string) EmailAddresses {
	if addrList == "" {
		return nil
	}
	addrParts := strings.Split(addrList, ",")
	addrs := make([]EmailAddress, 0)
	for _, addrPart := range addrParts {
		addrs = append(addrs, ParseEmailAddress(addrPart))
	}
	return addrs
}

// Maps a string list of email addresses (eg To or CC) to MX hosts.
// Performs DNS lookup as needed.
//
// "foo@bar.com,baz@boo.com" -> {<mxHost>:[]EmailAddress}
//
// Note mxHost is not the same as emailHost. For example:
// "larry@gmail.com" -> {"smtp-in.l.gmail.com": [...]}
func GroupAddrsByHost(addrList string) map[string]EmailAddresses {
	if addrList == "" {
		return nil
	}
	addrs := strings.Split(addrList, ",")
	hostAddrs := map[string]EmailAddresses{}
	for _, addr := range addrs {
		email := ParseEmailAddress(addr)
		hostAddrs[email.Host] = append(hostAddrs[email.Host], email)
	}
	return hostAddrs
}

// Like GroupAddrsByHost, but resolves the hostname to Mx host.
// Returns two maps where the second is all the hosts for which the Mx lookup failed.
func GroupAddrsByMxHost(addrList string) (map[string]EmailAddresses, map[string]EmailAddresses) {
	hostAddrs := GroupAddrsByHost(addrList)
	mxHostAddrs := map[string]EmailAddresses{}
	failedHostAddrs := map[string]EmailAddresses{}
	for host, addrs := range hostAddrs {
		var mxHost string
		// Skip lookup for self
		// This helps with localhost testing
		if host == GetConfig().SmtpMxHost {
			mxHostAddrs[host] = append(mxHostAddrs[host], addrs...)
			continue
		}
		// Lookup Mx record
		mxHost, err := smtpLookUp(host)
		if err != nil {
			failedHostAddrs[host] = addrs
		} else {
			mxHostAddrs[mxHost] = append(mxHostAddrs[mxHost], addrs...)
		}
	}
	return mxHostAddrs, failedHostAddrs
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
	return "<" + strings.Join(addrs.Strings(), ">,<") + ">"
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
