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

func ParseEmailAddress(addr string) EmailAddress {
	parts := strings.Split(strings.TrimSpace(addr), "@")
	if len(parts) != 2 {
		log.Panicf("Invalid email address %s", addr)
	}
	return EmailAddress{parts[0], parts[1]}
}

func ParseEmailAddresses(addrList string) []EmailAddress {
	addrParts := strings.Split(addrList, ",")
	addrs := make([]EmailAddress, 0)
	for _, addrPart := range addrParts {
		addrs = append(addrs, ParseEmailAddress(addrPart))
	}
	return addrs
}
