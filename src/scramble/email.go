package scramble

import (
	"crypto/rand"
	"encoding/hex"
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

//
// EMAIL PARSE
//

// "foo@bar.com" -> EmailAddress
func ParseEmailAddress(addr string) *EmailAddress {
	parsed, ok := ParseEmailAddressSafe(addr)
	if !ok {
		log.Panicf("Invalid email address %s", addr)
	}
	return parsed
}

func ParseEmailAddressSafe(addr string) (*EmailAddress, bool) {
	match := regexAddress.FindStringSubmatch(addr)
	if match == nil {
		return &EmailAddress{}, false
	}
	return &EmailAddress{match[1], match[2]}, true
}

// "foo@bar.com,baz@boo.com" -> []*EmailAddress
func ParseEmailAddresses(addrList string) EmailAddresses {
	if addrList == "" {
		return nil
	}
	addrParts := strings.Split(addrList, ",")
	addrs := EmailAddresses{}
	for _, addrPart := range addrParts {
		addrs = append(addrs, ParseEmailAddress(addrPart))
	}
	return addrs
}

// Parses a string list of email addresses (eg To or CC)
// "<foo@bar.com>,<baz@boo.com>" -> []*EmailAddress
func ParseAngledEmailAddresses(addrList string, delim string) EmailAddresses {
	if addrList == "" {
		return nil
	}
	addrParts := strings.Split(addrList, delim)
	addrs := EmailAddresses{}
	for _, addrPart := range addrParts {
		if addrPart[0:1] != "<" || addrPart[len(addrPart)-1:] != ">" {
			log.Panicf("Invalid angled email address %s", addrPart)
		}
		addrPart = addrPart[1 : len(addrPart)-1]
		addrs = append(addrs, ParseEmailAddress(addrPart))
	}
	return addrs
}

// More flexible than ParseAngledEmailAddresses, just looks for <...>
// Useful for parsing dirty data like the References header.
func ParseAngledEmailAddressesSmart(addrList string) EmailAddresses {
	found := regexAngledAddress.FindAllStringSubmatch(addrList, -1)
	if len(found) == 0 {
		return nil
	}
	addrs := EmailAddresses{}
	for _, addr := range found {
		addrs = append(addrs, &EmailAddress{addr[1], addr[2]})
	}
	return addrs
}

//
// EMAIL ADDRESSES
//

// This lets us add convenience methods to []*EmailAddress
type EmailAddresses []*EmailAddress

// -> "foo@bar.com,baz@boo.com"
func (addrs EmailAddresses) String() string {
	return strings.Join(addrs.Strings(), ",")
}

// -> "<foo@bar.com>,<baz@boo.com>"
func (addrs EmailAddresses) AngledString(delim string) string {
	if len(addrs) == 0 {
		return ""
	}
	return "<" + strings.Join(addrs.Strings(), ">"+delim+"<") + ">"
}

// Like AngledString(), but drops the leftmost items such that
// the result is less than or equal to `limit` bytes.
// This is for storing email>ancestor_ids, for the References header.
func (addrs EmailAddresses) AngledStringCappedToBytes(delim string, limit int) string {
	if len(addrs) == 0 {
		return ""
	}
	res := []byte("<" + strings.Join(addrs.Strings(), ">"+delim+"<") + ">")
	if len(res) <= limit {
		return string(res)
	}
	resPart := string(res[len(res)-limit:])
	addrStart := strings.Index(resPart, "<")
	if addrStart == -1 {
		return ""
	}
	return resPart[addrStart:]
}

// -> ["foo@bar.com","baz@boo.com"]
func (addrs EmailAddresses) Strings() []string {
	addrsList := []string{}
	for _, addr := range addrs {
		addrsList = append(addrsList, addr.String())
	}
	return addrsList
}

// Returns uniqued addresses. Does not modify self.
func (addrs EmailAddresses) Unique() EmailAddresses {
	unique := map[EmailAddress]struct{}{}
	for _, addr := range addrs {
		unique[*addr] = struct{}{}
	}
	uniqued := EmailAddresses{}
	for addr := range unique {
		addrCopy := addr
		uniqued = append(uniqued, &addrCopy)
	}
	return uniqued
}

// Maps email addresses to MX hosts.
// Performs DNS lookup as needed.
//
// returns {<mxHost>:[]*EmailAddress}
//
// Note mxHost is not the same as emailHost. For example:
// [<larry@gmail.com>] -> {"smtp-in.l.gmail.com": [...]}
func (addrs EmailAddresses) GroupByHost() map[string]EmailAddresses {
	hostAddrs := map[string]EmailAddresses{}
	for _, addr := range addrs {
		hostAddrs[addr.Host] = append(hostAddrs[addr.Host], addr)
	}
	return hostAddrs
}

// Like GroupByHost, but resolves the hostname to Mx host.
// The second return value is an array of all addresses that couldn't be resolved.
func (addrs EmailAddresses) GroupByMxHost() (map[string][]EmailAddresses, EmailAddresses) {
	hostAddrs := addrs.GroupByHost()
	mxHostAddrs := map[string][]EmailAddresses{}
	failedAddrs := EmailAddresses{}
	for host, addrs := range hostAddrs {
		var mxHost string
		// Skip lookup for self
		// This helps with localhost testing
		if host == GetConfig().SMTPMxHost {
			mxHostAddrs[host] = append(mxHostAddrs[host], addrs)
			continue
		}
		// Lookup Mx record
		mxHost, err := mxLookUp(host)
		if err != nil {
			failedAddrs = append(failedAddrs, addrs...)
		} else {
			mxHostAddrs[mxHost] = append(mxHostAddrs[mxHost], addrs)
		}
	}
	return mxHostAddrs, failedAddrs
}

func (addrs EmailAddresses) GroupByMxHostFlat() (map[string]EmailAddresses, EmailAddresses) {
	mxHostAddrs, failedAddrs := addrs.GroupByMxHost()
	ret := make(map[string]EmailAddresses)
	for mxHost, addrLists := range mxHostAddrs {
		allAddrs := EmailAddresses{}
		for _, addrs := range addrLists {
			allAddrs = append(allAddrs, addrs...)
		}
		ret[mxHost] = allAddrs
	}
	return ret, failedAddrs
}

//
// MISC
//

func GenerateMessageID() *EmailAddress {
	// generate a message id
	bytes := &[20]byte{}
	rand.Read(bytes[:])
	return &EmailAddress{hex.EncodeToString(bytes[:]), GetConfig().SMTPMxHost}
}
