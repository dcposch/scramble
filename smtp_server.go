/**
Modified from Go-Guerrilla SMTPd for Scramble
Copyright (c) 2012 Flashmob, GuerrillaMail.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/sloonz/go-iconv" // TODO: requires GCC.
	"github.com/sloonz/go-qprintable"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/mail"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	clientId    int64
	state       int
	helo        string
	response    string
	conn        net.Conn
	bufin       *bufio.Reader
	bufout      *bufio.Writer
	killTime    int64
	errors      int
	savedNotify chan int
	// Email properties
	time       int64
	mailFrom   string
	rcptTo     []string
	subject    string
	data       string
	remoteAddr string
}

var regexSMTPTemplatep = regexp.MustCompile(`(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----`)

var serverName string
var listenAddress string
var maxSize int
var timeout time.Duration
var sem chan int
var SaveMailChan chan *Client

// TODO: get parameters from config.go
func configure() {
	// MX server name
	serverName = GetConfig().SmtpMxHost
	// SMTP port that nginx forwards to
	listenAddress = fmt.Sprintf("127.0.0.1:%d", GetConfig().SmtpPort)
	// max email size
	maxSize = 131072
	// timeout for reads
	timeout = time.Duration(10)
	// currently active client list, 500 is maxClients
	sem = make(chan int, 500)
	// database writing workers
	SaveMailChan = make(chan *Client, 5)
	return
}

func StartSMTPServer() {
	configure()
	// start some savemail workers
	for i := 0; i < 3; i++ {
		go saveMail()
	}
	// Start listening for SMTP connections
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Printf("Cannot listen on port, %v\n", err)
	} else {
		log.Printf("Listening on %s (SMTP)\n", listenAddress)
	}
	var clientId int64
	clientId = 1
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %s\n", err)
			continue
		}
		log.Println(" There are now " + strconv.Itoa(runtime.NumGoroutine()) + " serving goroutines")
		sem <- 1 // Wait for active queue to drain.
		go handleClient(&Client{
			conn:        conn,
			remoteAddr:  conn.RemoteAddr().String(),
			time:        time.Now().Unix(),
			bufin:       bufio.NewReader(conn),
			bufout:      bufio.NewWriter(conn),
			clientId:    clientId,
			savedNotify: make(chan int),
		})
		clientId++
	}
}

func handleClient(client *Client) {
	defer closeClient(client)
	// TODO: is it safe to show the clientId counter & sem?
	//  it is nice debug info
	greeting := "220 " + serverName +
		" SMTP Scramble-SMTPd #" + strconv.FormatInt(client.clientId, 10) + " (" + strconv.Itoa(len(sem)) + ") " + time.Now().Format(time.RFC1123Z)
	advertiseTls := "250-STARTTLS\r\n"
	for i := 0; i < 100; i++ {
		switch client.state {
		case 0: // GREET
			responseAdd(client, greeting)
			client.state = 1
		case 1: // READ COMMAND
			input, err := readSmtp(client)
			if err != nil {
				log.Printf("Read error: %v\n", err)
				if err == io.EOF {
					// client closed the connection already
					return
				}
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					// too slow, timeout
					return
				}
				break
			}
			input = strings.Trim(input, " \n\r")
			cmd := strings.ToUpper(input)
			switch {
			case strings.Index(cmd, "HELO") == 0:
				if len(input) > 5 {
					client.helo = input[5:]
				}
				responseAdd(client, "250 "+serverName+" Hello ")
			case strings.Index(cmd, "EHLO") == 0:
				if len(input) > 5 {
					client.helo = input[5:]
				}
				responseAdd(client, "250-"+serverName+" Hello "+client.helo+"["+client.remoteAddr+"]"+"\r\n"+"250-SIZE "+strconv.Itoa(maxSize)+"\r\n"+advertiseTls+"250 HELP")
			case strings.Index(cmd, "MAIL FROM:") == 0:
				email := extractEmail(input[10:])
				if email == "" {
					responseAdd(client, "550 Invalid address")
					killClient(client)
				} else {
					client.mailFrom = email
					responseAdd(client, "250 Accepted")
				}
			case strings.Index(cmd, "XCLIENT") == 0:
				// Nginx sends this
				// XCLIENT ADDR=212.96.64.216 NAME=[UNAVAILABLE]
				client.remoteAddr = input[13:]
				client.remoteAddr = client.remoteAddr[0:strings.Index(client.remoteAddr, " ")]
				log.Println("remote client address:[" + client.remoteAddr + "]")
				responseAdd(client, "250 OK")
			case strings.Index(cmd, "RCPT TO:") == 0:
				email := extractEmail(input[8:])
				if email == "" {
					responseAdd(client, "550 Invalid address")
					killClient(client)
				} else {
					client.rcptTo = append(client.rcptTo, email)
					responseAdd(client, "250 Accepted")
				}
			case strings.Index(cmd, "NOOP") == 0:
				responseAdd(client, "250 OK")
			case strings.Index(cmd, "RSET") == 0:
				client.mailFrom = ""
				client.rcptTo = nil
				responseAdd(client, "250 OK")
			case strings.Index(cmd, "DATA") == 0:
				responseAdd(client, "354 Enter message, ending with \".\" on a line by itself")
				client.state = 2
			case (strings.Index(cmd, "STARTTLS") == 0):
				// with Nginx this shouldn't happen
				// responseAdd(client, "220 Ready to start TLS")
				log.Panic("STARTTLS requested but not supported. Nginx SMTP SSL support?")
			case strings.Index(cmd, "QUIT") == 0:
				responseAdd(client, "221 Bye")
				killClient(client)
			default:
				responseAdd(client, fmt.Sprintf("500 unrecognized command"))
				client.errors++
				if client.errors > 3 {
					responseAdd(client, fmt.Sprintf("500 Too many unrecognized commands"))
					killClient(client)
				}
			}
		case 2: // READ DATA
			var err error
			client.data, err = readSmtp(client)
			if err == nil {
				// to do: timeout when adding to SaveMailChan
				// place on the channel so that one of the save mail workers can pick it up
				SaveMailChan <- client
				// wait for the save to complete
				status := <-client.savedNotify

				if status == 1 {
					responseAdd(client, "250 OK : queued")
				} else {
					responseAdd(client, "554 Error : transaction failed, blame it on the weather")
				}
			} else {
				log.Printf("DATA read error: %v\n", err)
			}
			client.state = 1
		}
		// Send a response back to the client
		err := responseWrite(client)
		if err != nil {
			if err == io.EOF {
				// client closed the connection already
				return
			}
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				// too slow, timeout
				return
			}
		}
		if client.killTime > 1 {
			return
		}
	}

}

func responseAdd(client *Client, line string) {
	client.response = line + "\r\n"
}
func closeClient(client *Client) {
	client.conn.Close()
	<-sem // Done; enable next client to run.
}
func killClient(client *Client) {
	client.killTime = time.Now().Unix()
}

func readSmtp(client *Client) (input string, err error) {
	var reply string
	// Command state terminator by default
	suffix := "\r\n"
	if client.state == 2 {
		// DATA state
		suffix = "\r\n.\r\n"
	}
	for err == nil {
		client.conn.SetDeadline(time.Now().Add(timeout * time.Second))
		reply, err = client.bufin.ReadString('\n')
		if reply != "" {
			input = input + reply
			if len(input) > maxSize {
				err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(maxSize) + ")")
				return input, err
			}
			if client.state == 2 {
				// Extract the subject while we are at it.
				scanSubject(client, reply)
			}
		}
		if err != nil {
			break
		}
		if strings.HasSuffix(input, suffix) {
			break
		}
	}
	return input, err
}

// Scan the data part for a Subject line. Can be a multi-line
func scanSubject(client *Client, reply string) {
	if client.subject == "" && (len(reply) > 8) {
		test := strings.ToUpper(reply[0:9])
		if i := strings.Index(test, "SUBJECT: "); i == 0 {
			// first line with \r\n
			client.subject = reply[9:]
		}
	} else if strings.HasSuffix(client.subject, "\r\n") {
		// chop off the \r\n
		client.subject = client.subject[0 : len(client.subject)-2]
		if (strings.HasPrefix(reply, " ")) || (strings.HasPrefix(reply, "\t")) {
			// subject is multi-line
			client.subject = client.subject + reply[1:]
		}
	}
}

func responseWrite(client *Client) (err error) {
	var size int
	client.conn.SetDeadline(time.Now().Add(timeout * time.Second))
	size, err = client.bufout.WriteString(client.response)
	client.bufout.Flush()
	client.response = client.response[size:]
	return err
}

func saveMail() {
	var err error

	//  receives values from the channel repeatedly until it is closed.
	for {
		client := <-SaveMailChan
		log.Println("Mail from "+client.mailFrom+" to "+strings.Join(client.rcptTo, ","))
		// check mailFrom and rcptTo, etc.
		if client_err := validateEmailData(client); client_err != nil {
			log.Println(client_err)
			// notify client that a save completed, -1 = error
			client.savedNotify <- -1
			continue
		}
		client.subject = mimeHeaderDecode(client.subject)
		// compress to save space
		// client.data = compress(add_head + client.data)

		// insert data
		err = deliverMailLocally(client)
		if err != nil {
			log.Printf("Save error, %v\n", err)
			client.savedNotify <- -1
		} else {
			client.savedNotify <- 1
		}
	}
}

func deliverMailLocally(client *Client) error {

	// parse the mail data to get the headers & body
	parsed, err := mail.ReadMessage(strings.NewReader(client.data))
	if err != nil {
		return err
	}

	messageID := parsed.Header.Get("Message-ID")
	if messageID == "" { // generate a message id
		bytes := &[20]byte{}
		rand.Read(bytes[:])
		messageID = hex.EncodeToString(bytes[:])
	} else {
		re, _ := regexp.Compile(`<(.+?)>`)
		if matched := re.FindStringSubmatch(messageID); len(matched) > 1 {
			messageID = strings.Trim(matched[1], " ")
		}
		// trim messageID, we only allow so many characters.
		if len(messageID) > 40 {
			messageID = messageID[:40]
		}
	}

	toList, err := parsed.Header.AddressList("To")
	if err != nil {
		return err
	}
	// TODO: add a way to distinguish To & Cc fields.
	// for now just add merge them into To.
	ccList, err := parsed.Header.AddressList("Cc")
	if err == nil {
		toList = append(toList, ccList...)
	}
	// Bcc fields can be ignored, we still have rcptTo.
	toStrList := []string{}
	for _, to := range toList {
		toStrList = append(toStrList, to.Address)
	}

	bodyBytes, err := ioutil.ReadAll(parsed.Body)
	if err != nil { return err }
	cipherPackets := regexSMTPTemplatep.FindAllString(string(bodyBytes), -1)
	if len(cipherPackets) != 2 {
		return errors.New(fmt.Sprintf("Expected 2 cipher packets (subject & body). Found %v", len(cipherPackets)))
	}

	email := new(Email)
	email.MessageID = messageID
	email.UnixTime = client.time
	email.From = client.mailFrom
	email.To = strings.Join(toStrList, ",")
	email.CipherSubject = cipherPackets[0]
	email.CipherBody = cipherPackets[1]

	// TODO: consider if transactions are required.
	// TODO: saveMessage may fail if messageId is not unique.
	SaveMessage(email)
	log.Println("Saved new email " + messageID)

	// add to inbox locally
	for _, addr := range client.rcptTo {
		AddMessageToBox(email, addr, "inbox")
		log.Println("Got mail: " + addr)
	}

	return nil
}

func validateEmailData(client *Client) error {
	if client.mailFrom == "" {
		return errors.New("Missing MAIL FROM")
	}
	if len(client.rcptTo) == 0 {
		return errors.New("Missing RCPT TO")
	}
	for _, addr := range client.rcptTo {
		// TODO check the hosts of the rcptTo addresses.
		addr = addr // noop :P
	}
	return nil
}

func extractEmail(str string) string {
	re, _ := regexp.Compile(`<(.+?)>`)
	var email string
	if matched := re.FindStringSubmatch(str); len(matched) > 1 {
		email = strings.Trim(matched[1], " ")
	} else {
		email = strings.Trim(str, " ")
	}
	err := validateAddressSafe(email)
	if err != nil {
		return ""
	}

	return email
}

// Decode strings in Mime header format
// eg. =?ISO-2022-JP?B?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=
func mimeHeaderDecode(str string) string {
	reg, _ := regexp.Compile(`=\?(.+?)\?([QBqp])\?(.+?)\?=`)
	matched := reg.FindAllStringSubmatch(str, -1)
	var charset, encoding, payload string
	if matched != nil {
		for i := 0; i < len(matched); i++ {
			if len(matched[i]) > 2 {
				charset = matched[i][1]
				encoding = strings.ToUpper(matched[i][2])
				payload = matched[i][3]
				switch encoding {
				case "B":
					str = strings.Replace(str, matched[i][0], mailTransportDecode(payload, "base64", charset), 1)
				case "Q":
					str = strings.Replace(str, matched[i][0], mailTransportDecode(payload, "quoted-printable", charset), 1)
				}
			}
		}
	}
	return str
}

// decode from 7bit to 8bit UTF-8
// encoding_type can be "base64" or "quoted-printable"
func mailTransportDecode(str string, encoding_type string, charset string) string {
	if charset == "" {
		charset = "UTF-8"
	} else {
		charset = strings.ToUpper(charset)
	}
	if encoding_type == "base64" {
		str = fromBase64(str)
	} else if encoding_type == "quoted-printable" {
		str = fromQuotedP(str)
	}
	if charset != "UTF-8" {
		charset = fixCharset(charset)
		// eg. charset can be "ISO-2022-JP"
		convstr, err := iconv.Conv(str, "UTF-8", charset)
		if err == nil {
			return convstr
		}
	}
	return str
}

func fromBase64(data string) string {
	buf := bytes.NewBufferString(data)
	decoder := base64.NewDecoder(base64.StdEncoding, buf)
	res, _ := ioutil.ReadAll(decoder)
	return string(res)
}

func fromQuotedP(data string) string {
	buf := bytes.NewBufferString(data)
	decoder := qprintable.NewDecoder(qprintable.BinaryEncoding, buf)
	res, _ := ioutil.ReadAll(decoder)
	return string(res)
}

func compress(s string) string {
	var b bytes.Buffer
	w, _ := zlib.NewWriterLevel(&b, zlib.BestSpeed) // flate.BestCompression
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func fixCharset(charset string) string {
	reg, _ := regexp.Compile(`[_:.\/\\]`)
	fixed_charset := reg.ReplaceAllString(charset, "-")
	// Fix charset
	// borrowed from http://squirrelmail.svn.sourceforge.net/viewvc/squirrelmail/trunk/squirrelmail/include/languages.php?revision=13765&view=markup
	// OE ks_c_5601_1987 > cp949
	fixed_charset = strings.Replace(fixed_charset, "ks-c-5601-1987", "cp949", -1)
	// Moz x-euc-tw > euc-tw
	fixed_charset = strings.Replace(fixed_charset, "x-euc", "euc", -1)
	// Moz x-windows-949 > cp949
	fixed_charset = strings.Replace(fixed_charset, "x-windows_", "cp", -1)
	// windows-125x and cp125x charsets
	fixed_charset = strings.Replace(fixed_charset, "windows-", "cp", -1)
	// ibm > cp
	fixed_charset = strings.Replace(fixed_charset, "ibm", "cp", -1)
	// iso-8859-8-i -> iso-8859-8
	fixed_charset = strings.Replace(fixed_charset, "iso-8859-8-i", "iso-8859-8", -1)
	if charset != fixed_charset {
		return fixed_charset
	}
	return charset
}

func md5hex(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	sum := h.Sum([]byte{})
	return hex.EncodeToString(sum)
}
