package main

import (
	"fmt"
	"scramble"
)

const unreadNoticeFrom = "hello@scramble.io"
const unreadNoticeSubject = "Scramble.io | You've got mail"
const unreadNoticeBody = "You have new encrypted mail! Read it at https://scramble.io"

func main() {
	minAgeMins := 60
	maxAgeMins := 60 * 48
	fmt.Printf("Fetching users with unread email older than %d mins "+
		"but more recent than %d mins ago\n", minAgeMins, maxAgeMins)

	// TODO: probably use MailChimp instead, which has nice HTML
	// email and an unsubscribe link
	addresses := scramble.GetUsersWithUnreadMail(minAgeMins, maxAgeMins)
	for _, address := range addresses {
		if address == "" {
			continue
		}
		fmt.Printf("Unread mail, pinging %s \n", address)
		notifyUnreadMail(address)
	}
}

func notifyUnreadMail(secondaryEmailAddress string) {
	email := scramble.OutgoingEmail{
		IsPlaintext:      true,
		PlaintextSubject: unreadNoticeSubject,
		PlaintextBody:    unreadNoticeBody,
	}
	email.From = unreadNoticeFrom
	email.To = secondaryEmailAddress

	scramble.SmtpSend(&email)
}
