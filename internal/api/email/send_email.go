package email

import (
	"fmt"
	"net/smtp"
)

func SendEmailWarning(email, oldIP, newIP string) error {
	smtpHost := "smtp.example.com"
	smtpPort := "587"
	smtpUser := "mock@example.com"
	smtpPass := "password"

	msg := fmt.Sprintf("Subject: IP Address Changed\n\n"+
		"Your IP address has changed from %s to %s. "+
		"If this wasn't you, please contact us.", oldIP, newIP)

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, []string{email}, []byte(msg))

	return err
}
