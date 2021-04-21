package email

import (
	"crypto/tls"
	Notifications "github.com/plexsysio/msuite-services/notifications/pb"
	logger "github.com/ipfs/go-log/v2"
	"gopkg.in/gomail.v2"
)

var log = logger.Logger("mail/sender")

type emailer struct {
	smtpHost string
	smtpPort int
	username string
	password string
}

func NewEmailer(
	smtpHost string,
	smtpPort int,
	username string,
	password string,
) (*emailer, error) {
	return &emailer{
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		username: username,
		password: password,
	}, nil
}

func (e *emailer) SupportedModes() []Notifications.NotificationType {
	return []Notifications.NotificationType{
		Notifications.NotificationType_EMAIL,
	}
}

func (e *emailer) Send(req *Notifications.SendReq) (*Notifications.Notification, error) {
	d := gomail.NewDialer(e.smtpHost, e.smtpPort, e.username, e.password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	m := gomail.NewMessage()
	m.SetHeader("From", req.GetData().From)
	m.SetHeader("To", req.GetData().To)
	m.SetHeader("Subject", req.GetData().Title)
	m.SetBody("text/html", req.GetData().Body)

	err := d.DialAndSend(m)
	if err != nil {
		log.Errorf("Failed sending email Err:%s", err.Error())
		return nil, err
	}
	log.Infof("Successfully sent Email message %s", req.String())

	return &Notifications.Notification{
		UserId: req.GetUserId(),
		Type:   Notifications.NotificationType_EMAIL,
		Data:   req.GetData(),
	}, nil
}
