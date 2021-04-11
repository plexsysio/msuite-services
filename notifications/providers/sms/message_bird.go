package sms

import (
	Notifications "github.com/aloknerurkar/msuite-services/notifications/pb"
	logger "github.com/ipfs/go-log/v2"
	MessageBird "github.com/messagebird/go-rest-api"
	Sms "github.com/messagebird/go-rest-api/sms"
)

var log = logger.Logger("sms/sender")

type messageBirdHandler struct {
	origin string
	client *MessageBird.Client
}

func NewMessageBirdHandler(
	origin string,
	apiKey string,
) (*messageBirdHandler, error) {
	return &messageBirdHandler{
		origin: origin,
		client: MessageBird.New(apiKey),
	}, nil
}

func (e *messageBirdHandler) SupportedModes() []Notifications.NotificationType {
	return []Notifications.NotificationType{
		Notifications.NotificationType_SMS,
	}
}

func (e *messageBirdHandler) Send(req *Notifications.SendReq) (*Notifications.Notification, error) {
	params := &Sms.Params{}

	_, err := Sms.Create(
		e.client,
		e.origin,
		[]string{req.GetData().To},
		req.GetData().Body,
		params,
	)
	if err != nil {
		log.Errorf("Failed sending sms Err:%s", err.Error())
		return nil, err
	}
	log.Infof("Successfully sent SMS message %s", req.String())
	return &Notifications.Notification{
		UserId: req.GetUserId(),
		Type:   Notifications.NotificationType_SMS,
		Data:   req.GetData(),
	}, nil
}
