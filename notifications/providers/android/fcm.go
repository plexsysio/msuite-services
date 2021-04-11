package android

import (
	Notifications "github.com/aloknerurkar/msuite-services/notifications/pb"
	logger "github.com/ipfs/go-log/v2"
	"github.com/maddevsio/fcm"
)

var log = logger.Logger("fcm/sender")

type fcmHandler struct {
	apiKey string
}

func NewFcmHandler(apiKey string) (*fcmHandler, error) {
	return &fcmHandler{
		apiKey: apiKey,
	}, nil
}

func (f *fcmHandler) SupportedModes() []Notifications.NotificationType {
	return []Notifications.NotificationType{
		Notifications.NotificationType_ANDROID,
	}
}

func (f *fcmHandler) Send(req *Notifications.SendReq) (*Notifications.Notification, error) {
	c := fcm.NewFCM(f.apiKey)
	response, err := c.Send(fcm.Message{
		RegistrationIDs:  []string{req.Data.To},
		ContentAvailable: true,
		Priority:         fcm.PriorityHigh,
		Notification: fcm.Notification{
			Title: req.Data.GetTitle(),
			Body:  req.Data.GetBody(),
			Sound: "default",
			Badge: "3",
		},
	})
	if err != nil {
		log.Errorf("Failed sending FCM message Err:%s", err.Error())
		return nil, err
	}

	log.Infof("Successfully sent FCM notification Resp: %v", response)

	return &Notifications.Notification{
		UserId: req.GetUserId(),
		Type:   Notifications.NotificationType_ANDROID,
		Data:   req.GetData(),
	}, nil
}
