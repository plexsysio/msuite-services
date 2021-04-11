package apns

import (
	Notifications "github.com/aloknerurkar/msuite-services/notifications/pb"
	Apns "github.com/anachronistic/apns"
	logger "github.com/ipfs/go-log/v2"
)

var log = logger.Logger("fcm/sender")

type apnsHandler struct {
	gateway      string
	certFilename string
	certPassword string
}

func NewApnsHandler(gw, certFile, certPwd string) (*apnsHandler, error) {
	return &apnsHandler{
		gateway:      gw,
		certFilename: certFile,
		certPassword: certPwd,
	}, nil
}

func (a *apnsHandler) SupportedModes() []Notifications.NotificationType {
	return []Notifications.NotificationType{
		Notifications.NotificationType_IOS,
	}
}

func (a *apnsHandler) Send(req *Notifications.SendReq) (*Notifications.Notification, error) {
	client := Apns.NewClient(a.gateway, a.certFilename, a.certPassword)
	pn := Apns.NewPushNotification()
	// Create payload
	payload := Apns.NewPayload()
	payload.Alert = map[string]string{
		"title": req.GetData().Title,
		"body":  req.GetData().Body,
	}
	payload.Badge = 1 // Source:https://distriqt.github.io/ANE-PushNotifications/m.iOS%20APNS%20Payload
	payload.Sound = "default"
	// Set PushNotification object
	pn.AddPayload(payload)
	pn.DeviceToken = req.GetData().To
	// Send the Notification to APNS server using Send API
	res := client.Send(pn)
	if res.Error != nil {
		log.Errorf("Failed sending APNS notification Err: %s", res.Error.Error())
		return nil, res.Error
	}

	log.Infof("Successfully sent APNS message %v", res)

	return &Notifications.Notification{
		UserId: req.GetUserId(),
		Type:   Notifications.NotificationType_IOS,
		Data:   req.GetData(),
	}, nil
}
