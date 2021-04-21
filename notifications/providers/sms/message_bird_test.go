package sms

import (
	"fmt"
	"testing"

	Notifications "github.com/plexsysio/msuite-services/notifications/pb"
)

var ApiKey = "HLYWprzbMaRiVXa3rwqKzyTIY"

func TestNewMessageBirdHandler(t *testing.T) {
	messageBirdConf, err := NewMessageBirdHandler("9620058174", ApiKey)
	if err != nil {
		t.Fatal("Failed to create NewMessageBirdHandler")
	}
	if messageBirdConf.client.AccessKey != ApiKey {
		t.Fatal("Inconsistent Api key")
	}
}

func TestSendMessage(t *testing.T) {
	fmt.Println("Sending a SMS to authorized receipient")
	sendReq := &Notifications.SendReq{
		Type: Notifications.NotificationType_SMS,
		Data: &Notifications.Msg{
			From:  "919620058174",
			To:    "919620058174",
			Title: "Innovolt",
			Body:  "Hi, I am Navlok. This message is sent from go test",
		},
	}
	messageBirdConf, err := NewMessageBirdHandler("9620058174", ApiKey)
	if err != nil {
		t.Fatal("Failed to create NewMessageBirdHandler")
	}
	_, err = messageBirdConf.Send(sendReq)
	if err != nil {
		t.Fatal("Failed to send SMS to authorized receipient")
	}
}
