package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/plexsysio/go-msuite"
	"github.com/plexsysio/msuite-services/notifications/providers"
	notificationsSvc "github.com/plexsysio/msuite-services/notifications/service"
)

var (
	smtpHost     = os.Getenv("SMTPHost")
	smtpPort     = os.Getenv("SMTPPort")
	smtpUsername = os.Getenv("Username")
	smtpPassword = os.Getenv("Password")
)

func main() {
	svc, err := msuite.New(
		msuite.WithServices("notifications"),
		msuite.WithGRPC("tcp", 10000),
		msuite.WithP2P(10001),
		msuite.WithGRPC("p2p", nil),
		msuite.WithHTTP(10002),
	)
	if err != nil {
		fmt.Println("failed to start node", err)
		return
	}

	sport, err := strconv.Atoi(smtpPort)
	if err != nil {
		fmt.Println("SMTP port missing")
	}

	pvdrs, err := providers.NewProviders([]map[string]interface{}{
		{
			"Type": "EMAIL",
			"Cfg": map[string]interface{}{
				"SMTPHost": smtpHost,
				"SMTPPort": sport,
				"Username": smtpUsername,
				"Password": smtpPassword,
			},
		},
	})
	if err != nil {
		fmt.Println("failed to created providers", err)
		return
	}

	err = notificationsSvc.NewWithProviders(svc, pvdrs)
	if err != nil {
		fmt.Println("failed to start service", err)
		return
	}

	<-svc.Done()
}
