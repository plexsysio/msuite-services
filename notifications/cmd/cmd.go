package main

import (
	"context"
	"fmt"

	"github.com/plexsysio/go-msuite"
	notificationsSvc "github.com/plexsysio/msuite-services/notifications/service"
)

func main() {
	svc, err := msuite.New(
		msuite.WithService("notifications", notificationsSvc.New),
		msuite.WithAuth("dummysecret"),
		msuite.WithGRPC("tcp", 10000),
		msuite.WithP2P(10001),
		msuite.WithGRPC("p2p", nil),
		msuite.WithHTTP(10002),
		msuite.WithLocker("inmem", nil),
		msuite.WithServiceACL(map[string]string{
			"dummyresource": "admin",
		}),
	)
	if err != nil {
		fmt.Println("failed to start node", err)
		return
	}

	err = svc.Start(context.Background())
	if err != nil {
		fmt.Println("failed to start service", err)
		return
	}

	<-svc.Done()
}
