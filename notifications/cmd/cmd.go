package main

import (
	"fmt"

	"github.com/plexsysio/go-msuite"
	notificationsSvc "github.com/plexsysio/msuite-services/notifications/service"
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

	err = notificationsSvc.New(svc)
	if err != nil {
		fmt.Println("failed to start service", err)
		return
	}

	<-svc.Done()
}
