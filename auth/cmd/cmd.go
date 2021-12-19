package main

import (
	"context"
	"fmt"

	"github.com/plexsysio/go-msuite"
	authSvc "github.com/plexsysio/msuite-services/auth/service"
	authUI "github.com/plexsysio/msuite-services/auth/ui"
)

func main() {
	svc, err := msuite.New(
		msuite.WithService("Auth", authSvc.New),
		msuite.WithService("AuthUI", authUI.New),
		msuite.WithJWT("dummysecret"),
		msuite.WithGRPC(),
		msuite.WithGRPCTCPListener(10000),
		msuite.WithP2PPort(10001),
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