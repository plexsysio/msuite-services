package main

import (
	"context"
	"fmt"

	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/go-msuite"
	cdn "github.com/plexsysio/msuite-services/cdn/service"
)

func main() {
	logger.SetLogLevel("cdn", "Debug")
	svc, err := msuite.New(
		msuite.WithServiceName("CDN"),
		msuite.WithHTTP(8080),
		msuite.WithP2PPort(10000),
	)
	err = cdn.NewCDNService(svc)
	if err != nil {
		fmt.Println("Failed creating new CDN service", err.Error())
		return
	}
	err = svc.Start(context.Background())
	if err != nil {
		fmt.Println("Failed creating new CDN service", err.Error())
		return
	}
	<-svc.Done()
	svc.Stop(context.Background())
}
