package main

import (
	"context"
	"fmt"
	"github.com/plexsysio/go-msuite/lib"
	"github.com/plexsysio/msuite-services/cdn/service"
	logger "github.com/ipfs/go-log/v2"
)

func main() {
	logger.SetLogLevel("*", "Debug")
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
