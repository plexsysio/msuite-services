package service

import (
	"github.com/plexsysio/go-msuite/core"
	"github.com/plexsysio/msuite-services/notifications/providers"
)

func NewCtorWithProvider(p providers.Provider) func(core.Service) error {
	return func(svc core.Service) error {
		return newWithProviders(svc, []providers.Provider{p})
	}
}
