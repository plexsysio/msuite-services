package providers

import (
	"errors"
	"github.com/plexsysio/msuite-services/notifications/pb"
	"github.com/plexsysio/msuite-services/notifications/providers/android"
	"github.com/plexsysio/msuite-services/notifications/providers/email"
	apns "github.com/plexsysio/msuite-services/notifications/providers/ios"
	"github.com/plexsysio/msuite-services/notifications/providers/sms"
)

type Provider interface {
	SupportedModes() []pb.NotificationType
	Send(*pb.SendReq) (*pb.Notification, error)
}

func NewProviders(providerCfg []map[string]interface{}) ([]Provider, error) {
	pvdrs := make([]Provider, len(providerCfg))
	for i, v := range providerCfg {
		var (
			p   Provider
			err error
		)
		switch v["Type"].(string) {
		case pb.NotificationType_EMAIL.String():
			emCfg, ok := v["Cfg"].(map[string]interface{})
			if !ok {
				return nil, errors.New("Emailer config invalid")
			}
			p, err = email.NewEmailer(
				emCfg["SMTPHost"].(string),
				emCfg["SMTPPort"].(int),
				emCfg["Username"].(string),
				emCfg["Password"].(string),
			)
		case pb.NotificationType_SMS.String():
			mbCfg, ok := v["Cfg"].(map[string]interface{})
			if !ok {
				return nil, errors.New("SMS handler config invalid")
			}
			p, err = sms.NewMessageBirdHandler(
				mbCfg["Origin"].(string),
				mbCfg["APIKey"].(string),
			)
		case pb.NotificationType_ANDROID.String():
			fcmCfg, ok := v["Cfg"].(map[string]interface{})
			if !ok {
				return nil, errors.New("FCM handler config invalid")
			}
			p, err = android.NewFcmHandler(fcmCfg["APIKey"].(string))
		case pb.NotificationType_IOS.String():
			apnsCfg, ok := v["Cfg"].(map[string]interface{})
			if !ok {
				return nil, errors.New("APNS handler config invalid")
			}
			p, err = apns.NewApnsHandler(
				apnsCfg["Gateway"].(string),
				apnsCfg["CertFile"].(string),
				apnsCfg["CertPassword"].(string),
			)
		default:
			err = errors.New("Unimplemented provider type.")
		}
		if err != nil {
			return nil, err
		}
		pvdrs[i] = p
	}
	return pvdrs, nil
}
