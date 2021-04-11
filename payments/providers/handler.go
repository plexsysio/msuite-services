package providers

import (
	"errors"
	"github.com/aloknerurkar/msuite-services/payments/pb"
	"github.com/aloknerurkar/msuite-services/payments/providers/razorpay_frontend"
)

type Provider interface {
	ProviderId() pb.ProviderId
	SupportedCards() []pb.CardType
	Charge(*pb.ChargeReq) (*pb.Charge, error)
	Refund(*pb.RefundReq) (*pb.Refund, error)
}

type Providers struct {
	providers map[pb.ProviderId]Provider
}

func NewProviders(conf []map[string]interface{}) (*Providers, error) {
	p := new(Providers)
	p.providers = make(map[pb.ProviderId]Provider)
	for _, v := range conf {
		var (
			pvdr Provider
			err  error
		)
		cfg, ok := v["Cfg"].(map[string]interface{})
		if !ok {
			return nil, errors.New("Payment provider config absent")
		}
		switch cfg["Type"].(string) {
		case pb.ProviderId_RAZORPAY_FE.String():
			pvdr, err = razorpay.NewRazorpayClient(
				cfg["MerchantId"].(string),
				cfg["MerchantSecret"].(string),
			)
		default:
			return nil, errors.New("Invalid payment provider config")
		}
		if err != nil {
			return nil, err
		}
		p.providers[pvdr.ProviderId()] = pvdr
	}
	return p, nil
}

func (p *Providers) GetProvider(id pb.ProviderId) Provider {
	if v, ok := p.providers[id]; ok {
		return v
	}
	return nil
}
