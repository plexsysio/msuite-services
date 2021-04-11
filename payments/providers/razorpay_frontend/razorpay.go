package razorpay

import (
	"fmt"
	"github.com/aloknerurkar/msuite-services/payments/pb"
	"github.com/razorpay/razorpay-go"
	"time"
)

type provider struct {
	merchId     string
	merchSecret string
}

func NewRazorpayClient(merchId, merchSecret string) (*provider, error) {
	return &provider{merchId: merchId, merchSecret: merchSecret}, nil
}

func (p *provider) SupportedCards() []pb.CardType {
	return []pb.CardType{
		pb.CardType_CARD_RESERVED,
	}
}

func (p *provider) ProviderId() pb.ProviderId {
	return pb.ProviderId(pb.ProviderId_RAZORPAY_FE)
}

func (p *provider) Charge(req *pb.ChargeReq) (*pb.Charge, error) {
	rzp := razorpay.NewClient(p.merchId, p.merchSecret)
	paymentDetails, err := rzp.Payment.Fetch(req.GetVoucherId(), nil, nil)
	if err != nil {
		return nil, err
	}
	if req.Amount != int64(paymentDetails["amount"].(float64)) {
		return nil, fmt.Errorf("Amount does not match with Order Exp:%d Found%d",
			req.Amount, paymentDetails["amount"].(float64))
	}
	return &pb.Charge{
		Provider:     p.ProviderId(),
		ProviderRef:  req.GetVoucherId(),
		Status:       pb.ChargeStatus_PAID,
		Email:        req.GetEmail(),
		Currency:     req.GetCurrency(),
		ChargeAmount: req.GetAmount(),
		Statement:    req.GetStatement(),
	}, nil
}

func (p *provider) Refund(req *pb.RefundReq) (*pb.Refund, error) {
	rzp := razorpay.NewClient(p.merchId, p.merchSecret)
	refundDetails, err := rzp.Payment.Refund(req.GetProviderRef(),
		int(req.Amount), nil, nil)
	if err != nil {
		return nil, err
	}
	return &pb.Refund{
		ProviderRef:  refundDetails["id"].(string),
		RefundAmount: int64(refundDetails["amount"].(float64)),
		Created:      time.Now().Unix(),
		Type:         req.Type,
	}, nil
}
