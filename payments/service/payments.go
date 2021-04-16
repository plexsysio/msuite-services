package payments

import (
	"github.com/SWRMLabs/ss-store"
	"github.com/aloknerurkar/dLocker"
	"github.com/aloknerurkar/go-msuite/lib"
	"github.com/aloknerurkar/msuite-services/app_errors"
	msgs "github.com/aloknerurkar/msuite-services/common/pb"
	"github.com/aloknerurkar/msuite-services/payments/pb"
	"github.com/aloknerurkar/msuite-services/payments/providers"
	proto "github.com/golang/protobuf/proto"
	logger "github.com/ipfs/go-log/v2"
	"golang.org/x/net/context"
	"math"
	"sync"
	"time"
)

var log = logger.Logger("payments")

type chargeObj struct {
	*pb.Charge
}

func (l *chargeObj) GetNamespace() string { return "payments/charge" }

func (l *chargeObj) GetId() string { return l.ChargeId }

func (l *chargeObj) SetId(id string) { l.ChargeId = id }

func (l *chargeObj) SetCreated(i int64) { l.Created = i }

func (l *chargeObj) SetUpdated(i int64) { l.Updated = i }

func (l *chargeObj) Marshal() ([]byte, error) {
	return proto.Marshal(l)
}

func (l *chargeObj) Unmarshal(buf []byte) error {
	return proto.Unmarshal(buf, l)
}

func (l *chargeObj) Factory() store.SerializedItem { return &chargeObj{} }

type payments struct {
	pb.UnimplementedPaymentsServer
	dbP     store.Store
	lckr    dLocker.DLocker
	provdrs *providers.Providers
}

func New(svc msuite.Service) error {
	ndApi, err := svc.Node()
	if err != nil {
		return err
	}
	grpcApi, err := svc.GRPC()
	if err != nil {
		return err
	}
	lcker, err := svc.Locker()
	if err != nil {
		return err
	}
	providerCfg := []map[string]interface{}{}
	if ok := svc.Repo().Config().Get("PaymentProviders", &providerCfg); !ok {
		log.Warn("No payment providers configured")
	}
	p, err := providers.NewProviders(providerCfg)
	if err != nil {
		return err
	}
	pb.RegisterPaymentsServer(grpcApi.Server(), &payments{
		provdrs: p,
		dbP:     ndApi.Storage(),
		lckr:    lcker,
	})
	return nil
}

func checkSupportedCard(p pb.ProviderId) bool {
	if p == pb.ProviderId_RAZORPAY_FE {
		return false
	}
	return true
}

func (p *payments) NewCharge(c context.Context,
	payReq *pb.ChargeReq) (retCharge *pb.Charge, retErr error) {

	pr := p.provdrs.GetProvider(payReq.Provider)

	if checkSupportedCard(pr.ProviderId()) {
		supported := false
		for _, v := range pr.SupportedCards() {
			if v == payReq.GetCard().Type {
				supported = true
				break
			}
		}
		if !supported {
			retErr = app_errors.ErrInvalidArg("Card type not supported.")
			log.Errorf("Unsupported card type:%v", payReq)
			return
		}
	}
	var err error
	retCharge, err = pr.Charge(payReq)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed to charge.")
		log.Errorf("Failed to charge SecErr:%s Req:%v", err.Error(), payReq)
		return
	}
	retCharge.Status = pb.ChargeStatus_PAID
	ch := &chargeObj{
		Charge: retCharge,
	}
	err = p.dbP.Create(ch)
	if err != nil {
		if _, err := pr.Refund(&pb.RefundReq{
			ProviderRef: retCharge.ProviderRef,
			Type:        pb.Refund_SERVER_ERROR,
			Amount:      retCharge.ChargeAmount,
			Currency:    retCharge.Currency}); err != nil {
			retErr = app_errors.ErrInternal("Failed to store charge and then failed to refund.")
			log.Errorf("Failed to refund charge after initial failure SecErr:%s Req:%v",
				err.Error(), payReq)
			return
		}
		retErr = app_errors.ErrInternal("Failed to store charge, amount refunded.")
		log.Errorf("SecErr:%s Req:%v", err.Error(), payReq)
	}

	return
}

func (p *payments) RefundCharge(c context.Context,
	refundReq *pb.RefundReq) (retRefund *pb.Refund, retErr error) {

	charge := &chargeObj{
		Charge: &pb.Charge{
			ChargeId: refundReq.ChargeId,
		},
	}
	unlock, err := p.lckr.TryLock(c, charge.GetNamespace()+"/"+charge.GetId(), time.Second*5)
	if err != nil {
		retErr = app_errors.ErrResourceExhausted("Unable to lock charge.")
		log.Errorf("Failed to lock charge SecErr:%s Req:%v", err.Error(), refundReq)
		return
	}
	defer unlock()
	err = p.dbP.Read(charge)
	if err != nil {
		retErr = app_errors.ErrInvalidArg("Unable to find charge.")
		log.Errorf("Unable to find charge SecErr:%s Req:%v", err.Error(), refundReq)
		return
	}
	if charge.Status != pb.ChargeStatus_PAID || charge.ChargeAmount <= 0 ||
		charge.ChargeAmount < refundReq.Amount ||
		(charge.RefundAmount+refundReq.Amount) > charge.ChargeAmount {
		retErr = app_errors.ErrPermissionDenied("Refund not available for this charge.")
		log.Errorf("Charge not refundable Req:%v", refundReq)
		return
	}
	refundReq.ProviderRef = charge.ProviderRef
	pr := p.provdrs.GetProvider(charge.Provider)
	retRefund, err = pr.Refund(refundReq)
	if err != nil {
		retErr = app_errors.ErrInternal("Unable to process refund.")
		log.Errorf("Failed to process refund SecErr:%s Req:%v", err.Error(), refundReq)
		return
	}
	charge.RefundAmount += retRefund.RefundAmount
	charge.Status = pb.ChargeStatus_REFUNDED
	charge.RefundInfo = append(charge.RefundInfo, retRefund)

	err = p.dbP.Update(charge)
	if err != nil {
		retErr = app_errors.ErrInternal("Unable to update charge.")
		log.Errorf("Failed to update refund SecErr:%s Req:%v", err.Error(), charge)
		return
	}
	return
}

func (p *payments) Get(
	c context.Context,
	ids *msgs.UUIDs,
) (retItems *pb.Charges, retErr error) {

	ch := make(chan *chargeObj)
	wg := sync.WaitGroup{}
	retItems = &pb.Charges{}
	retItems.Charges = []*pb.Charge{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case it, ok := <-ch:
				if !ok {
					return
				}
				retItems.Charges = append(retItems.Charges, it.Charge)
			}
		}
	}()
	fanout := math.Ceil(float64(len(ids.Vals)) / 1000.0)
	for i := 0; i < int(fanout); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := i * 1000
			end := start + 1000
			if start+1000 > (len(ids.Vals) - 1) {
				end = len(ids.Vals) - 1
			}
			for _, v := range ids.Vals[start:end] {
				c := &chargeObj{
					&pb.Charge{
						ChargeId: v,
					},
				}
				err := p.dbP.Read(c)
				if err != nil {
					log.Errorf("Failed reading charge %s Err:%s", c.String(), err.Error())
				} else {
					ch <- c
				}
			}
		}()
	}
	wg.Wait()
	return
}

func (p *payments) List(
	c context.Context,
	req *msgs.ListReq,
) (retItems *pb.Charges, retErr error) {
	listOpt := store.ListOpt{
		Page:  req.Page,
		Limit: req.Limit,
	}
	items, err := p.dbP.List(&chargeObj{}, listOpt)
	if err != nil {
		log.Errorf("Failed listing Charge items Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to list Charge items.")
		return
	}

	retItems = new(pb.Charges)
	retItems.Charges = make([]*pb.Charge, len(items))
	for i := 0; i < len(items); i++ {
		retItems.Charges[i] = items[i].(*chargeObj).Charge
	}
	return
}
