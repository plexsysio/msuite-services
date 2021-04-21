package rpc_service

import (
	"context"
	"errors"
	"time"

	"github.com/SWRMLabs/ss-store"
	"github.com/plexsysio/dLocker"
	"github.com/plexsysio/go-msuite/lib"
	"github.com/plexsysio/msuite-services/app_errors"
	msgs "github.com/plexsysio/msuite-services/common/pb"
	inv "github.com/plexsysio/msuite-services/inventory/pb"
	"github.com/plexsysio/msuite-services/orders/pb"
	pmnts "github.com/plexsysio/msuite-services/payments/pb"
	"github.com/plexsysio/msuite-services/utils"
	proto "github.com/golang/protobuf/proto"
	logger "github.com/ipfs/go-log/v2"
)

var (
	orderTTL time.Duration = time.Minute * 5
	log                    = logger.Logger("orders")
)

type orderItem struct {
	*pb.Item
}

func (l *orderItem) GetNamespace() string { return "orders" }

func (l *orderItem) SetId(i string) { l.Id = i }

func (l *orderItem) SetCreated(i int64) { l.Created = i }

func (l *orderItem) SetUpdated(i int64) { l.Updated = i }

func (l *orderItem) Marshal() ([]byte, error) {
	return proto.Marshal(l.Item)
}

func (l *orderItem) Unmarshal(buf []byte) error {
	if l.Item == nil {
		l.Item = &pb.Item{}
	}
	return proto.Unmarshal(buf, l.Item)
}

func (l *orderItem) LockString() string {
	return "/" + l.GetNamespace() + "/" + l.GetId()
}

func (l *orderItem) Factory() store.SerializedItem {
	return &orderItem{}
}

type inventoryItem struct {
	*inv.Item
}

func (l *inventoryItem) GetNamespace() string { return "inventory" }

func (l *inventoryItem) SetCreated(i int64) { l.Created = i }

func (l *inventoryItem) SetUpdated(i int64) { l.Updated = i }

func (l *inventoryItem) Marshal() ([]byte, error) {
	return proto.Marshal(l.Item)
}

func (l *inventoryItem) Unmarshal(buf []byte) error {
	if l.Item == nil {
		l.Item = &inv.Item{}
	}
	return proto.Unmarshal(buf, l.Item)
}

func (l *inventoryItem) LockString() string {
	return "/" + l.GetNamespace() + "/" + l.GetId()
}

type lockedOrderItem struct {
	Item   *inv.Item
	Unlock func()
	Update func() error
}

type updateFn func() error
type unlockFn func() error

type orders struct {
	pb.UnimplementedOrdersServer
	dbP  store.Store
	lckr dLocker.DLocker
	rpc  msuite.GRPC
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
	lckrApi, err := svc.Locker()
	if err != nil {
		return err
	}
	oSvc := &orders{
		dbP:  ndApi.Storage(),
		lckr: lckrApi,
		rpc:  grpcApi,
	}
	pb.RegisterOrdersServer(grpcApi.Server(), oSvc)
	return nil
}

func isPayable(order *pb.Item) error {
	if order.Status != pb.Item_CREATED {
		return errors.New("Incorrect order state")
	}

	if time.Since(time.Unix(order.Created, 0)) > orderTTL {
		return errors.New("Order too old")
	}

	if order.Amount <= 0 {
		return errors.New("Order amount is 0")
	}
	return nil
}

func isReturnable(order *pb.Item) error {
	if order.Status != pb.Item_PAID && order.Status != pb.Item_COMPLETED &&
		order.Status != pb.Item_CANCELLED {
		return errors.New("Incorrect order state")
	}
	return nil
}

func (o *orders) updateOrder(ctx context.Context, order *pb.Item, item *pb.NewOrderReq) error {

	orderItems := make([]*pb.OrderItem, 0)

	conn, err := o.rpc.Client(ctx, "inventory")
	if err != nil {
		return err
	}
	defer conn.Close()

	invSvc := inv.NewInventoryClient(conn)

	req := &msgs.UUIDs{Vals: []string{item.ItemId}}
	invItem, err := invSvc.Get(context.Background(), req)
	if err != nil {
		return err
	}

	if !invItem.Items[0].Active || invItem.Items[0].Count == 0 {
		return errors.New("Item not available")
	}

	validRate := false
	for _, v := range invItem.Items[0].Rates {
		if v.String() == item.Rate.String() {
			validRate = true
		}
	}

	if !validRate {
		log.Errorf("Rate invalid Exp:%s Specified:%s",
			invItem.Items[0].String(), item.String())
		return errors.New("Invalid rate specified")
	}

	var prodCost int64
	prodCost = item.Rate.Amount
	orderItems = append(orderItems, &pb.OrderItem{
		Type: pb.OrderItem_INVENTORY, Amount: prodCost, ParentId: item.ItemId})

	var metaCost, discountCost, taxCost int64
	for _, v := range item.Items {
		if v.Type == pb.OrderItem_INSURANCE {
			metaCost += 1
		}
		// Going ahead we need to check if discount is applicable
		if v.Type == pb.OrderItem_DISCOUNT {
			discountCost += -1
		}
		if v.Type == pb.OrderItem_TAX {
			taxCost += 1
		}
	}
	order.Items = orderItems
	order.Amount = prodCost + metaCost + taxCost - discountCost
	return nil
}

func (o *orders) getLockedOrderItem(ctx context.Context, ord *pb.Item) (*lockedOrderItem, error) {

	var invItem *inventoryItem
	for _, v := range ord.Items {
		if v.Type == pb.OrderItem_INVENTORY {
			invItem = &inventoryItem{
				Item: &inv.Item{
					Id: v.ParentId,
				},
			}
		}
	}

	if invItem == nil {
		log.Errorf("Order doesnt contain any inventory item")
		return nil, errors.New("Inventory item not found")
	}

	unlock, err := o.lckr.TryLock(ctx, invItem.LockString(), time.Second*3)
	if err != nil {
		return nil, err
	}

	err = o.dbP.Read(invItem)
	if err != nil {
		unlock()
		return nil, err
	}

	updFn := func() error {
		err = o.dbP.Update(invItem)
		return err
	}

	return &lockedOrderItem{
		Item:   invItem.Item,
		Unlock: unlock,
		Update: updFn,
	}, nil
}

func (o *orders) NewOrder(c context.Context, newOrder *pb.NewOrderReq) (retOrder *pb.Item, retErr error) {

	ord := &orderItem{
		&pb.Item{
			Amount:   0,
			Currency: newOrder.Rate.Currency,
			Status:   pb.Item_CREATED,
			Email:    newOrder.Email,
			UserId:   newOrder.UserId,
		},
	}

	err := o.updateOrder(c, ord.Item, newOrder)
	if err != nil {
		log.Errorf("Unable to update Order %v with %v. Err:%s", ord, newOrder,
			err.Error())
		retErr = app_errors.ErrInternal("Unable to update order.")
		return
	}

	err = o.dbP.Create(ord)
	if err != nil {
		log.Errorf("Failed to store Order %v. Err:%s", ord, err.Error())
		retErr = app_errors.ErrInternal("Failed to store order details")
		return
	}

	retOrder = ord.Item

	return
}

func (o *orders) PayOrder(c context.Context, payOrder *pb.PayOrderReq) (retOrder *pb.Item, retErr error) {

	if len(payOrder.Charges) > 1 {
		log.Errorf("Multiple pay split not implemented")
		retErr = app_errors.ErrUnimplemented("Multiple pay split not allowed.")
		return
	}

	ord := &orderItem{&pb.Item{Id: payOrder.OrderId}}

	unlock, err := o.lckr.TryLock(c, ord.LockString(), time.Second*3)
	if err != nil {
		log.Errorf("Failed to lock order item %s Err:%s", payOrder.OrderId, err.Error())
		retErr = app_errors.ErrResourceExhausted("Unable to lock order.")
		return
	}
	defer unlock()

	err = o.dbP.Read(ord)
	if err != nil {
		log.Errorf("Failed to read order %s Err:%s", ord.GetId(), err.Error())
		retErr = app_errors.ErrInvalidArg("Unable to find order.")
		return
	}

	err = isPayable(ord.Item)
	if err != nil {
		log.Errorf("Order is not payable Err:%s", err.Error())
		retErr = app_errors.ErrUnavailable("Unable to pay order.")
		return
	}

	item, err := o.getLockedOrderItem(c, ord.Item)
	if err != nil {
		log.Errorf("Failed to lock order item Err:%s", err)
		retErr = app_errors.ErrInternal("Failed to lock order item")
		return
	}
	defer item.Unlock()

	req := &pmnts.ChargeReq{
		Provider:  payOrder.Charges[0].Provider,
		Amount:    ord.Amount,
		Currency:  ord.Currency,
		Email:     ord.Email,
		Statement: "Order ID " + ord.Id,
	}
	switch {
	case len(payOrder.Charges[0].GetUserId()) > 0:
		req.Source = &pmnts.ChargeReq_UserId{
			UserId: payOrder.Charges[0].GetUserId(),
		}
	case payOrder.Charges[0].GetCard() != nil:
		req.Source = &pmnts.ChargeReq_Card{
			Card: payOrder.Charges[0].GetCard(),
		}
	case len(payOrder.Charges[0].GetPaymentRef()) > 0:
		req.Source = &pmnts.ChargeReq_VoucherId{
			VoucherId: payOrder.Charges[0].GetPaymentRef(),
		}
	}

	paymentsConn, err := o.rpc.Client(c, "payments")
	if err != nil {
		log.Errorf("Failed to get connection to payment service Err: %s", err.Error())
		retErr = app_errors.ErrInternal("Failed getting connection.")
		return
	}
	defer paymentsConn.Close()

	paymentsSvc := pmnts.NewPaymentsClient(paymentsConn)

	charge, err := paymentsSvc.NewCharge(context.Background(), req)
	if err != nil {
		log.Errorf("Failed creating new charge Err:%s", err.Error())
		retErr = err
		return
	}

	ord.PaymentId = charge.ChargeId
	ord.Status = pb.Item_PAID

	// This should be done with retry
	err = o.dbP.Update(ord)
	if err != nil {
		r, e := paymentsSvc.RefundCharge(context.Background(), &pmnts.RefundReq{
			Type:     pmnts.Refund_PROVIDER_FAILURE,
			Amount:   ord.Amount,
			Currency: ord.Currency,
			ChargeId: charge.ChargeId,
		})
		if e != nil {
			log.Errorf("Failed to refund charge on DB failure Err:%s", e.Error())
			retErr = e
			return
		}
		log.Errorf("Failed to update DB with charge %s. Charge refunded Id %s. Err:%s",
			charge.ChargeId, r.ProviderRef, err.Error())
		retErr = app_errors.ErrInternal("Failed to store order. Charge Refunded")
		return
	}

	// Update the inventory item
	item.Item.Count--
	err = item.Update()
	if err != nil {
		// This error is ignored at this point.
		log.Errorf("Failed to update inventory after payment of order Err:%s")
	}

	retOrder = ord.Item

	return
}

func (o *orders) ReturnOrder(c context.Context, orderId *msgs.UUID) (retOrder *pb.Item, retErr error) {

	ord := &orderItem{&pb.Item{Id: orderId.Val}}

	unlock, err := o.lckr.TryLock(c, ord.LockString(), time.Second*3)
	if err != nil {
		log.Errorf("Failed to lock order item Err:%s", err.Error())
		retErr = app_errors.ErrResourceExhausted("Unable to lock order.")
		return
	}
	defer unlock()

	err = o.dbP.Read(ord)
	if err != nil {
		log.Errorf("Failed to read order item Err:%s", err.Error())
		retErr = app_errors.ErrInvalidArg("Unable to find order.")
		return
	}

	err = isReturnable(ord.Item)
	if err != nil {
		log.Errorf("Order item not returnable Err:%s", err.Error())
		retErr = app_errors.ErrPermissionDenied("Order not returnable.")
		return
	}

	item, err := o.getLockedOrderItem(c, ord.Item)
	if err != nil {
		log.Errorf("Failed to lock inventory item Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to lock inventory item")
		return
	}
	defer item.Unlock()

	paymentsConn, err := o.rpc.Client(c, "payments")
	if err != nil {
		log.Errorf("Failed to get connection to Payment svc Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed getting connection.")
		return
	}
	defer paymentsConn.Close()

	paymentsSvc := pmnts.NewPaymentsClient(paymentsConn)

	r, err := paymentsSvc.RefundCharge(context.Background(), &pmnts.RefundReq{
		Type:     pmnts.Refund_USER_REQUESTED,
		Amount:   ord.Amount,
		Currency: ord.Currency,
		ChargeId: ord.PaymentId,
	})
	if err != nil {
		log.Errorf("Failed refunding charge %s Err:%s", item.Item.Id, err.Error())
		retErr = app_errors.ErrInternal("Failed to refund charge")
		return
	}

	item.Item.Count++
	err = item.Update()
	if err != nil {
		log.Errorf("Failed to update item after refund %s. Ignore error", r.ProviderRef)
	}

	err = o.dbP.Update(ord)
	if err != nil {
		log.Errorf("Failed to update order item after refund Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to store order. Charge Refunded")
		return
	}

	retOrder = ord.Item

	return
}

func (o *orders) Get(c context.Context, ids *msgs.UUIDs) (retItems *pb.Items, retErr error) {

	items := make([]store.Item, len(ids.Vals))

	err := utils.FanOutGet(
		c,
		o.dbP,
		5,
		ids.Vals,
		func(id string) store.Item {
			return &orderItem{&pb.Item{Id: id}}
		},
		items,
	)
	if err != nil {
		log.Errorf("FanOutGetHelper failed Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed listing items")
		return
	}

	retItems = new(pb.Items)
	retItems.Items = make([]*pb.Item, len(items))
	for i, v := range items {
		retItems.Items[i] = v.(*orderItem).Item
	}
	return
}

func (o *orders) List(c context.Context, req *msgs.ListReq) (retItems *pb.Items, retErr error) {

	listOpt := store.ListOpt{
		Page:  req.Page,
		Limit: req.Limit,
	}

	items, err := o.dbP.List(&orderItem{}, listOpt)
	if err != nil {
		log.Errorf("Failed listing orders items Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to list orders items.")
		return
	}

	retItems = new(pb.Items)
	retItems.Items = make([]*pb.Item, len(items))
	for i := 0; i < len(items); i++ {
		retItems.Items[i] = items[i].(*orderItem).Item
	}
	return
}
