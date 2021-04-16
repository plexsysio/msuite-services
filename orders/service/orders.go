package rpc_service

import (
	"errors"
	logger "github.com/ipfs/go-log"
	"gitlab.com/go-msuite/app-errors"
	helper "gitlab.com/go-msuite/common/go-common"
	msgs "gitlab.com/go-msuite/common/pb"
	"gitlab.com/go-msuite/configurator/config_service/grpc_server"
	"gitlab.com/go-msuite/locker"
	Payments "gitlab.com/go-msuite/payments/pb"
	"gitlab.com/go-msuite/store"
	storeItem "gitlab.com/go-msuite/store/item"
	Inventory "gitlab.com/trainer/inventory/pb"
	Orders "gitlab.com/trainer/orders/pb"
	"golang.org/x/net/context"
	"sync/atomic"
	"time"
)

var log = logger.Logger("orders")

var (
	req_id   int64         = 1
	orderTTL time.Duration = time.Minute * 5
)

func getNextId() int64 {
	return atomic.AddInt64(&req_id, 1)
}

type orderItem struct {
	*Orders.Item
}

func (l *orderItem) GetNamespace() string { return "orders" }

func (l *orderItem) SetId(i string) { l.Id = i }

func (l *orderItem) SetCreated(i int64) { l.Created = i }

func (l *orderItem) SetUpdated(i int64) { l.Updated = i }

type inventoryItem struct {
	*Inventory.Item
}

func (l *inventoryItem) GetNamespace() string { return "inventory" }

func (l *inventoryItem) SetUpdated(i int64) { l.Updated = i }

type lockedOrderItem struct {
	Item   *Inventory.Item
	Unlock func() error
	Update func() error
}

type updateFn func() error
type unlockFn func() error

type orders struct {
	baseSrv grpc_server.BaseGrpcService
	dbP     store.Store
	lckr    locker.Locker
}

var InitFn grpc_server.RPCInitFn = Init

var DB = "redis"
var LOCKER = "zookeeper"

func Init(base grpc_server.BaseGrpcService) error {

	if base.GetDb(DB) == nil || base.GetLocker(LOCKER) == nil {
		return errors.New("Incomplete config for orders service")
	}
	Orders.RegisterOrdersServer(base.GetRPCServer(), &orders{
		baseSrv: base,
		dbP:     base.GetDb(DB),
		lckr:    base.GetLocker(LOCKER),
	})
	return nil
}

func isPayable(order *Orders.Item) error {
	if order.Status != Orders.Item_CREATED {
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

func isReturnable(order *Orders.Item) error {
	if order.Status != Orders.Item_PAID && order.Status != Orders.Item_COMPLETED &&
		order.Status != Orders.Item_CANCELLED {
		return errors.New("Incorrect order state")
	}
	return nil
}

func (o *orders) updateOrder(order *Orders.Item, item *Orders.NewOrderReq) error {

	orderItems := make([]*Orders.OrderItem, 0)

	conn, done, err := o.baseSrv.GetClientConn("inventory")
	if err != nil {
		return err
	}
	defer done()

	invSvc := Inventory.NewInventoryClient(conn)

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
	orderItems = append(orderItems, &Orders.OrderItem{
		Type: Orders.OrderItem_INVENTORY, Amount: prodCost, ParentId: item.ItemId})

	var metaCost, discountCost, taxCost int64
	for _, v := range item.Items {
		if v.Type == Orders.OrderItem_INSURANCE {
			metaCost += 1
		}
		// Going ahead we need to check if discount is applicable
		if v.Type == Orders.OrderItem_DISCOUNT {
			discountCost += -1
		}
		if v.Type == Orders.OrderItem_TAX {
			taxCost += 1
		}
	}
	order.Items = orderItems
	order.Amount = prodCost + metaCost + taxCost - discountCost
	return nil
}

func (o *orders) getLockedOrderItem(ord *Orders.Item) (*lockedOrderItem, error) {

	var invItem *inventoryItem
	for _, v := range ord.Items {
		if v.Type == Orders.OrderItem_INVENTORY {
			invItem = &inventoryItem{
				Item: &Inventory.Item{
					Id: v.ParentId,
				},
			}
		}
	}

	if invItem == nil {
		log.Errorf("Order doesnt contain any inventory item")
		return nil, errors.New("Inventory item not found")
	}

	unlock, err := o.lckr.TryLock(invItem, locker.DefaultTimeout)
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

func (o *orders) NewOrder(c context.Context, newOrder *Orders.NewOrderReq) (retOrder *Orders.Item, retErr error) {

	ord := &orderItem{
		&Orders.Item{
			Amount:   0,
			Currency: newOrder.Rate.Currency,
			Status:   Orders.Item_CREATED,
			Email:    newOrder.Email,
			UserId:   newOrder.UserId,
		},
	}

	err := o.updateOrder(ord.Item, newOrder)
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

func (o *orders) PayOrder(c context.Context, payOrder *Orders.PayOrderReq) (retOrder *Orders.Item, retErr error) {

	ord := &orderItem{&Orders.Item{Id: payOrder.OrderId}}

	unlock, err := o.lckr.TryLock(ord, locker.DefaultTimeout)
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

	item, err := o.getLockedOrderItem(ord.Item)
	if err != nil {
		log.Errorf("Failed to lock order item Err:%s", err)
		retErr = app_errors.ErrInternal("Failed to lock order item")
		return
	}
	defer item.Unlock()

	paymentsConn, done, err := o.baseSrv.GetClientConn("payments")
	if err != nil {
		log.Errorf("Failed to get connection to payment service Err: %s", err.Error())
		retErr = app_errors.ErrInternal("Failed getting connection.")
		return
	}
	defer done()
	paymentsSvc := Payments.NewPaymentsClient(paymentsConn)

	if len(payOrder.Charges) > 1 {
		log.Errorf("Multiple pay split not implemented")
		retErr = app_errors.ErrUnimplemented("Multiple pay split not allowed.")
		return
	}

	req := &Payments.ChargeReq{
		Provider:  payOrder.Charges[0].Provider,
		Amount:    ord.Amount,
		Currency:  ord.Currency,
		Email:     ord.Email,
		Statement: "Order ID " + ord.Id,
	}
	switch {
	case len(payOrder.Charges[0].GetUserId()) > 0:
		req.Source = &Payments.ChargeReq_UserId{
			UserId: payOrder.Charges[0].GetUserId(),
		}
	case payOrder.Charges[0].GetCard() != nil:
		req.Source = &Payments.ChargeReq_Card{
			Card: payOrder.Charges[0].GetCard(),
		}
	case len(payOrder.Charges[0].GetPaymentRef()) > 0:
		req.Source = &Payments.ChargeReq_VoucherId{
			VoucherId: payOrder.Charges[0].GetPaymentRef(),
		}
	}

	charge, err := paymentsSvc.NewCharge(context.Background(), req)
	if err != nil {
		log.Errorf("Failed creating new charge Err:%s", err.Error())
		retErr = err
		return
	}

	ord.PaymentId = charge.ChargeId
	ord.Status = Orders.Item_PAID

	// This should be done with retry
	err = o.dbP.Update(ord)
	if err != nil {
		r, e := paymentsSvc.RefundCharge(context.Background(), &Payments.RefundReq{
			Type:     Payments.Refund_PROVIDER_FAILURE,
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

func (o *orders) ReturnOrder(c context.Context, orderId *msgs.UUID) (retOrder *Orders.Item, retErr error) {

	ord := &orderItem{&Orders.Item{Id: orderId.Val}}

	unlock, err := o.lckr.TryLock(ord, locker.DefaultTimeout)
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

	item, err := o.getLockedOrderItem(ord.Item)
	if err != nil {
		log.Errorf("Failed to lock inventory item Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to lock inventory item")
		return
	}
	defer item.Unlock()

	paymentsConn, done, err := o.baseSrv.GetClientConn("payments")
	if err != nil {
		log.Errorf("Failed to get connection to Payment svc Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed getting connection.")
		return
	}
	defer done()
	paymentsSvc := Payments.NewPaymentsClient(paymentsConn)

	r, err := paymentsSvc.RefundCharge(context.Background(), &Payments.RefundReq{
		Type:     Payments.Refund_USER_REQUESTED,
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

func (o *orders) Get(c context.Context, ids *msgs.UUIDs) (retItems *Orders.Items, retErr error) {

	items := make([]storeItem.Item, len(ids.Vals))

	err := helper.ParallelGetHelper(c, ids, func(id string) storeItem.Item {
		return &orderItem{&Orders.Item{Id: id}}
	}, items, o.lckr, o.dbP)
	if err != nil {
		log.Errorf("ParallelGetHelper failed Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed listing Orders items")
		return
	}

	retItems = new(Orders.Items)
	retItems.Items = make([]*Orders.Item, len(items))
	for i, v := range items {
		retItems.Items[i] = v.(*orderItem).Item
	}
	return
}

func (o *orders) List(c context.Context, req *msgs.ListReq) (retItems *Orders.Items, retErr error) {

	items := make([]storeItem.Item, req.Limit)
	for i := range items {
		items[i] = &orderItem{
			Item: new(Orders.Item),
		}
	}

	listOpt := storeItem.ListOpt{
		Page:  req.Page,
		Limit: req.Limit,
	}

	count, err := o.dbP.List(items, listOpt)
	if err != nil {
		log.Errorf("Failed listing orders items Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to list orders items.")
		return
	}

	retItems = new(Orders.Items)
	retItems.Items = make([]*Orders.Item, count)
	for i := 0; i < count; i++ {
		retItems.Items[i] = items[i].(*orderItem).Item
	}
	return
}
