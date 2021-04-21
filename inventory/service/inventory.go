package rpc_service

import (
	"github.com/SWRMLabs/ss-store"
	"github.com/plexsysio/dLocker"
	"github.com/plexsysio/go-msuite/lib"
	"github.com/plexsysio/msuite-services/app_errors"
	msgs "github.com/plexsysio/msuite-services/common/pb"
	"github.com/plexsysio/msuite-services/inventory/pb"
	"github.com/plexsysio/msuite-services/utils"
	proto "github.com/golang/protobuf/proto"
	logger "github.com/ipfs/go-log/v2"
	"golang.org/x/net/context"
	"time"
)

var log = logger.Logger("inventory")

type inventoryItem struct {
	*pb.Item
}

// GetId is generated by grpc
func (l *inventoryItem) GetNamespace() string { return "inventory" }

func (l *inventoryItem) SetCreated(i int64) { l.Created = i }

func (l *inventoryItem) SetUpdated(i int64) { l.Updated = i }

func (l *inventoryItem) Marshal() ([]byte, error) {
	return proto.Marshal(l.Item)
}

func (l *inventoryItem) Unmarshal(buf []byte) error {
	if l.Item == nil {
		l.Item = &pb.Item{}
	}
	return proto.Unmarshal(buf, l)
}

func (l *inventoryItem) LockString() string {
	return "/" + l.GetNamespace() + "/" + l.GetId()
}

func (l *inventoryItem) Factory() store.SerializedItem {
	return &inventoryItem{}
}

type inventory struct {
	pb.UnimplementedInventoryServer
	dbP  store.Store
	lckr dLocker.DLocker
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
	lkApi, err := svc.Locker()
	if err != nil {
		return err
	}
	pb.RegisterInventoryServer(grpcApi.Server(), &inventory{
		dbP:  ndApi.Storage(),
		lckr: lkApi,
	})
	log.Info("Inventory service registered")
	return nil
}

func (s *inventory) Get(c context.Context, ids *msgs.UUIDs) (retItems *pb.Items, retErr error) {

	items := make([]store.Item, len(ids.Vals))

	err := utils.FanOutGet(
		c,
		s.dbP,
		5,
		ids.Vals,
		func(id string) store.Item {
			return &inventoryItem{&pb.Item{Id: id}}
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
		retItems.Items[i] = v.(*inventoryItem).Item
	}
	return
}

func (s *inventory) Update(c context.Context, item *pb.UpdateReq) (retItem *pb.Item, retErr error) {

	inv := &inventoryItem{
		Item: item.Item,
	}

	unlock, err := s.lckr.TryLock(c, inv.LockString(), time.Second*5)
	if err != nil {
		log.Errorf("Failed getting lock Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to get inventory lock.")
		return
	}
	defer unlock()

	switch {
	case item.Map == int32(pb.UpdateReq_New):
		retErr = s.dbP.Create(inv)
	case item.Map == int32(pb.UpdateReq_Full):
		retErr = s.dbP.Update(inv)
	default:
		existing := &inventoryItem{
			Item: &pb.Item{
				Id: inv.Item.Id,
			},
		}
		retErr = s.dbP.Read(existing)
		if retErr != nil {
			log.Errorf("Failed reading existing entry for update Err:%s", err.Error())
			retErr = app_errors.ErrInternal("Failed reading item")
			return
		}
		switch {
		case item.Map&int32(pb.UpdateReq_Count) > 0:
			existing.Count = item.Item.Count
			fallthrough
		case item.Map&int32(pb.UpdateReq_Rate) > 0:
			existing.Rates = item.Item.Rates
			fallthrough
		case item.Map&int32(pb.UpdateReq_Active) > 0:
			existing.Active = item.Item.Active
			fallthrough
		case item.Map&int32(pb.UpdateReq_Metadata) > 0:
			existing.Metadata = item.Item.Metadata
		}
		inv = existing
		retErr = s.dbP.Update(existing)
	}

	if retErr != nil {
		log.Errorf("Failed updating inventory item Err:%s", retErr.Error())
		retErr = app_errors.ErrInternal("Failed to update inventory item.")
		return
	}
	retItem = inv.Item
	return
}

func (s *inventory) List(c context.Context, req *msgs.ListReq) (retItems *pb.Items, retErr error) {

	listOpt := store.ListOpt{
		Page:  req.Page,
		Limit: req.Limit,
	}

	items, err := s.dbP.List(&inventoryItem{}, listOpt)
	if err != nil {
		log.Errorf("Failed listing inventory items Err:%s", err.Error())
		retErr = app_errors.ErrInternal("Failed to list inventory items.")
		return
	}

	retItems = new(pb.Items)
	retItems.Items = make([]*pb.Item, len(items))
	for i := 0; i < len(items); i++ {
		retItems.Items[i] = items[i].(*inventoryItem).Item
	}
	return
}
