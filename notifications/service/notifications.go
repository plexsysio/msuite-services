package service

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/SWRMLabs/ss-store"
	"github.com/aloknerurkar/go-msuite/lib"
	"github.com/aloknerurkar/go-msuite/modules/events"
	"github.com/aloknerurkar/msuite-services/app_errors"
	msgs "github.com/aloknerurkar/msuite-services/common/pb"
	"github.com/aloknerurkar/msuite-services/notifications/pb"
	"github.com/aloknerurkar/msuite-services/notifications/providers"
	proto "github.com/golang/protobuf/proto"
	logger "github.com/ipfs/go-log/v2"
)

var log = logger.Logger("notifications")

type subscriber struct {
	*pb.SubscribeReq
}

func (l *subscriber) GetNamespace() string { return "notif/sub" }

func (l *subscriber) GetId() string { return l.UserId }

func (l *subscriber) Marshal() ([]byte, error) {
	return proto.Marshal(l.SubscribeReq)
}

func (l *subscriber) Unmarshal(buf []byte) error {
	if l.SubscribeReq == nil {
		l.SubscribeReq = &pb.SubscribeReq{}
	}
	return proto.Unmarshal(buf, l.SubscribeReq)
}

type notifObj struct {
	*pb.Notification
}

func (l *notifObj) GetNamespace() string { return "notif/obj" }

func (l *notifObj) SetId(i string) { l.Id = i }

func (l *notifObj) SetCreated(i int64) { l.Created = i }

func (l *notifObj) SetUpdated(i int64) { l.Updated = i }

type sendReq struct {
	*pb.SendReq
}

func (s *sendReq) Topic() string {
	return "SendNotification"
}

func (s *sendReq) Marshal() ([]byte, error) {
	return proto.Marshal(s.SendReq)
}

func (s *sendReq) Unmarshal(buf []byte) error {
	if s.SendReq == nil {
		s.SendReq = &pb.SendReq{}
	}
	return proto.Unmarshal(buf, s.SendReq)
}

type UserNotification struct {
	UserId         string
	NotificationId string
}

func (s *UserNotification) Topic() string {
	return "UserNotification"
}

func (s *UserNotification) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *UserNotification) Unmarshal(buf []byte) error {
	return json.Unmarshal(buf, s)
}

type notifications struct {
	pb.UnimplementedNotificationsServer
	dbP   store.Store
	pvdrs []providers.Provider
	ev    events.Events
}

func New(svc msuite.Service) error {
	ndApi, err := svc.Node()
	if err != nil {
		return err
	}
	evApi, err := svc.Events()
	if err != nil {
		return err
	}
	grpcApi, err := svc.GRPC()
	if err != nil {
		return err
	}
	providerCfg := []map[string]interface{}{}
	if ok := svc.Repo().Config().Get("NotificationProviders", &providerCfg); !ok {
		log.Warn("No notification providers configured")
	}
	pvdrs := []providers.Provider{}
	if len(providerCfg) > 0 {
		pvdrs, err = providers.NewProviders(providerCfg)
		if err != nil {
			return err
		}
	}
	nSvc := &notifications{
		dbP:   ndApi.Storage(),
		pvdrs: pvdrs,
		ev:    evApi,
	}
	pb.RegisterNotificationsServer(grpcApi.Server(), nSvc)
	evApi.RegisterHandler(func() events.Event {
		return &sendReq{}
	}, nSvc.handleSendMessage)
	return nil
}

func (s *notifications) Subscribe(
	c context.Context,
	req *pb.SubscribeReq,
) (resp *msgs.UUID, retErr error) {

	err := s.dbP.Create(&subscriber{SubscribeReq: req})
	if err != nil {
		retErr = app_errors.ErrInternal("Unable to store newly created subscriber")
		log.Errorf("Failed to get store User %v SecErr:%s", req, err.Error())
		return
	}
	resp = &msgs.UUID{Val: req.UserId}
	log.Info("Created new subscriber %v", req)
	return
}

func (s *notifications) Send(
	c context.Context,
	req *pb.SendReq,
) (resp *pb.Notification, retErr error) {

	supported := false
	var selected providers.Provider
	for _, pvdr := range s.pvdrs {
		for _, v := range pvdr.SupportedModes() {
			if (v & req.Type) > 0 {
				supported = true
				selected = pvdr
				break
			}
		}
		if supported {
			break
		}
	}
	if !supported && req.Type != pb.NotificationType_PULL {
		retErr = app_errors.ErrUnimplemented("Unsupported request")
		log.Errorf("Notification provider unsupported Req:%s", req.String())
		return
	}
	if len(req.GetUserId()) > 0 {
		sub := &subscriber{SubscribeReq: &pb.SubscribeReq{UserId: req.GetUserId()}}
		err := s.dbP.Read(sub)
		if err != nil {
			retErr = app_errors.ErrInvalidArg("User ID does not exist")
			log.Errorf("Failed getting subscriber UUID:%s SecErr:%s", req.GetUserId(),
				err.Error())
			return
		}
		for i := range sub.GetSubscriptions() {
			if req.Type == sub.GetSubscriptions()[i].GetMode() {
				req.GetData().To = sub.GetSubscriptions()[i].GetIdentifier()
			}
		}
	}
	if len(req.GetData().To) > 0 {
		resp, retErr = selected.Send(req)
		if retErr != nil {
			retErr = app_errors.ErrInternal("Failed sending notification")
			log.Errorf("Provider failure SecErr:%s", retErr.Error())
			return
		}
	} else if req.Type == pb.NotificationType_PULL && len(req.GetUserId()) > 0 {
		log.Warningf("Unable to find any subscription for PULL. Saving message.")
		resp = &pb.Notification{
			UserId: req.GetUserId(),
			Type:   req.GetType(),
			Data:   req.GetData(),
		}
	} else {
		retErr = app_errors.ErrInvalidArg("Receiver not provided")
		log.Errorf("Failed getting receiver info :%s", req.String())
		return
	}
	obj := &notifObj{Notification: resp}
	retErr = s.dbP.Create(obj)
	if retErr != nil {
		retErr = app_errors.ErrInternal("Failed storing notification")
		log.Errorf("Failed storing notification %v SecErr:%s", resp, retErr.Error())
	}
	return
}

func (s *notifications) Get(
	c context.Context,
	ids *msgs.UUIDs,
) (retItems *pb.NotificationList, retErr error) {

	ch := make(chan *notifObj)
	wg := sync.WaitGroup{}
	retItems = &pb.NotificationList{}
	retItems.Items = []*pb.Notification{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case it, ok := <-ch:
				if !ok {
					return
				}
				retItems.Items = append(retItems.Items, it.Notification)
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
				n := &notifObj{
					&pb.Notification{
						Id: v,
					},
				}
				err := s.dbP.Read(n)
				if err != nil {
					log.Errorf("Failed reading notification %s Err:%s", n.String(), err.Error())
				} else {
					ch <- n
				}
			}
		}()
	}
	wg.Wait()
	return
}

func (n *notifications) handleSendMessage(ev events.Event) {
	msg, ok := ev.(*sendReq)
	if !ok {
		log.Errorf("Invalid notification object %v", ev)
		return
	}
	cCtx, _ := context.WithTimeout(context.Background(), time.Second*15)
	resp, err := n.Send(cCtx, msg.SendReq)
	if err != nil {
		log.Errorf("Failed sending notification %v Err:%s", msg.SendReq, err.Error())
		return
	}
	if len(msg.UserId) > 0 {
		err = n.ev.Broadcast(cCtx, &UserNotification{
			UserId:         msg.SendReq.UserId,
			NotificationId: resp.Id,
		})
		if err != nil {
			log.Errorf("Failed publishing new user notification event")
		}
	}
	return
}
