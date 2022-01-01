package service

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/gkvstore"
	"github.com/plexsysio/go-msuite/core"
	"github.com/plexsysio/go-msuite/modules/events"
	"github.com/plexsysio/msuite-services/app_errors"
	msgs "github.com/plexsysio/msuite-services/common/pb"
	"github.com/plexsysio/msuite-services/notifications/openapiv2"
	"github.com/plexsysio/msuite-services/notifications/pb"
	"github.com/plexsysio/msuite-services/notifications/providers"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

var log = logger.Logger("notifications")

type subscriber struct {
	*pb.SubscribeReq
}

func (l *subscriber) GetNamespace() string { return "notif/sub" }

func (l *subscriber) GetID() string { return l.UserId }

func (l *subscriber) SetID(id string) { l.UserId = id }

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

func (l *notifObj) GetID() string { return l.Id }

func (l *notifObj) SetID(i string) { l.Id = i }

func (l *notifObj) SetCreated(i int64) { l.Created = i }

func (l *notifObj) SetUpdated(i int64) { l.Updated = i }

func (l *notifObj) Marshal() ([]byte, error) {
	return proto.Marshal(l.Notification)
}

func (l *notifObj) Unmarshal(buf []byte) error {
	if l.Notification == nil {
		l.Notification = &pb.Notification{}
	}
	return proto.Unmarshal(buf, l.Notification)
}

type SendRequest struct {
	*pb.SendReq
}

func (s *SendRequest) Topic() string {
	return "SendRequest"
}

func (s *SendRequest) Marshal() ([]byte, error) {
	return proto.Marshal(s.SendReq)
}

func (s *SendRequest) Unmarshal(buf []byte) error {
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
	dbP   gkvstore.Store
	pvdrs []providers.Provider
	ev    events.Events
}

func New(svc core.Service) error {
	providerCfg := []map[string]interface{}{}
	if ok := svc.Repo().Config().Get("NotificationProviders", &providerCfg); !ok {
		log.Warn("No notification providers configured")
	}
	pvdrs := []providers.Provider{}
	var err error
	if len(providerCfg) > 0 {
		pvdrs, err = providers.NewProviders(providerCfg)
		if err != nil {
			return err
		}
	}

	return NewWithProviders(svc, pvdrs)
}

func NewWithProviders(svc core.Service, pvdrs []providers.Provider) error {
	evApi, err := svc.Events()
	if err != nil {
		return err
	}

	grpcApi, err := svc.GRPC()
	if err != nil {
		return err
	}

	store, err := svc.SharedStorage("notifications", nil)
	if err != nil {
		return err
	}

	httpApi, err := svc.HTTP()
	if err != nil {
		return err
	}

	nSvc := &notifications{
		dbP:   store,
		pvdrs: pvdrs,
		ev:    evApi,
	}

	pb.RegisterNotificationsServer(grpcApi.Server(), nSvc)

	// Start the service to start the listeners
	err = svc.Start(context.Background())
	if err != nil {
		return err
	}

	conn, err := grpcApi.Client(context.Background(), "notifications", grpc.WithInsecure())
	if err != nil {
		return err
	}

	err = pb.RegisterNotificationsHandler(context.Background(), httpApi.Gateway(), conn)
	if err != nil {
		return err
	}

	subFS, err := fs.Sub(openapiv2.OpenAPI, "OpenAPI")
	if err != nil {
		return err
	}

	httpApi.Mux().Handle("/notifications/openapiv2/", http.StripPrefix("/notifications/openapiv2", http.FileServer(http.FS(subFS))))

	evApi.RegisterHandler(func() events.Event {
		return &SendRequest{}
	}, nSvc.handleSendMessage)

	return nil
}

func NewRPCWithProviders(svc core.Service, pvdrs []providers.Provider) error {
	evApi, err := svc.Events()
	if err != nil {
		return err
	}

	grpcApi, err := svc.GRPC()
	if err != nil {
		return err
	}

	store, err := svc.SharedStorage("notifications", nil)
	if err != nil {
		return err
	}

	nSvc := &notifications{
		dbP:   store,
		pvdrs: pvdrs,
		ev:    evApi,
	}

	pb.RegisterNotificationsServer(grpcApi.Server(), nSvc)

	evApi.RegisterHandler(func() events.Event {
		return &SendRequest{}
	}, nSvc.handleSendMessage)

	return nil
}

func (s *notifications) Subscribe(c context.Context, req *pb.SubscribeReq) (*msgs.UUID, error) {

	if req.UserId == "" {
		err := s.dbP.Create(c, &subscriber{SubscribeReq: req})
		if err != nil {
			log.Errorf("failed to store User %v SecErr:%v", req, err)
			return nil, app_errors.ErrInternal("failed to store user %v", err)
		}

		log.Debugf("created new subscriber %v", req)
	} else {
		existingSub := &subscriber{SubscribeReq: &pb.SubscribeReq{UserId: req.UserId}}
		err := s.dbP.Read(c, existingSub)
		if err != nil {
			log.Errorf("failed to get user %v, Err: %v", req, err)
			return nil, app_errors.ErrInvalidArg("failed to find user %v", err)
		}

		for _, newSub := range req.Subscriptions {
			found := false
			for idx, oldSub := range existingSub.Subscriptions {
				if oldSub.Mode == newSub.Mode {
					existingSub.Subscriptions[idx].Identifier = newSub.Identifier
					found = true
					break
				}
			}
			if !found {
				existingSub.Subscriptions = append(existingSub.Subscriptions, newSub)
			}
		}

		err = s.dbP.Update(c, existingSub)
		if err != nil {
			log.Errorf("failed updating user subscriptions %v", err)
			return nil, app_errors.ErrInternal("failed to update user subs %v", err)
		}

		log.Debugf("updated existing subscriber %v", req)
	}

	return &msgs.UUID{Val: req.UserId}, nil
}

func (s *notifications) Send(c context.Context, req *pb.SendReq) (*pb.Notification, error) {

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
		log.Errorf("notification provider unsupported Req:%s", req.String())
		return nil, app_errors.ErrUnimplemented("unsupported notification provider")
	}

	if len(req.GetUserId()) > 0 {
		sub := &subscriber{SubscribeReq: &pb.SubscribeReq{UserId: req.GetUserId()}}

		err := s.dbP.Read(c, sub)
		if err != nil {
			log.Errorf("failed getting subscriber UUID:%s SecErr:%v", req.GetUserId(), err)
			return nil, app_errors.ErrInvalidArg("user does not exist")
		}

		for i := range sub.GetSubscriptions() {
			if req.Type == sub.GetSubscriptions()[i].GetMode() {
				req.GetData().To = sub.GetSubscriptions()[i].GetIdentifier()
			}
		}
	}

	var (
		resp *pb.Notification
		err  error
	)

	if len(req.GetData().To) > 0 {
		resp, err = selected.Send(req)
		if err != nil {
			log.Errorf("provider failure SecErr:%v", err)
			return nil, app_errors.ErrInternal("provider error %v", err)
		}
	} else if req.Type == pb.NotificationType_PULL && len(req.GetUserId()) > 0 {
		log.Warnf("unable to find any subscription for PULL. Saving message.")
		resp = &pb.Notification{
			UserId: req.GetUserId(),
			Type:   req.GetType(),
			Data:   req.GetData(),
		}
	} else {
		log.Errorf("failed getting receiver info :%s", req.String())
		return nil, app_errors.ErrInvalidArg("receiver not provided")
	}

	obj := &notifObj{Notification: resp}
	err = s.dbP.Create(c, obj)
	if err != nil {
		log.Errorf("failed storing notification %v SecErr:%v", resp, err)
		return nil, app_errors.ErrInternal("failed storing notification %v", err)
	}

	return resp, nil
}

func (s *notifications) Get(c context.Context, ids *msgs.UUIDs) (*pb.NotificationList, error) {

	// 5 parallel workers for Get
	sem := make(chan struct{}, 5)

	type res struct {
		n   *notifObj
		idx int
		err error
	}
	resChan := make(chan res)

	results := &pb.NotificationList{Items: make([]*pb.Notification, len(ids.Vals))}
	eg, ctx := errgroup.WithContext(c)

	// Collector
	eg.Go(func() error {
		count := 0
		for r := range resChan {
			if r.err != nil {
				return r.err
			}
			results.Items[r.idx] = r.n.Notification
			count++
			if count == len(ids.Vals) {
				break
			}
		}
		return nil
	})

LOOP:
	for i := range ids.Vals {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break LOOP
		}

		idx := i

		eg.Go(func() error {
			defer func() { <-sem }()

			it := &notifObj{&pb.Notification{Id: ids.Vals[idx]}}
			err := s.dbP.Read(c, it)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case resChan <- res{n: it, idx: idx, err: err}:
			}
			return nil
		})
	}

	err := eg.Wait()
	if err != nil {
		log.Errorf("failed getting notifications %v", err)
		return nil, err
	}

	return results, nil
}

func (n *notifications) handleSendMessage(ev events.Event) {
	msg, ok := ev.(*SendRequest)
	if !ok {
		log.Errorf("invalid notification object %v", ev)
		return
	}

	cCtx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	resp, err := n.Send(cCtx, msg.SendReq)
	if err != nil {
		log.Errorf("failed sending notification %v Err:%v", msg.SendReq, err)
		return
	}

	if len(msg.UserId) > 0 {
		err = n.ev.Broadcast(cCtx, &UserNotification{
			UserId:         msg.SendReq.UserId,
			NotificationId: resp.Id,
		})
		if err != nil {
			log.Errorf("failed publishing new user notification event Err:%v", err)
		}
	}
	return
}
