package service_test

import (
	"context"
	"testing"

	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/go-msuite"
	"github.com/plexsysio/go-msuite/modules/events"
	commonpb "github.com/plexsysio/msuite-services/common/pb"
	"github.com/plexsysio/msuite-services/notifications/pb"
	notifications "github.com/plexsysio/msuite-services/notifications/service"
	"google.golang.org/grpc"
)

type testNotifProvider struct {
	out chan *pb.Notification
}

func newTestProvider() *testNotifProvider {
	return &testNotifProvider{
		out: make(chan *pb.Notification, 10),
	}
}

func (testNotifProvider) SupportedModes() []pb.NotificationType {
	return []pb.NotificationType{
		pb.NotificationType_EMAIL,
		pb.NotificationType_SMS,
		pb.NotificationType_ANDROID,
	}
}

func (t *testNotifProvider) Send(req *pb.SendReq) (*pb.Notification, error) {
	n := &pb.Notification{
		UserId: req.GetUserId(),
		Type:   req.GetType(),
		Data:   req.GetData(),
	}
	t.out <- n
	return n, nil
}

func (t *testNotifProvider) Outbox() <-chan *pb.Notification {
	return t.out
}

func TestNotificationsFlow(t *testing.T) {
	logger.SetLogLevel("*", "Error")

	testProvider := newTestProvider()

	svc, err := msuite.New(
		msuite.WithService("Notifications", notifications.NewCtorWithProvider(testProvider)),
		msuite.WithGRPC(),
		msuite.WithGRPCTCPListener(10000),
		msuite.WithP2PPort(10001),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Stop(context.Background())

	conn, err := grpc.Dial(":10000", grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reqCtx, _ := context.WithCancel(context.Background())

	notificationsClient := pb.NewNotificationsClient(conn)

	evApi, err := svc.Events()
	if err != nil {
		t.Fatal(err)
	}

	eventChan := make(chan events.Event)

	evApi.RegisterHandler(func() events.Event {
		return &notifications.UserNotification{}
	}, func(e events.Event) {
		eventChan <- e
	})

	usr := &pb.SubscribeReq{}

	t.Run("subscribe user with no subs returns error", func(t *testing.T) {
		_, err := notificationsClient.Subscribe(reqCtx, usr)
		if err == nil {
			t.Fatal("expected error on subscribe with no subs")
		}
	})

	usr.Subscriptions = []*pb.SubscriberInfo{
		{Mode: pb.NotificationType_EMAIL, Identifier: "user@email.com"},
		{Mode: pb.NotificationType_IOS, Identifier: "ios_ID"},
	}

	t.Run("subscribe user", func(t *testing.T) {
		resp, err := notificationsClient.Subscribe(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}
		usr.UserId = resp.Val
	})

	usr.Subscriptions = append(usr.Subscriptions, &pb.SubscriberInfo{
		Mode:       pb.NotificationType_SMS,
		Identifier: "1234567890",
	})

	t.Run("subscribe user add sub", func(t *testing.T) {
		resp, err := notificationsClient.Subscribe(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}
		usr.UserId = resp.Val
	})

	ids := &commonpb.UUIDs{}

	t.Run("send email", func(t *testing.T) {
		msg, err := notificationsClient.Send(reqCtx, &pb.SendReq{
			Type:   pb.NotificationType_EMAIL,
			UserId: usr.UserId,
			Data: &pb.Msg{
				Title: "dummy title",
				Body:  "dummy body",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if msg.UserId != usr.UserId || msg.Data.To != "user@email.com" {
			t.Fatal("invalid msg sent")
		}
		ids.Vals = append(ids.Vals, msg.Id)
	})

	t.Run("send sms", func(t *testing.T) {
		msg, err := notificationsClient.Send(reqCtx, &pb.SendReq{
			Type:   pb.NotificationType_SMS,
			UserId: usr.UserId,
			Data: &pb.Msg{
				Title: "dummy title",
				Body:  "dummy body",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if msg.UserId != usr.UserId || msg.Data.To != "1234567890" {
			t.Fatal("invalid msg sent")
		}
		ids.Vals = append(ids.Vals, msg.Id)
	})

	outCount := 0
	for range testProvider.Outbox() {
		outCount++
		if outCount == 2 {
			break
		}
	}

	t.Run("send on wrong subscription", func(t *testing.T) {
		_, err := notificationsClient.Send(reqCtx, &pb.SendReq{
			Type:   pb.NotificationType_ANDROID,
			UserId: usr.UserId,
			Data: &pb.Msg{
				Title: "dummy title",
				Body:  "dummy body",
			},
		})
		if err == nil {
			t.Fatal("expected error on non existent sub")
		}
	})

	t.Run("send on unsupported provider", func(t *testing.T) {
		_, err := notificationsClient.Send(reqCtx, &pb.SendReq{
			Type:   pb.NotificationType_IOS,
			UserId: usr.UserId,
			Data: &pb.Msg{
				Title: "dummy title",
				Body:  "dummy body",
			},
		})
		if err == nil {
			t.Fatal("expected error on unsupported provider")
		}
	})

	t.Run("get", func(t *testing.T) {
		items, err := notificationsClient.Get(reqCtx, ids)
		if err != nil {
			t.Fatal(err)
		}

		if len(items.Items) != 2 {
			t.Fatal("invalid count of messages")
		}

		for _, v := range items.Items {
			if v.Type != pb.NotificationType_EMAIL && v.Type != pb.NotificationType_SMS {
				t.Fatalf("invalid notification type found %v", v.String())
			}
			if v.Type == pb.NotificationType_EMAIL {
				if v.Data.To != "user@email.com" {
					t.Fatal("invalid msg")
				}
			}
			if v.Type == pb.NotificationType_SMS {
				if v.Data.To != "1234567890" {
					t.Fatal("invalid msg")
				}
			}
			if v.Data.Title != "dummy title" || v.Data.Body != "dummy body" {
				t.Fatal("invalid msg")
			}
		}
	})
}
