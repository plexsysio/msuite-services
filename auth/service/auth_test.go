package service_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/go-msuite"
	"github.com/plexsysio/go-msuite/modules/events"
	"github.com/plexsysio/msuite-services/auth/pb"
	auth "github.com/plexsysio/msuite-services/auth/service"
	npb "github.com/plexsysio/msuite-services/notifications/pb"
	"github.com/plexsysio/msuite-services/notifications/providers"
	notifications "github.com/plexsysio/msuite-services/notifications/service"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

type testNotifProvider struct {
	out chan *npb.Notification
}

func newTestProvider() *testNotifProvider {
	return &testNotifProvider{
		out: make(chan *npb.Notification, 10),
	}
}

func (testNotifProvider) SupportedModes() []npb.NotificationType {
	return []npb.NotificationType{
		npb.NotificationType_EMAIL,
		npb.NotificationType_SMS,
		npb.NotificationType_ANDROID,
	}
}

func (t *testNotifProvider) Send(req *npb.SendReq) (*npb.Notification, error) {
	n := &npb.Notification{
		UserId: req.GetUserId(),
		Type:   req.GetType(),
		Data:   req.GetData(),
	}
	t.out <- n
	return n, nil
}

func (t *testNotifProvider) Outbox() <-chan *npb.Notification {
	return t.out
}

func TestAuthFlow(t *testing.T) {
	logger.SetLogLevel("auth", "Error")

	svc, err := msuite.New(
		msuite.WithServices("auth", "notifications"),
		msuite.WithAuth("dummysecret"),
		msuite.WithGRPC("tcp", 10000),
		msuite.WithP2P(10001),
		msuite.WithGRPC("p2p", nil),
		msuite.WithHTTP(10002),
		msuite.WithLocker("inmem", nil),
		msuite.WithServiceACL(map[string]string{
			"dummyresource": "admin",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	testProvider := newTestProvider()

	err = notifications.NewRPCWithProviders(svc, []providers.Provider{testProvider})
	if err != nil {
		t.Fatal(err)
	}

	err = auth.New(svc)
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

	authClient := pb.NewAuthClient(conn)

	evApi, err := svc.Events()
	if err != nil {
		t.Fatal(err)
	}

	eventChan := make(chan events.Event)

	evApi.RegisterHandler(func() events.Event {
		return &auth.NewUserEvent{}
	}, func(e events.Event) {
		eventChan <- e
	})

	usr := &pb.AuthCredentials{
		Type:     pb.LoginType_Email,
		Username: "user@email.com",
		Password: "userpass",
	}

	t.Run("register user", func(t *testing.T) {
		resp, err := authClient.Register(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Created new user %v", resp)
	})

	var notification1 *npb.Notification

	select {
	case <-time.After(time.Second):
	case notification1 = <-testProvider.Outbox():
	}

	if notification1 == nil {
		t.Fatal("did not get new user notification")
	}

	ss := strings.Split(notification1.Data.Body, fmt.Sprintf("%s/auth/v1/verify/", auth.BaseUrl))
	if len(ss) != 2 {
		t.Fatal("incorrect notification", notification1.Data.Body)
	}
	code := ss[1][:20]

	t.Run("verify user", func(t *testing.T) {
		resp, err := authClient.Verify(reqCtx, &pb.VerifyReq{
			Code:  code,
			Creds: usr,
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Verified new user %v", resp)
	})

	var createdUser *auth.NewUserEvent

	select {
	case <-time.After(time.Second):
	case e := <-eventChan:
		n, ok := e.(*auth.NewUserEvent)
		if !ok {
			t.Fatal("got incorrent event")
		}
		createdUser = n
	}

	if createdUser == nil {
		t.Fatal("did not get new user created notification")
	}

	t.Logf("Created new user %v", createdUser)

	var authResult *pb.AuthResult

	t.Run("authenticate user", func(t *testing.T) {
		resp, err := authClient.Authenticate(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Authenticated user %v", resp)
	})

	t.Run("refresh tokens", func(t *testing.T) {
		resp, err := authClient.RefreshToken(reqCtx, authResult)
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Refreshed tokens %v", resp)
	})

	t.Run("reset password", func(t *testing.T) {
		resp, err := authClient.ResetPassword(reqCtx, &pb.UpdateCredentials{
			UserId:      createdUser.UserId,
			NewPassword: "userpass2",
			OldPassword: usr.Password,
			AccessToken: authResult.AccessToken,
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Reset password %v", resp)
	})

	t.Run("authenticate user with new password", func(t *testing.T) {
		usr.Password = "userpass2"
		resp, err := authClient.Authenticate(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Authenticated user %v", resp)
	})

	t.Run("forgot password", func(t *testing.T) {
		resp, err := authClient.ForgotPassword(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Forgot password %v", resp)
	})

	var notification2 *npb.Notification

	select {
	case <-time.After(time.Second):
	case notification2 = <-testProvider.Outbox():
	}

	if notification2 == nil {
		t.Fatal("did not get new user notification")
	}

	r2, _ := regexp.Compile("Temporary Password: *")
	lt2 := r2.FindStringIndex(notification2.Data.Body)
	tmpPwd := notification2.Data.Body[lt2[1] : lt2[1]+10]

	t.Run("authenticate user with temp password", func(t *testing.T) {
		resp, err := authClient.Authenticate(reqCtx, &pb.AuthCredentials{
			Type:     usr.Type,
			Username: usr.Username,
			Password: tmpPwd,
		})
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Authenticated user %v", resp)
	})

	t.Run("report unauthorized password change", func(t *testing.T) {
		resp, err := authClient.ReportUnauthorizedPwdChange(reqCtx, &pb.AuthCredentials{
			Type:     usr.Type,
			Username: usr.Username,
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Report unauthorized password change %v", resp)
	})

	t.Run("authenticate user with old password", func(t *testing.T) {
		resp, err := authClient.Authenticate(reqCtx, usr)
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Authenticated user %v", resp)
	})
}

func TestAuthFlowGateway(t *testing.T) {
	_ = logger.SetLogLevel("auth", "Debug")

	svc, err := msuite.New(
		msuite.WithServices("auth", "notifications"),
		msuite.WithAuth("dummysecret"),
		msuite.WithGRPC("tcp", 10000),
		msuite.WithP2P(10001),
		msuite.WithGRPC("p2p", nil),
		msuite.WithHTTP(10002),
		msuite.WithLocker("inmem", nil),
		msuite.WithServiceACL(map[string]string{
			"dummyresource": "admin",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	testProvider := newTestProvider()

	err = notifications.NewRPCWithProviders(svc, []providers.Provider{testProvider})
	if err != nil {
		t.Fatal(err)
	}

	err = auth.New(svc)
	if err != nil {
		t.Fatal(err)
	}

	defer svc.Stop(context.Background())

	evApi, err := svc.Events()
	if err != nil {
		t.Fatal(err)
	}

	eventChan := make(chan events.Event)

	evApi.RegisterHandler(func() events.Event {
		return &auth.NewUserEvent{}
	}, func(e events.Event) {
		eventChan <- e
	})

	usr := &pb.AuthCredentials{
		Type:     pb.LoginType_Email,
		Username: "user@email.com",
		Password: "userpass",
	}

	baseURL := "http://localhost:10002/auth/v1/"

	t.Run("register user", func(t *testing.T) {
		req, err := protojson.Marshal(usr)
		if err != nil {
			t.Fatal(err)
		}

		registerURL := baseURL + "register"

		resp, err := http.Post(registerURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code", resp)
		}

		t.Logf("Created new user %v", resp)
	})

	var notification1 *npb.Notification

	select {
	case <-time.After(time.Second):
	case notification1 = <-testProvider.Outbox():
	}

	if notification1 == nil {
		t.Fatal("did not get new user notification")
	}

	ss := strings.Split(notification1.Data.Body, fmt.Sprintf("%s/auth/v1/verify/", auth.BaseUrl))
	if len(ss) != 2 {
		t.Fatal("incorrect notification", notification1.Data.Body)
	}
	code := ss[1][:20]

	t.Run("verify user", func(t *testing.T) {
		verifyURL := fmt.Sprintf("%sverify/%s?creds.type=%s&creds.username=%s",
			baseURL, code, usr.Type, usr.Username)

		resp, err := http.Post(verifyURL, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		t.Logf("Verified new user %v", resp)
	})

	var createdUser *auth.NewUserEvent

	select {
	case <-time.After(time.Second):
	case e := <-eventChan:
		n, ok := e.(*auth.NewUserEvent)
		if !ok {
			t.Fatal("got incorrent event")
		}
		createdUser = n
	}

	if createdUser == nil {
		t.Fatal("did not get new user created notification")
	}

	t.Logf("Created new user %v", createdUser)

	authResult := &pb.AuthResult{}

	t.Run("authenticate user", func(t *testing.T) {
		req, err := protojson.Marshal(usr)
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "authenticate"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		err = protojson.Unmarshal(buf, authResult)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Authenticated user %v", authResult)
	})

	t.Run("refresh tokens", func(t *testing.T) {
		req, err := protojson.Marshal(authResult)
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "refresh_token"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		err = protojson.Unmarshal(buf, authResult)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Refreshed tokens %v", resp)
	})

	t.Run("reset password", func(t *testing.T) {
		req, err := protojson.Marshal(&pb.UpdateCredentials{
			UserId:      createdUser.UserId,
			NewPassword: "userpass2",
			OldPassword: usr.Password,
			AccessToken: authResult.AccessToken,
		})
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "reset_password"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		t.Logf("Reset password %v", resp)
	})

	t.Run("authenticate user with new password", func(t *testing.T) {
		usr.Password = "userpass2"
		req, err := protojson.Marshal(usr)
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "authenticate"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		err = protojson.Unmarshal(buf, authResult)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Authenticated user %v", authResult)
	})

	t.Run("forgot password", func(t *testing.T) {
		forgotURL := fmt.Sprintf("%sforgot_password/%s?type=%s",
			baseURL, usr.Username, usr.Type)

		resp, err := http.Post(forgotURL, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		t.Logf("Forgot password %v", resp)
	})

	var notification2 *npb.Notification

	select {
	case <-time.After(time.Second):
	case notification2 = <-testProvider.Outbox():
	}

	if notification2 == nil {
		t.Fatal("did not get new user notification")
	}

	ss2 := strings.Split(notification2.Data.Body, "Temporary Password: ")
	if len(ss) != 2 {
		t.Fatal("incorrect notification", notification2.Data.Body)
	}
	tmpPwd := ss2[1][:10]

	t.Run("authenticate user with temp password", func(t *testing.T) {
		req, err := protojson.Marshal(&pb.AuthCredentials{
			Type:     usr.Type,
			Username: usr.Username,
			Password: tmpPwd,
		})
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "authenticate"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		err = protojson.Unmarshal(buf, authResult)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Authenticated user %v", authResult)
	})

	t.Run("report unauthorized password change", func(t *testing.T) {
		reportURL := fmt.Sprintf("%sreport_pwd_change/%s?type=%s",
			baseURL, usr.Username, usr.Type)

		resp, err := http.Post(reportURL, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		t.Logf("Report unauthorized password change %v", resp)
	})

	t.Run("authenticate user with old password", func(t *testing.T) {
		req, err := protojson.Marshal(usr)
		if err != nil {
			t.Fatal(err)
		}

		authURL := baseURL + "authenticate"

		resp, err := http.Post(authURL, "application/json", bytes.NewBuffer(req))
		if err != nil {
			t.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatal("invalid response code")
		}

		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		err = protojson.Unmarshal(buf, authResult)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Authenticated user %v", authResult)
	})
}
