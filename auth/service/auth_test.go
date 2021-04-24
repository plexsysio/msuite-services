package service_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/go-msuite/lib"
	"github.com/plexsysio/go-msuite/modules/events"
	"github.com/plexsysio/msuite-services/auth/pb"
	auth "github.com/plexsysio/msuite-services/auth/service"
	"google.golang.org/grpc"
)

type userRegisterEvent struct {
	*pb.UnverifiedUser
}

func (u *userRegisterEvent) Topic() string {
	return "NewUserRegistration"
}

func (u *userRegisterEvent) Marshal() ([]byte, error) {
	return proto.Marshal(u.UnverifiedUser)
}

func (u *userRegisterEvent) Unmarshal(buf []byte) error {
	if u.UnverifiedUser == nil {
		u.UnverifiedUser = &pb.UnverifiedUser{}
	}
	return proto.Unmarshal(buf, u.UnverifiedUser)
}

type userCreatedEvent struct {
	*pb.VerifiedUser
}

func (u *userCreatedEvent) Topic() string {
	return "NewUserCreated"
}

func (u *userCreatedEvent) Marshal() ([]byte, error) {
	return proto.Marshal(u.VerifiedUser)
}

func (u *userCreatedEvent) Unmarshal(buf []byte) error {
	if u.VerifiedUser == nil {
		u.VerifiedUser = &pb.VerifiedUser{}
	}
	return proto.Unmarshal(buf, u.VerifiedUser)
}

func TestAuthFlow(t *testing.T) {
	defer os.RemoveAll("tmp")

	logger.SetLogLevel("*", "Error")

	svc, err := msuite.New(
		msuite.WithRepositoryRoot("tmp"),
		msuite.WithServiceName("Auth"),
		msuite.WithJWT("dummysecret"),
		msuite.WithGRPCTCPListener(10000),
		msuite.WithP2PPort(10001),
		msuite.WithLocker("inmem", nil),
		msuite.WithServiceACL(map[string]string{
			"dummyresource": "admin",
		}),
	)
	err = auth.New(svc)
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

	authClient := pb.NewAuthClient(conn)

	evApi, err := svc.Events()
	if err != nil {
		t.Fatal(err)
	}

	eventChan := make(chan events.Event)

	evApi.RegisterHandler(func() events.Event {
		return &userRegisterEvent{}
	}, func(e events.Event) {
		eventChan <- e
	})

	evApi.RegisterHandler(func() events.Event {
		return &userCreatedEvent{}
	}, func(e events.Event) {
		eventChan <- e
	})

	evApi.RegisterHandler(func() events.Event {
		return &auth.ForgotPasswordRequest{}
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

	var newUser *userRegisterEvent

	select {
	case <-time.After(time.Second):
	case e := <-eventChan:
		n, ok := e.(*userRegisterEvent)
		if !ok {
			t.Fatal("got incorrent event")
		}
		newUser = n
	}

	if newUser == nil {
		t.Fatal("did not get new user notification")
	}

	t.Run("verify user", func(t *testing.T) {
		resp, err := authClient.Verify(reqCtx, &pb.VerifyReq{
			Code:  newUser.UnverifiedUser.Code,
			Creds: usr,
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Verified new user %v", resp)
	})

	var createdUser *userCreatedEvent

	select {
	case <-time.After(time.Second):
	case e := <-eventChan:
		n, ok := e.(*userCreatedEvent)
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

	var forgotReq *auth.ForgotPasswordRequest

	select {
	case <-time.After(time.Second):
	case e := <-eventChan:
		n, ok := e.(*auth.ForgotPasswordRequest)
		if !ok {
			t.Fatal("got incorrent event")
		}
		forgotReq = n
	}

	if forgotReq == nil {
		t.Fatal("did not get forgot password notification")
	}

	t.Logf("Forgot password request %v", createdUser)

	t.Run("authenticate user with temp password", func(t *testing.T) {
		resp, err := authClient.Authenticate(reqCtx, &pb.AuthCredentials{
			Type:     pb.LoginType(pb.LoginType_value[forgotReq.UsernameType]),
			Username: forgotReq.Username,
			Password: forgotReq.TempPassword,
		})
		if err != nil {
			t.Fatal(err)
		}

		authResult = resp
		t.Logf("Authenticated user %v", resp)
	})

	t.Run("report unauthorized password change", func(t *testing.T) {
		resp, err := authClient.ReportUnauthorizedPwdChange(reqCtx, &pb.AuthCredentials{
			Type:     pb.LoginType(pb.LoginType_value[forgotReq.UsernameType]),
			Username: forgotReq.Username,
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