package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/hgfischer/go-otp"
	logger "github.com/ipfs/go-log/v2"
	"github.com/plexsysio/dLocker"
	"github.com/plexsysio/gkvstore"
	"github.com/plexsysio/go-msuite/core"
	"github.com/plexsysio/go-msuite/modules/auth"
	"github.com/plexsysio/go-msuite/modules/events"
	"github.com/plexsysio/msuite-services/app_errors"
	"github.com/plexsysio/msuite-services/auth/openapiv2"
	"github.com/plexsysio/msuite-services/auth/pb"
	npb "github.com/plexsysio/msuite-services/notifications/pb"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

var (
	log           = logger.Logger("auth")
	OTP_LEN uint8 = 6
	otpGen        = &otp.TOTP{Length: OTP_LEN}
)

var (
	BaseUrl    = "http://localhost:10000"
	OrgName    = "PlexsysIO"
	OrgContact = "plexsys@email.com"
)

const DefaultTimeout time.Duration = time.Second * 10

type unverifiedUser struct {
	*pb.UnverifiedUser
}

func (u *unverifiedUser) GetNamespace() string {
	return "auth/UnverifiedUser"
}

func (u *unverifiedUser) GetID() string {
	return u.GetType().String() + "/" + u.GetUsername()
}

func (u *unverifiedUser) LockString() string {
	return u.GetNamespace() + "/" + u.GetID()
}

func (u *unverifiedUser) SetCreated(i int64) { u.Created = i }

func (u *unverifiedUser) SetUpdated(i int64) { u.Updated = i }

func (u *unverifiedUser) Marshal() ([]byte, error) {
	return proto.Marshal(u.UnverifiedUser)
}

func (u *unverifiedUser) Unmarshal(buf []byte) error {
	if u.UnverifiedUser == nil {
		u.UnverifiedUser = &pb.UnverifiedUser{}
	}
	return proto.Unmarshal(buf, u.UnverifiedUser)
}

type verifiedUser struct {
	*pb.VerifiedUser
}

func (u *verifiedUser) GetNamespace() string {
	return "auth/VerifiedUser"
}

func (u *verifiedUser) GetID() string {
	return u.GetType().String() + "/" + u.GetUsername()
}

func (u *verifiedUser) LockString() string {
	return u.GetNamespace() + "/" + u.GetID()
}

func (u *verifiedUser) ID() string {
	return u.GetID()
}

func (u *verifiedUser) Role() string {
	return u.GetRole()
}

func (u *verifiedUser) Mtdt() map[string]interface{} {
	return map[string]interface{}{
		"UserID": u.GetUserId(),
	}
}

func (u *verifiedUser) SetCreated(i int64) { u.Created = i }

func (u *verifiedUser) SetUpdated(i int64) { u.Updated = i }

func (u *verifiedUser) Marshal() ([]byte, error) {
	return proto.Marshal(u.VerifiedUser)
}

func (u *verifiedUser) Unmarshal(buf []byte) error {
	if u.VerifiedUser == nil {
		u.VerifiedUser = &pb.VerifiedUser{}
	}
	return proto.Unmarshal(buf, u.VerifiedUser)
}

type NewUserEvent struct {
	UserId   string
	Username string
	Type     pb.LoginType
}

func (NewUserEvent) Topic() string {
	return "NewUserRegistration"
}

func (n *NewUserEvent) Marshal() ([]byte, error) {
	return json.Marshal(n)
}

func (n *NewUserEvent) Unmarshal(buf []byte) error {
	return json.Unmarshal(buf, n)
}

type authServer struct {
	pb.UnimplementedAuthServer

	dbP    gkvstore.Store
	lckr   dLocker.DLocker
	ev     events.Events
	jm     auth.JWTManager
	client func(context.Context, string, ...grpc.DialOption) (*grpc.ClientConn, error)
}

func New(svc core.Service) error {
	authApi, err := svc.Auth()
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

	lkApi, err := svc.Locker()
	if err != nil {
		return err
	}

	store, err := svc.SharedStorage("auth", nil)
	if err != nil {
		return err
	}

	httpApi, err := svc.HTTP()
	if err != nil {
		return err
	}

	pb.RegisterAuthServer(grpcApi.Server(), &authServer{
		dbP:    store,
		lckr:   lkApi,
		ev:     evApi,
		jm:     authApi.JWT(),
		client: grpcApi.Client,
	})
	log.Info("Auth service registered")

	// Start the service to start the listeners
	err = svc.Start(context.Background())
	if err != nil {
		return err
	}

	conn, err := grpcApi.Client(context.Background(), "auth", grpc.WithInsecure())
	if err != nil {
		return err
	}

	err = pb.RegisterAuthHandler(context.Background(), httpApi.Gateway(), conn)
	if err != nil {
		return err
	}

	subFS, err := fs.Sub(openapiv2.OpenAPI, "OpenAPI")
	if err != nil {
		return err
	}

	httpApi.Mux().Handle("/auth/openapiv2/", http.StripPrefix("/auth/openapiv2", http.FileServer(http.FS(subFS))))

	return nil
}

/*
 * First step in User Registration. The client will start user registration process
 * using this API call. We will send the confirmation information on the supplied
 * email/passcode on mobile. We will create an unverified user entry with the
 * credentials and the code that we have sent. Once the user gets the confirmation,
 * he will use verify to complete the verification. During verification he will use
 * this passcode that we generate to complete the registration.
 */
func (s *authServer) Register(c context.Context, creds *pb.AuthCredentials) (*pb.AuthResponse, error) {

	usrObj := &unverifiedUser{
		UnverifiedUser: &pb.UnverifiedUser{
			Type:     creds.Type,
			Username: creds.Username,
		},
	}

	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		log.Errorf("failed to get lock on user %s. SecErr:%v", usrObj.GetID(), err)
		return nil, app_errors.ErrInternal("failed to get lock %v", err)
	}
	defer unlock()

	alreadyStarted := false

	err = s.dbP.Read(c, usrObj)
	if err == nil && usrObj.Verified {
		log.Errorf("username %s already exists.", usrObj.GetID())
		return nil, app_errors.ErrPermissionDenied("username already exists, please login")
	} else if err == nil {
		alreadyStarted = true
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed to generate password hash. SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed to generate hash")
	}

	// Random string. Will be a 20 char string in case of email and 6 digit OTP in case of mobile.
	var randStr string
	switch creds.Type {
	case pb.LoginType_Email:
		randStr = RandStringBytes(20)
	case pb.LoginType_Mobile:
		randStr = otpGen.Get()
	case pb.LoginType_OAuthProvider:
		fallthrough
	default:
		return nil, app_errors.ErrUnimplemented("unsupported registration type")
	}
	usrObj.Code = randStr
	usrObj.Password = hashedPass

	if alreadyStarted {
		// If the user previously started registration process but did not complete,
		// allow him to update password and retry
		err = s.dbP.Update(c, usrObj)
	} else {
		err = s.dbP.Create(c, usrObj)
	}
	if err != nil {
		log.Errorf("failed to update user SecErr:%s", err.Error())
		return nil, app_errors.ErrInternal("failed creating user entry %v", err)
	}

	err = s.sendRegistrationNotification(c, usrObj)
	if err != nil {
		log.Warnf("failed sending registration notification %s", usrObj.GetUsername())
	}

	return &pb.AuthResponse{}, nil
}

// Used to complete verification.
func (s *authServer) Verify(c context.Context, verify *pb.VerifyReq) (*pb.AuthResponse, error) {

	usrObj := &unverifiedUser{
		UnverifiedUser: &pb.UnverifiedUser{
			Type:     verify.Creds.Type,
			Username: verify.Creds.Username,
		},
	}

	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		log.Errorf("failed to get lock on user %s. SecErr:%v", usrObj.GetID(), err)
		return nil, app_errors.ErrInternal("failed to lock %v", err)
	}
	defer unlock()

	err = s.dbP.Read(c, usrObj)
	if err != nil {
		log.Errorf("failed to find user SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed to find user %v", err)
	}

	if usrObj.Verified {
		log.Errorf("duplicate verification req: %v", verify)
		return nil, app_errors.ErrPermissionDenied("already verified user")
	}

	if usrObj.Code != verify.Code {
		log.Errorf("invalid verify request %v", verify)
		return nil, app_errors.ErrPermissionDenied("invalid verification code")
	}

	verifiedUsr := &verifiedUser{
		&pb.VerifiedUser{
			UserId:   usrObj.Type.String() + "/" + usrObj.Username,
			Role:     "authenticated_write",
			Username: usrObj.Username,
			Type:     usrObj.Type,
			Password: usrObj.Password,
		},
	}

	// Step 1: Update user as verified
	usrObj.Verified = true
	err = s.dbP.Update(c, usrObj)
	if err != nil {
		log.Errorf("failed to update unverified user SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed to update user %v", err)
	}

	// Step 2: Create verified user entry
	err = s.dbP.Create(c, verifiedUsr)
	if err != nil {
		log.Errorf("failed to create verified user SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed creating user entry %v", err)
	}

	// Step 3: Broadcast new user creation event
	newUserEv := &NewUserEvent{
		UserId:   verifiedUsr.GetID(),
		Username: verifiedUsr.GetUsername(),
		Type:     verifiedUsr.GetType(),
	}
	err = s.ev.Broadcast(c, newUserEv)
	if err != nil {
		log.Warnf("failed broadcasting new user event %v", newUserEv)
	}

	// Set redirect URL. This handling is part of go-msuite lib
	grpc.SendHeader(c, metadata.Pairs("Location", BaseUrl))

	return &pb.AuthResponse{}, nil
}

func (s *authServer) createTokens(usr *verifiedUser) (string, string, error) {
	acTok, err := s.jm.Generate(usr, time.Hour*24)
	if err != nil {
		return "", "", err
	}
	rfshTok, err := s.jm.Generate(usr, time.Hour*24*30)
	if err != nil {
		return "", "", err
	}
	log.Debugf("Generated New tokens: %s %s", acTok, rfshTok)
	return acTok, rfshTok, nil
}

func (s *authServer) Authenticate(c context.Context, creds *pb.AuthCredentials) (*pb.AuthResult, error) {

	usrObj := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}

	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		log.Errorf("failed to lock user %s. SecErr:%v", usrObj.GetID(), err)
		return nil, app_errors.ErrInternal("failed to lock user")
	}
	defer unlock()

	err = s.dbP.Read(c, usrObj)
	if err != nil {
		log.Errorf("username %s does not exist. SecErr:%v", usrObj.GetID(), err)
		return nil, app_errors.ErrInternal("username does not exist, please register first")
	}

	if usrObj.UseTempPwd {
		if err = bcrypt.CompareHashAndPassword(usrObj.TempPwd, []byte(creds.Password)); err != nil {
			log.Errorf("temporary password doesnt match. SecErr:%v", err)
			return nil, app_errors.ErrPermissionDenied("temporary password doesn't match")
		}
	} else {
		if err = bcrypt.CompareHashAndPassword(usrObj.Password, []byte(creds.Password)); err != nil {
			log.Errorf("password doesnt match. SecErr:%v", err)
			return nil, app_errors.ErrPermissionDenied("password doesn't match")
		}
	}

	accTok, refTok, err := s.createTokens(usrObj)
	if err != nil {
		log.Errorf("failed creating tokens. SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed generating tokens")
	}

	log.Debugf("User %s login successful", usrObj.UserId)

	return &pb.AuthResult{
		UserId:       usrObj.UserId,
		AccessToken:  accTok,
		RefreshToken: refTok,
	}, nil
}

func getUsernameTypeFromClaims(c *auth.UserClaims) (pb.LoginType, string, error) {
	splits := strings.Split(c.ID, "/")
	if len(splits) != 2 {
		log.Errorf("Invalid claims ID %v", c)
		return 0, "", errors.New("Invalid claims ID")
	}
	return pb.LoginType(pb.LoginType_value[splits[0]]), splits[1], nil
}

func (s *authServer) RefreshToken(c context.Context, currToken *pb.AuthResult) (*pb.AuthResult, error) {

	if len(currToken.RefreshToken) == 0 {
		log.Error("refresh token empty")
		return nil, app_errors.ErrInvalidArg("token not present")
	}

	claims, err := s.jm.Verify(currToken.RefreshToken)
	if err != nil {
		log.Errorf("token is invalid Err:%v", err)
		return nil, app_errors.ErrPermissionDenied("invalid token")
	}

	usrType, username, err := getUsernameTypeFromClaims(claims)
	if err != nil {
		log.Errorf("invalid claims ID Err: %v", err)
		return nil, app_errors.ErrPermissionDenied("invalid claims")
	}

	usrObj := &verifiedUser{
		&pb.VerifiedUser{
			Type:     usrType,
			Username: username,
			Role:     claims.Role,
		},
	}

	accTok, refTok, err := s.createTokens(usrObj)
	if err != nil {
		log.Errorf("failed creating tokens. SecErr:%s", err.Error())
		return nil, app_errors.ErrInternal("failed generating tokens %v", err)
	}

	log.Infof("Access token refresh successful for user %s", claims.ID)

	return &pb.AuthResult{
		UserId:       claims.ID,
		AccessToken:  accTok,
		RefreshToken: refTok,
	}, nil
}

func (s *authServer) ResetPassword(c context.Context, updCreds *pb.UpdateCredentials) (*pb.AuthResponse, error) {

	if len(updCreds.AccessToken) == 0 {
		log.Error("access token empty")
		return nil, app_errors.ErrInvalidArg("token not present")
	}

	// Parse returns error for expired tokens.
	claims, err := s.jm.Verify(updCreds.AccessToken)
	if err != nil {
		log.Errorf("cannot parse claims Err:%v", err)
		return nil, app_errors.ErrPermissionDenied("invalid token")
	}

	if updCreds.UserId != claims.ID {
		log.Errorf("user ID mismatch in token and req. TokenUID:%s ReqUID:%s", updCreds.UserId, claims.ID)
		return nil, app_errors.ErrPermissionDenied("invalid token claims")
	}

	usrType, username, err := getUsernameTypeFromClaims(claims)
	if err != nil {
		log.Errorf("invalid claims ID Err:%s", err.Error())
		return nil, app_errors.ErrPermissionDenied("invalid claims")
	}

	usr := &verifiedUser{
		&pb.VerifiedUser{
			Type:     usrType,
			Username: username,
		},
	}

	err = s.dbP.Read(c, usr)
	if err != nil {
		log.Errorf("user ID %s does not exist.", updCreds.UserId)
		return nil, app_errors.ErrInvalidArg("user ID does not found")
	}

	if usr.UseTempPwd {
		if err = bcrypt.CompareHashAndPassword(usr.TempPwd, []byte(updCreds.OldPassword)); err != nil {
			log.Errorf("temporary password doesnt match. SecErr:%v", err)
			return nil, app_errors.ErrPermissionDenied("temporary password doesn't match")
		}
	} else {
		if err = bcrypt.CompareHashAndPassword(usr.Password, []byte(updCreds.OldPassword)); err != nil {
			log.Errorf("password doesnt match. SecErr:%v", err)
			return nil, app_errors.ErrPermissionDenied("temporary password doesn't match")
		}
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(updCreds.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed to generate password hash. SecErr:%s", err.Error())
		return nil, app_errors.ErrInternal("failed to generate hash %v", err)
	}

	usr.Password = hashedPass
	usr.UseTempPwd = false

	err = s.dbP.Update(c, usr)
	if err != nil {
		log.Errorf("failed updating password in DB SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed to update entry %v", err)
	}

	log.Infof("Reset password for user %s", usr.UserId)

	return &pb.AuthResponse{}, nil
}

func (s *authServer) ForgotPassword(c context.Context, creds *pb.AuthCredentials) (*pb.AuthResponse, error) {

	usr := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}

	unlock, err := s.lckr.TryLock(c, usr.LockString(), DefaultTimeout)
	if err != nil {
		log.Errorf("failed to get lock on user %s. SecErr:%v", usr.GetID(), err)
		return nil, app_errors.ErrInternal("failed to lock user %v", err)
	}
	defer unlock()

	err = s.dbP.Read(c, usr)
	if err != nil {
		log.Errorf("username %s does not exists. SecErr:%v", usr.GetID(), err)
		return nil, app_errors.ErrInvalidArg("user does not exist %v", err)
	}

	tempPwd := RandStringBytes(10)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(tempPwd), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed to generate password hash. SecErr:%s", err.Error())
		return nil, app_errors.ErrInternal("failed to generate password")
	}

	usr.TempPwd = hashedPass
	usr.UseTempPwd = true

	err = s.dbP.Update(c, usr)
	if err != nil {
		log.Errorf("failed to update user. SecErr:%s", err.Error())
		return nil, app_errors.ErrInternal("failed to update user")
	}

	err = s.sendForgotPwdNotification(c, usr, tempPwd)
	if err != nil {
		log.Errorf("failed to send notification with temp password %v", err)
		return nil, app_errors.ErrInternal("failed to send notification")
	}

	return &pb.AuthResponse{}, nil
}

func (s *authServer) ReportUnauthorizedPwdChange(
	c context.Context,
	creds *pb.AuthCredentials,
) (*pb.AuthResponse, error) {

	usr := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}

	unlock, err := s.lckr.TryLock(c, usr.LockString(), DefaultTimeout)
	if err != nil {
		log.Errorf("failed to get lock on user %s. SecErr:%v", usr.GetID(), err)
		return nil, app_errors.ErrInternal("failed to lock user %v", err)
	}
	defer unlock()

	err = s.dbP.Read(c, usr)
	if err != nil {
		log.Errorf("username %s does not exist. SecErr:%v", usr.GetID(), err)
		return nil, app_errors.ErrInternal("username does not exist")
	}

	usr.UseTempPwd = false
	usr.TempPwd = []byte("")

	err = s.dbP.Update(c, usr)
	if err != nil {
		log.Errorf("failed removing temp password from DB SecErr:%v", err)
		return nil, app_errors.ErrInternal("failed to update user %v", err)
	}

	return &pb.AuthResponse{}, nil
}

// For generating random strings
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	rand.Seed(time.Now().Unix() + time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func (s *authServer) sendRegistrationNotification(ctx context.Context, usr *unverifiedUser) error {
	conn, err := s.client(ctx, "notifications", grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()

	var req *npb.SendReq

	switch usr.GetType() {
	case pb.LoginType_Email:
		req = &npb.SendReq{
			Type: npb.NotificationType_EMAIL,
			Data: &npb.Msg{
				From:  OrgContact,
				To:    usr.GetUsername(),
				Title: "Welcome!",
				Body: fmt.Sprintf(
					userRegistrationEmail,
					OrgName,
					BaseUrl,
					usr.GetCode(), usr.GetType(), usr.GetUsername(),
					OrgName,
				),
			},
		}
	case pb.LoginType_Mobile:
		req = &npb.SendReq{
			Type: npb.NotificationType_SMS,
			Data: &npb.Msg{
				From:  OrgName,
				To:    usr.GetUsername(),
				Title: "Welcome!",
				Body:  fmt.Sprintf(userRegistrationSMS, usr.GetCode()),
			},
		}
	default:
		return errors.New("unsupported login type")
	}

	resp, err := npb.NewNotificationsClient(conn).Send(ctx, req)
	if err != nil {
		return err
	}
	log.Debugf("sent registration msg to user %s notification %s", usr.GetUsername(), resp.GetId())
	return nil
}

func (s *authServer) sendForgotPwdNotification(ctx context.Context, usr *verifiedUser, tmpPwd string) error {
	conn, err := s.client(ctx, "notifications", grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()

	var req *npb.SendReq

	switch usr.GetType() {
	case pb.LoginType_Email:
		req = &npb.SendReq{
			Type: npb.NotificationType_EMAIL,
			Data: &npb.Msg{
				From:  OrgContact,
				To:    usr.GetUsername(),
				Title: "Account recovery",
				Body: fmt.Sprintf(
					forgotPwdEmail,
					usr.GetUsername(),
					tmpPwd,
					BaseUrl, usr.GetUsername(), usr.GetType(), tmpPwd,
					OrgName,
				),
			},
		}
	case pb.LoginType_Mobile:
		req = &npb.SendReq{
			Type: npb.NotificationType_SMS,
			Data: &npb.Msg{
				From:  OrgName,
				To:    usr.GetUsername(),
				Title: "Account Recovery",
				Body: fmt.Sprintf(
					forgotPwdSMS,
					tmpPwd,
					BaseUrl, usr.GetUsername(), usr.GetType(), tmpPwd,
				),
			},
		}
	default:
		return errors.New("unsupported login type")
	}

	resp, err := npb.NewNotificationsClient(conn).Send(ctx, req)
	if err != nil {
		return err
	}
	log.Debugf("sent temp password msg to user %s notification %s", usr.GetUsername(), resp.GetId())
	return nil
}

var userRegistrationEmail = `<style>
	.btn-link{
	  border:none;
	  outline:none;
	  background:none;
	  cursor:pointer;
	  color:#0000EE;
	  padding:0;
	  text-decoration:underline;
	  font-family:inherit;
	  font-size:inherit;
	}
	</style>
	<p>Hi!</p>
	<p>Thanks for registering with %s!</p>
	<p>As a final step in the registration, please click on the following link to verify
	your email address and you are all set!</p>
	<p><form action="http://%s/auth/v1/verify/%s?type=%s&username=%s" method="post">
	  <button type="submit" name="verify_btn" class="btn-link">Verify Email Address</button>
	</form></p>
	<p>Thanks,</p>
	<p>%s Team</p>`

var userRegistrationSMS = "Your OTP is %s. Please use it to complete the registration process."

var forgotPwdEmail = `<style>
	.btn-link{
	  border:none;
	  outline:none;
	  background:none;
	  cursor:pointer;
	  color:#0000EE;
	  padding:0;
	  text-decoration:underline;
	  font-family:inherit;
	  font-size:inherit;
	}
	</style>
	<p>Hi,</p>
	<p>Seems like you have forgotten your credentials. We have created a temporary
	password for you. Please login using the following credentials:</p>
	<p>Username: %s</p>
	<p>Temporary Password: %s</p>
	<p>If you did not request to reset the password, please click on the following link:</p>
	<p><form action="http://%s/auth/v1/report_pwd_change/%s?type=%s&password=%s" method="post">
	<button type="submit" name="verify_btn" class="btn-link">Report unauthorized password change</button>
	</form></p>
	<p>The temporary password will be valid for a period of 24 hours. It is recommended that
	you reset the password immediately after logging in. If you fail to change within 24 hours, you
	will need to re-submit the password change request. This is required for your account's safety!</p>
	<p>Thanks,</p>
	<p>%s Team</p>`

var forgotPwdSMS = `<style>
	.btn-link{
	border:none;
  	outline:none;
  	background:none;
  	cursor:pointer;
  	color:#0000EE;
  	padding:0;
  	text-decoration:underline;
  	font-family:inherit;
  	font-size:inherit;
	}
	</style>
	<p>Your OTP is %s. Please use it to reset your password.</p>
	<p><form action="http://%s/auth/v1/report_pwd_change/%s?type=%s&password=%s" method="post">
	<button type="submit" name="verify_btn" class="btn-link">Report unauthorized password change</button>
	</form></p>`
