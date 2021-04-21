package service

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/SWRMLabs/ss-store"
	"github.com/plexsysio/dLocker"
	"github.com/plexsysio/go-msuite/lib"
	"github.com/plexsysio/go-msuite/modules/auth"
	"github.com/plexsysio/go-msuite/modules/events"
	"github.com/plexsysio/msuite-services/app_errors"
	"github.com/plexsysio/msuite-services/auth/pb"
	"github.com/plexsysio/msuite-services/utils"
	"github.com/golang/protobuf/proto"
	"github.com/hgfischer/go-otp"
	logger "github.com/ipfs/go-log/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

var log = logger.Logger("auth")

const DefaultTimeout time.Duration = time.Second * 10

type unverifiedUser struct {
	*pb.UnverifiedUser
}

func (u *unverifiedUser) GetNamespace() string {
	return "auth/UnverifiedUser"
}

func (u *unverifiedUser) GetId() string {
	return u.GetType().String() + "/" + u.GetUsername()
}

func (u *unverifiedUser) LockString() string {
	return u.GetNamespace() + "/" + u.GetId()
}

func (u *unverifiedUser) Topic() string {
	return "NewUserRegistration"
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

func (u *verifiedUser) GetId() string {
	return u.GetType().String() + "/" + u.GetUsername()
}

func (u *verifiedUser) LockString() string {
	return u.GetNamespace() + "/" + u.GetId()
}

func (u *verifiedUser) Topic() string {
	return "NewUserCreated"
}

func (u *verifiedUser) ID() string {
	return u.GetId()
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

type authServer struct {
	pb.UnimplementedAuthServer

	dbP  store.Store
	lckr dLocker.DLocker
	ev   events.Events
	jm   auth.JWTManager
}

var OTP_LEN uint8 = 6

func New(svc msuite.Service) error {
	jwtMgr, err := svc.Auth().JWT()
	if err != nil {
		return err
	}
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
	lkApi, err := svc.Locker()
	if err != nil {
		return err
	}
	pb.RegisterAuthServer(grpcApi.Server(), &authServer{
		dbP:  ndApi.Storage(),
		lckr: lkApi,
		ev:   evApi,
		jm:   jwtMgr,
	})
	log.Info("Auth service registered")
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
func (s *authServer) Register(
	c context.Context,
	creds *pb.AuthCredentials,
) (retEmp *pb.AuthResponse, retErr error) {

	usrObj := &unverifiedUser{
		UnverifiedUser: &pb.UnverifiedUser{
			Type:     creds.Type,
			Username: creds.Username,
		},
	}
	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to get lock on user %s. SecErr:%s", usrObj.GetId(),
			err.Error())
		return
	}
	defer unlock()

	alreadyStarted := false
	err = s.dbP.Read(usrObj)
	if err == nil && usrObj.Verified {
		retErr = app_errors.ErrPermissionDenied("Username already exists. Please login.")
		log.Errorf("Username %s already exists.", usrObj.GetId())
		return
	} else if err == nil {
		alreadyStarted = true
	}
	hashedPass, err := bcrypt.GenerateFromPassword(
		[]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to generate password hash. SecErr:%s", err.Error())
		return
	}
	// Random string. Will be a 20 char string in case of email and 6 digit OTP in case of mobile.
	var ran_str string
	switch creds.Type {
	case pb.LoginType_EMAIL:
		ran_str = utils.RandStringBytes(20)
	case pb.LoginType_MOBILE:
		totp := &otp.TOTP{
			Length: OTP_LEN,
		}
		ran_str = totp.Get()
	case pb.LoginType_OAUTH_PROVIDER:
		fallthrough
	default:
		retErr = app_errors.ErrUnimplemented("Unsupported registration type.")
		log.Errorf("Failed to register user. SecErr:%s", err.Error())
		return
	}
	usrObj.Code = ran_str
	usrObj.Password = hashedPass

	if alreadyStarted {
		err = s.dbP.Update(usrObj)
	} else {
		err = s.dbP.Create(usrObj)
	}
	if err != nil {
		retErr = app_errors.ErrInternal("Failed creating user entry.")
		log.Errorf("Failed to register user SecErr:%s", err.Error())
		return
	}
	// Publish new user creation event. This can be used by other services
	// to send notifications etc
	err = s.ev.Broadcast(c, usrObj)
	if err != nil {
		log.Warnf("Failed to broadcast user registration msg %v", usrObj)
	}
	retEmp = &pb.AuthResponse{}
	return
}

// Used to complete verification.
func (s *authServer) Verify(
	c context.Context,
	verify *pb.VerifyReq,
) (retEmp *pb.AuthResponse, retErr error) {

	usrObj := &unverifiedUser{
		UnverifiedUser: &pb.UnverifiedUser{
			Type:     verify.Creds.Type,
			Username: verify.Creds.Username,
		},
	}

	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to get lock on user %s. SecErr:%s", usrObj.GetId(),
			err.Error())
		return
	}
	defer unlock()

	err = s.dbP.Read(usrObj)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed verifying user entry.")
		log.Errorf("Failed to verify user SecErr:%s", err.Error())
		return
	}
	if usrObj.Verified {
		retErr = app_errors.ErrInternal("Already verified user.")
		log.Errorf("Duplicate verification req: %v", verify)
		return
	}
	if usrObj.Code != verify.Code {
		retErr = app_errors.ErrPermissionDenied("Invalid verify code")
		log.Errorf("Invalid verify request %v", verify)
		return
	}
	verifiedUsr := &verifiedUser{
		&pb.VerifiedUser{
			Username: usrObj.Username,
			Type:     usrObj.Type,
			Password: usrObj.Password,
		},
	}
	// Step 1: Update user as verified
	usrObj.Verified = true
	err = s.dbP.Update(usrObj)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed creating user entry.")
		log.Errorf("Failed to update unverified user SecErr:%s", err.Error())
		return
	}
	// Step 2: Create verified user entry
	err = s.dbP.Create(verifiedUsr)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed creating user entry.")
		log.Errorf("Failed to create verified user SecErr:%s", err.Error())
		return
	}
	// Step 3: Broadcast new user creation
	err = s.ev.Broadcast(c, verifiedUsr)
	if err != nil {
		log.Warn("Failed broadcasting new user creation")
	}
	retEmp = &pb.AuthResponse{}
	return
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
	log.Infof("Generated New tokens: %s %s", acTok, rfshTok)
	return acTok, rfshTok, nil
}

func (s *authServer) Authenticate(
	c context.Context,
	creds *pb.AuthCredentials,
) (result *pb.AuthResult, retErr error) {

	usrObj := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}
	unlock, err := s.lckr.TryLock(c, usrObj.LockString(), DefaultTimeout)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to get lock on user %s. SecErr:%s", usrObj.GetId(),
			err.Error())
		return
	}
	defer unlock()

	err = s.dbP.Read(usrObj)
	if err != nil {
		retErr = app_errors.ErrPermissionDenied("Username does not exist. Please signup first.")
		log.Errorf("Username %s does not exist. SecErr:%s", usrObj.GetId(), err.Error())
		return
	}
	if usrObj.UseTempPwd {
		if err = bcrypt.CompareHashAndPassword(usrObj.TempPwd, []byte(creds.Password)); err != nil {
			retErr = app_errors.ErrPermissionDenied("Temporary Password incorrect.")
			log.Errorf("Temporary password doesnt match. SecErr:%v", err)
			return
		}
	} else {
		if err = bcrypt.CompareHashAndPassword(usrObj.Password, []byte(creds.Password)); err != nil {
			retErr = app_errors.ErrPermissionDenied("Password incorrect.")
			log.Errorf("Password doesnt match. SecErr:%v", err)
			return
		}
	}
	accTok, refTok, err := s.createTokens(usrObj)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed creating tokens. SecErr:%s", err.Error())
		return
	}
	result = &pb.AuthResult{
		UserId:       usrObj.UserId,
		AccessToken:  accTok,
		RefreshToken: refTok,
	}
	log.Infof("User %s login successful", usrObj.UserId)
	return
}

func getUsernameTypeFromClaims(c *auth.UserClaims) (pb.LoginType, string, error) {
	splits := strings.Split(c.ID, "/")
	if len(splits) != 2 {
		log.Errorf("Invalid claims ID %v", c)
		return 0, "", errors.New("Invalid claims ID")
	}
	return pb.LoginType(pb.LoginType_value[splits[0]]), splits[1], nil
}

func (s *authServer) RefreshToken(
	c context.Context,
	currToken *pb.AuthResult,
) (result *pb.AuthResult, retErr error) {

	if len(currToken.RefreshToken) == 0 {
		retErr = app_errors.ErrInvalidArg("Token not present.")
		log.Error("Refresh token empty")
		return
	}
	claims, err := s.jm.Verify(currToken.RefreshToken)
	if err != nil {
		retErr = app_errors.ErrPermissionDenied("Token invalid")
		log.Errorf("Token is invalid Err:%s", err.Error())
		return
	}
	usrType, username, err := getUsernameTypeFromClaims(claims)
	if err != nil {
		retErr = app_errors.ErrInternal("Invalid claims ID")
		log.Errorf("Invalid claims ID %s", err.Error())
		return
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
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed creating tokens. SecErr:%s", err.Error())
		return
	}
	result = &pb.AuthResult{
		UserId:       claims.ID,
		AccessToken:  accTok,
		RefreshToken: refTok,
	}
	log.Infof("Access token refresh successful for user %s", claims.ID)
	return
}

func (s *authServer) ResetPassword(
	c context.Context,
	updCreds *pb.UpdateCredentials,
) (retEmp *pb.AuthResponse, retErr error) {

	if len(updCreds.AccessToken) == 0 {
		retErr = app_errors.ErrInvalidArg("Token not present.")
		log.Error("Access token empty")
		return
	}
	// Parse returns error for expired tokens.
	claims, err := s.jm.Verify(updCreds.AccessToken)
	if err != nil {
		retErr = app_errors.ErrUnauthenticated("Invalid token.")
		log.Errorf("Error while parsing claims ERR:%s", err.Error())
		return
	}
	userId, ok := claims.Mtdt["UserId"]
	if !ok {
		retErr = app_errors.ErrInternal("UserID missing in claims")
		log.Errorf("Invalid claims, UserID missing %v", claims)
		return
	}
	if updCreds.UserId != userId {
		retErr = app_errors.ErrUnauthenticated("Token invalid for request.")
		log.Errorf("User ID mismatch in token and req. Token UID:%s ReqUID:%s",
			updCreds.UserId, claims.ID)
		return
	}
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(updCreds.OldPassword), bcrypt.DefaultCost)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to generate password hash. SecErr:%s", err.Error())
		return
	}
	usrType, username, err := getUsernameTypeFromClaims(claims)
	if err != nil {
		retErr = app_errors.ErrInternal("Invalid claims ID")
		log.Errorf("Invalid claims ID %s", err.Error())
		return
	}
	usr := &verifiedUser{
		&pb.VerifiedUser{
			Type:     usrType,
			Username: username,
		},
	}
	err = s.dbP.Read(usr)
	if err != nil {
		retErr = app_errors.ErrInvalidArg("Username does not exist.")
		log.Errorf("User ID %s does not exist.", updCreds.UserId)
		return
	}
	if usr.UseTempPwd {
		if bytes.Compare(usr.TempPwd, hashedPass) != 0 {
			retErr = app_errors.ErrPermissionDenied("Temporary Password incorrect.")
			log.Error("Temporary password doesnt match.")
			return
		}
	} else {
		if bytes.Compare(usr.Password, hashedPass) != 0 {
			retErr = app_errors.ErrPermissionDenied("Password incorrect.")
			log.Error("Password doesnt match.")
			return
		}
	}
	hashedPass, err = bcrypt.GenerateFromPassword([]byte(updCreds.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to generate password hash. SecErr:%s", err.Error())
		return
	}
	usr.Password = hashedPass
	usr.UseTempPwd = false

	err = s.dbP.Update(usr)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed updating password entry")
		log.Errorf("Failed updating password in DB SecErr:%s", err.Error())
	}
	retEmp = &pb.AuthResponse{}
	log.Infof("Reset password for user %s", usr.UserId)
	return
}

func (s *authServer) ForgotPassword(
	c context.Context,
	creds *pb.AuthCredentials,
) (retEmp *pb.AuthResponse, retErr error) {

	usr := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}
	unlock, err := s.lckr.TryLock(c, usr.LockString(), DefaultTimeout)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to get lock on user %s. SecErr:%s", usr.GetId(), err.Error())
		return
	}
	defer unlock()
	err = s.dbP.Read(usr)
	if err != nil {
		retErr = app_errors.ErrPermissionDenied("Username does not exist.")
		log.Errorf("Username %s does not exists. SecErr:%s", usr.GetId(), err.Error())
		return
	}
	temp_pwd := utils.RandStringBytes(10)
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(temp_pwd), bcrypt.DefaultCost)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to generate password hash. SecErr:%s", err.Error())
		return
	}
	usr.TempPwd = hashedPass
	usr.UseTempPwd = true

	err = s.dbP.Update(usr)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to update user. SecErr:%s", err.Error())
		return
	}
	retEmp = &pb.AuthResponse{}
	return
}

func (s *authServer) ReportUnauthorizedPwdChange(
	c context.Context,
	creds *pb.AuthCredentials,
) (retEmp *pb.AuthResponse, retErr error) {

	usr := &verifiedUser{
		&pb.VerifiedUser{
			Username: creds.Username,
			Type:     creds.Type,
		},
	}
	unlock, err := s.lckr.TryLock(c, usr.LockString(), DefaultTimeout)
	if err != nil {
		retErr = app_errors.ErrInternal("Internal server error.")
		log.Errorf("Failed to get lock on user %s. SecErr:%s", usr.GetId(), err.Error())
		return
	}
	defer unlock()
	err = s.dbP.Read(usr)
	if err != nil {
		retErr = app_errors.ErrInternal("Username does not exist.")
		log.Errorf("Username %s already exists. SecErr:%s", usr.GetId(), err.Error())
		return
	}
	usr.UseTempPwd = false

	err = s.dbP.Update(usr)
	if err != nil {
		retErr = app_errors.ErrInternal("Failed removing temporary password.")
		log.Errorf("Failed removing temp password from DB SecErr:%s", err.Error())
	}
	retEmp = &pb.AuthResponse{}
	return
}

var user_registration_email = `<style>
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
	<p>Thanks for registering with UrbanTrainers!</p>
	<p>As a final step in the registration, please click on the following link to verify
	your email address and you are all set!</p>
	<p><form action="http://localhost:8080/auth/v1/verify/%s?type=%s&username=%s" method="post">
	  <button type="submit" name="verify_btn" class="btn-link">Verify Email Address</button>
	</form></p>
	<p>Thanks,</p>
	<p>UrbanTrainers Team</p>`

var forgot_pwd_email = `<style>
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
	<p><form action="http://localhost:8080/auth/v1/report_pwd_change/%s?type=%s&password=%s" method="post">
	<button type="submit" name="verify_btn" class="btn-link">Report unauthorized password change</button>
	</form></p>
	<p>The temporary password will be valid for a period of 24 hours. It is recommended that
	you reset the password immediately after logging in. If you fail to change within 24 hours, you
	will need to re-submit the password change request. This is required for your account's safety!</p>
	<p>Thanks,</p>
	<p>UrbanTrainers Team</p>`

var user_registration_sms = "Your OTP is %s. Please use it to complete the registration process."
var user_forgot_password_sms = `<style>
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
	<p><form action="http://localhost:8080/auth/v1/report_pwd_change/%s?type=%s&password=%s" method="post">
	<button type="submit" name="verify_btn" class="btn-link">Report unauthorized password change</button>
	</form></p>`
