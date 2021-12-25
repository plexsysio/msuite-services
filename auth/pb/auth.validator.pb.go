// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: auth.proto

package pb

import (
	fmt "fmt"
	math "math"
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	_ "github.com/mwitkow/go-proto-validators"
	github_com_mwitkow_go_proto_validators "github.com/mwitkow/go-proto-validators"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

func (this *AuthCredentials) Validate() error {
	if _, ok := LoginType_name[int32(this.Type)]; !ok {
		return github_com_mwitkow_go_proto_validators.FieldError("Type", fmt.Errorf(`value '%v' must be a valid LoginType field`, this.Type))
	}
	if this.Username == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("Username", fmt.Errorf(`value '%v' must not be an empty string`, this.Username))
	}
	return nil
}
func (this *VerifyReq) Validate() error {
	if this.Code == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("Code", fmt.Errorf(`value '%v' must not be an empty string`, this.Code))
	}
	if nil == this.Creds {
		return github_com_mwitkow_go_proto_validators.FieldError("Creds", fmt.Errorf("message must exist"))
	}
	if this.Creds != nil {
		if err := github_com_mwitkow_go_proto_validators.CallValidatorIfExists(this.Creds); err != nil {
			return github_com_mwitkow_go_proto_validators.FieldError("Creds", err)
		}
	}
	return nil
}
func (this *AuthResponse) Validate() error {
	return nil
}
func (this *AuthResult) Validate() error {
	if this.UserId == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("UserId", fmt.Errorf(`value '%v' must not be an empty string`, this.UserId))
	}
	if this.AccessToken == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("AccessToken", fmt.Errorf(`value '%v' must not be an empty string`, this.AccessToken))
	}
	if this.RefreshToken == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("RefreshToken", fmt.Errorf(`value '%v' must not be an empty string`, this.RefreshToken))
	}
	return nil
}
func (this *UpdateCredentials) Validate() error {
	if this.UserId == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("UserId", fmt.Errorf(`value '%v' must not be an empty string`, this.UserId))
	}
	if this.NewPassword == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("NewPassword", fmt.Errorf(`value '%v' must not be an empty string`, this.NewPassword))
	}
	if this.OldPassword == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("OldPassword", fmt.Errorf(`value '%v' must not be an empty string`, this.OldPassword))
	}
	if this.AccessToken == "" {
		return github_com_mwitkow_go_proto_validators.FieldError("AccessToken", fmt.Errorf(`value '%v' must not be an empty string`, this.AccessToken))
	}
	return nil
}
func (this *UnverifiedUser) Validate() error {
	return nil
}
func (this *VerifiedUser) Validate() error {
	return nil
}