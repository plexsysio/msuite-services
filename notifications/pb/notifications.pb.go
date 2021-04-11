// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: notifications.proto

package pb

import (
	proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type NotificationType int32

const (
	NotificationType_RESERVED NotificationType = 0
	NotificationType_EMAIL    NotificationType = 1
	NotificationType_SMS      NotificationType = 2
	NotificationType_WEB      NotificationType = 4
	NotificationType_ANDROID  NotificationType = 8
	NotificationType_IOS      NotificationType = 16
	// Pull type is basically a notification which will be pulled
	// by client subsequently. We just need to save the notification
	// in this case.
	// The value is such that, any of the WEB, ANDROID or IOS providers
	// can be used to send the notification if they exist.
	NotificationType_PULL NotificationType = 28
)

// Enum value maps for NotificationType.
var (
	NotificationType_name = map[int32]string{
		0:  "RESERVED",
		1:  "EMAIL",
		2:  "SMS",
		4:  "WEB",
		8:  "ANDROID",
		16: "IOS",
		28: "PULL",
	}
	NotificationType_value = map[string]int32{
		"RESERVED": 0,
		"EMAIL":    1,
		"SMS":      2,
		"WEB":      4,
		"ANDROID":  8,
		"IOS":      16,
		"PULL":     28,
	}
)

func (x NotificationType) Enum() *NotificationType {
	p := new(NotificationType)
	*p = x
	return p
}

func (x NotificationType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NotificationType) Descriptor() protoreflect.EnumDescriptor {
	return file_notifications_proto_enumTypes[0].Descriptor()
}

func (NotificationType) Type() protoreflect.EnumType {
	return &file_notifications_proto_enumTypes[0]
}

func (x NotificationType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NotificationType.Descriptor instead.
func (NotificationType) EnumDescriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{0}
}

type ID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Val string `protobuf:"bytes,1,opt,name=val,proto3" json:"val,omitempty"`
}

func (x *ID) Reset() {
	*x = ID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ID) ProtoMessage() {}

func (x *ID) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ID.ProtoReflect.Descriptor instead.
func (*ID) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{0}
}

func (x *ID) GetVal() string {
	if x != nil {
		return x.Val
	}
	return ""
}

type IDs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Vals []string `protobuf:"bytes,1,rep,name=vals,proto3" json:"vals,omitempty"`
}

func (x *IDs) Reset() {
	*x = IDs{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IDs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IDs) ProtoMessage() {}

func (x *IDs) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IDs.ProtoReflect.Descriptor instead.
func (*IDs) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{1}
}

func (x *IDs) GetVals() []string {
	if x != nil {
		return x.Vals
	}
	return nil
}

type SubscriberInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Mode       NotificationType `protobuf:"varint,1,opt,name=mode,proto3,enum=pb.NotificationType" json:"mode,omitempty"`
	Identifier string           `protobuf:"bytes,2,opt,name=identifier,proto3" json:"identifier,omitempty"`
}

func (x *SubscriberInfo) Reset() {
	*x = SubscriberInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscriberInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscriberInfo) ProtoMessage() {}

func (x *SubscriberInfo) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscriberInfo.ProtoReflect.Descriptor instead.
func (*SubscriberInfo) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{2}
}

func (x *SubscriberInfo) GetMode() NotificationType {
	if x != nil {
		return x.Mode
	}
	return NotificationType_RESERVED
}

func (x *SubscriberInfo) GetIdentifier() string {
	if x != nil {
		return x.Identifier
	}
	return ""
}

type SubscribeReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	UserId        string            `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Subscriptions []*SubscriberInfo `protobuf:"bytes,2,rep,name=subscriptions,proto3" json:"subscriptions,omitempty"`
}

func (x *SubscribeReq) Reset() {
	*x = SubscribeReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscribeReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscribeReq) ProtoMessage() {}

func (x *SubscribeReq) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscribeReq.ProtoReflect.Descriptor instead.
func (*SubscribeReq) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{3}
}

func (x *SubscribeReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *SubscribeReq) GetSubscriptions() []*SubscriberInfo {
	if x != nil {
		return x.Subscriptions
	}
	return nil
}

type Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From  string `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	To    string `protobuf:"bytes,2,opt,name=to,proto3" json:"to,omitempty"`
	Title string `protobuf:"bytes,3,opt,name=title,proto3" json:"title,omitempty"`
	Body  string `protobuf:"bytes,4,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *Msg) Reset() {
	*x = Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Msg) ProtoMessage() {}

func (x *Msg) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Msg.ProtoReflect.Descriptor instead.
func (*Msg) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{4}
}

func (x *Msg) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *Msg) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *Msg) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *Msg) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

type SendReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type   NotificationType `protobuf:"varint,1,opt,name=type,proto3,enum=pb.NotificationType" json:"type,omitempty"`
	UserId string           `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Data   *Msg             `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *SendReq) Reset() {
	*x = SendReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SendReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendReq) ProtoMessage() {}

func (x *SendReq) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendReq.ProtoReflect.Descriptor instead.
func (*SendReq) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{5}
}

func (x *SendReq) GetType() NotificationType {
	if x != nil {
		return x.Type
	}
	return NotificationType_RESERVED
}

func (x *SendReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *SendReq) GetData() *Msg {
	if x != nil {
		return x.Data
	}
	return nil
}

type Notification struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string           `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	UserId  string           `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Type    NotificationType `protobuf:"varint,3,opt,name=type,proto3,enum=pb.NotificationType" json:"type,omitempty"`
	Data    *Msg             `protobuf:"bytes,4,opt,name=data,proto3" json:"data,omitempty"`
	Created int64            `protobuf:"varint,98,opt,name=created,proto3" json:"created,omitempty"`
	Updated int64            `protobuf:"varint,99,opt,name=updated,proto3" json:"updated,omitempty"`
}

func (x *Notification) Reset() {
	*x = Notification{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Notification) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Notification) ProtoMessage() {}

func (x *Notification) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Notification.ProtoReflect.Descriptor instead.
func (*Notification) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{6}
}

func (x *Notification) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Notification) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *Notification) GetType() NotificationType {
	if x != nil {
		return x.Type
	}
	return NotificationType_RESERVED
}

func (x *Notification) GetData() *Msg {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Notification) GetCreated() int64 {
	if x != nil {
		return x.Created
	}
	return 0
}

func (x *Notification) GetUpdated() int64 {
	if x != nil {
		return x.Updated
	}
	return 0
}

type NotificationList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*Notification `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *NotificationList) Reset() {
	*x = NotificationList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_notifications_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NotificationList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotificationList) ProtoMessage() {}

func (x *NotificationList) ProtoReflect() protoreflect.Message {
	mi := &file_notifications_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotificationList.ProtoReflect.Descriptor instead.
func (*NotificationList) Descriptor() ([]byte, []int) {
	return file_notifications_proto_rawDescGZIP(), []int{7}
}

func (x *NotificationList) GetItems() []*Notification {
	if x != nil {
		return x.Items
	}
	return nil
}

var File_notifications_proto protoreflect.FileDescriptor

var file_notifications_proto_rawDesc = []byte{
	0x0a, 0x13, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x70, 0x62, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x16, 0x0a, 0x02, 0x49, 0x44, 0x12, 0x10, 0x0a,
	0x03, 0x76, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x76, 0x61, 0x6c, 0x22,
	0x19, 0x0a, 0x03, 0x49, 0x44, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x76, 0x61, 0x6c, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x76, 0x61, 0x6c, 0x73, 0x22, 0x5a, 0x0a, 0x0e, 0x53, 0x75,
	0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x28, 0x0a, 0x04,
	0x6d, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x70, 0x62, 0x2e,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x66, 0x69, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x22, 0x61, 0x0a, 0x0c, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72,
	0x69, 0x62, 0x65, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x38, 0x0a, 0x0d, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x70, 0x62, 0x2e, 0x53, 0x75, 0x62, 0x73,
	0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x73, 0x75, 0x62, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x53, 0x0a, 0x03, 0x4d, 0x73, 0x67,
	0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x74, 0x6f, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f,
	0x64, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0x69,
	0x0a, 0x07, 0x53, 0x65, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x12, 0x28, 0x0a, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x70, 0x62, 0x2e, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x70, 0x62, 0x2e,
	0x4d, 0x73, 0x67, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0xb2, 0x01, 0x0a, 0x0c, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65,
	0x72, 0x49, 0x64, 0x12, 0x28, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x14, 0x2e, 0x70, 0x62, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1b, 0x0a,
	0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x70, 0x62,
	0x2e, 0x4d, 0x73, 0x67, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x64, 0x18, 0x62, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18,
	0x63, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x22, 0x3a,
	0x0a, 0x10, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x26, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x70, 0x62, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x2a, 0x5d, 0x0a, 0x10, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0c,
	0x0a, 0x08, 0x52, 0x45, 0x53, 0x45, 0x52, 0x56, 0x45, 0x44, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05,
	0x45, 0x4d, 0x41, 0x49, 0x4c, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x53, 0x4d, 0x53, 0x10, 0x02,
	0x12, 0x07, 0x0a, 0x03, 0x57, 0x45, 0x42, 0x10, 0x04, 0x12, 0x0b, 0x0a, 0x07, 0x41, 0x4e, 0x44,
	0x52, 0x4f, 0x49, 0x44, 0x10, 0x08, 0x12, 0x07, 0x0a, 0x03, 0x49, 0x4f, 0x53, 0x10, 0x10, 0x12,
	0x08, 0x0a, 0x04, 0x50, 0x55, 0x4c, 0x4c, 0x10, 0x1c, 0x32, 0xed, 0x01, 0x0a, 0x0d, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x4d, 0x0a, 0x09, 0x53,
	0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x12, 0x10, 0x2e, 0x70, 0x62, 0x2e, 0x53, 0x75,
	0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x52, 0x65, 0x71, 0x1a, 0x06, 0x2e, 0x70, 0x62, 0x2e,
	0x49, 0x44, 0x22, 0x26, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x20, 0x22, 0x1b, 0x2f, 0x6e, 0x6f, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x75,
	0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x3a, 0x01, 0x2a, 0x12, 0x48, 0x0a, 0x04, 0x53, 0x65,
	0x6e, 0x64, 0x12, 0x0b, 0x2e, 0x70, 0x62, 0x2e, 0x53, 0x65, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x1a,
	0x10, 0x2e, 0x70, 0x62, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x22, 0x21, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1b, 0x22, 0x16, 0x2f, 0x6e, 0x6f, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x6e,
	0x64, 0x3a, 0x01, 0x2a, 0x12, 0x43, 0x0a, 0x03, 0x47, 0x65, 0x74, 0x12, 0x07, 0x2e, 0x70, 0x62,
	0x2e, 0x49, 0x44, 0x73, 0x1a, 0x14, 0x2e, 0x70, 0x62, 0x2e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x22, 0x1d, 0x82, 0xd3, 0xe4, 0x93,
	0x02, 0x17, 0x12, 0x15, 0x2f, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x42, 0x27, 0x5a, 0x25, 0x67, 0x69, 0x74,
	0x6c, 0x61, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x2d, 0x6d, 0x73, 0x75, 0x69, 0x74,
	0x65, 0x2f, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_notifications_proto_rawDescOnce sync.Once
	file_notifications_proto_rawDescData = file_notifications_proto_rawDesc
)

func file_notifications_proto_rawDescGZIP() []byte {
	file_notifications_proto_rawDescOnce.Do(func() {
		file_notifications_proto_rawDescData = protoimpl.X.CompressGZIP(file_notifications_proto_rawDescData)
	})
	return file_notifications_proto_rawDescData
}

var file_notifications_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_notifications_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_notifications_proto_goTypes = []interface{}{
	(NotificationType)(0),    // 0: pb.NotificationType
	(*ID)(nil),               // 1: pb.ID
	(*IDs)(nil),              // 2: pb.IDs
	(*SubscriberInfo)(nil),   // 3: pb.SubscriberInfo
	(*SubscribeReq)(nil),     // 4: pb.SubscribeReq
	(*Msg)(nil),              // 5: pb.Msg
	(*SendReq)(nil),          // 6: pb.SendReq
	(*Notification)(nil),     // 7: pb.Notification
	(*NotificationList)(nil), // 8: pb.NotificationList
}
var file_notifications_proto_depIdxs = []int32{
	0,  // 0: pb.SubscriberInfo.mode:type_name -> pb.NotificationType
	3,  // 1: pb.SubscribeReq.subscriptions:type_name -> pb.SubscriberInfo
	0,  // 2: pb.SendReq.type:type_name -> pb.NotificationType
	5,  // 3: pb.SendReq.data:type_name -> pb.Msg
	0,  // 4: pb.Notification.type:type_name -> pb.NotificationType
	5,  // 5: pb.Notification.data:type_name -> pb.Msg
	7,  // 6: pb.NotificationList.items:type_name -> pb.Notification
	4,  // 7: pb.Notifications.Subscribe:input_type -> pb.SubscribeReq
	6,  // 8: pb.Notifications.Send:input_type -> pb.SendReq
	2,  // 9: pb.Notifications.Get:input_type -> pb.IDs
	1,  // 10: pb.Notifications.Subscribe:output_type -> pb.ID
	7,  // 11: pb.Notifications.Send:output_type -> pb.Notification
	8,  // 12: pb.Notifications.Get:output_type -> pb.NotificationList
	10, // [10:13] is the sub-list for method output_type
	7,  // [7:10] is the sub-list for method input_type
	7,  // [7:7] is the sub-list for extension type_name
	7,  // [7:7] is the sub-list for extension extendee
	0,  // [0:7] is the sub-list for field type_name
}

func init() { file_notifications_proto_init() }
func file_notifications_proto_init() {
	if File_notifications_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_notifications_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IDs); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscriberInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscribeReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SendReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Notification); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_notifications_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NotificationList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_notifications_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_notifications_proto_goTypes,
		DependencyIndexes: file_notifications_proto_depIdxs,
		EnumInfos:         file_notifications_proto_enumTypes,
		MessageInfos:      file_notifications_proto_msgTypes,
	}.Build()
	File_notifications_proto = out.File
	file_notifications_proto_rawDesc = nil
	file_notifications_proto_goTypes = nil
	file_notifications_proto_depIdxs = nil
}