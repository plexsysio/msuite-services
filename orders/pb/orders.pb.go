// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.14.0
// source: orders.proto

package pb

import (
	pb1 "github.com/aloknerurkar/msuite-services/common/pb"
	pb2 "github.com/aloknerurkar/msuite-services/inventory/pb"
	pb "github.com/aloknerurkar/msuite-services/payments/pb"
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

type Item_OrderStatus int32

const (
	Item_RESERVED  Item_OrderStatus = 0 // Not to be used.
	Item_CREATED   Item_OrderStatus = 1
	Item_PAID      Item_OrderStatus = 2
	Item_CANCELLED Item_OrderStatus = 3
	Item_COMPLETED Item_OrderStatus = 4
	Item_RETURNED  Item_OrderStatus = 5
)

// Enum value maps for Item_OrderStatus.
var (
	Item_OrderStatus_name = map[int32]string{
		0: "RESERVED",
		1: "CREATED",
		2: "PAID",
		3: "CANCELLED",
		4: "COMPLETED",
		5: "RETURNED",
	}
	Item_OrderStatus_value = map[string]int32{
		"RESERVED":  0,
		"CREATED":   1,
		"PAID":      2,
		"CANCELLED": 3,
		"COMPLETED": 4,
		"RETURNED":  5,
	}
)

func (x Item_OrderStatus) Enum() *Item_OrderStatus {
	p := new(Item_OrderStatus)
	*p = x
	return p
}

func (x Item_OrderStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Item_OrderStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_orders_proto_enumTypes[0].Descriptor()
}

func (Item_OrderStatus) Type() protoreflect.EnumType {
	return &file_orders_proto_enumTypes[0]
}

func (x Item_OrderStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Item_OrderStatus.Descriptor instead.
func (Item_OrderStatus) EnumDescriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{0, 0}
}

type OrderItem_Type int32

const (
	OrderItem_RESERVED  OrderItem_Type = 0
	OrderItem_INVENTORY OrderItem_Type = 1
	OrderItem_DISCOUNT  OrderItem_Type = 2
	OrderItem_TAX       OrderItem_Type = 3
	OrderItem_INSURANCE OrderItem_Type = 4
	OrderItem_SHIPPING  OrderItem_Type = 5
)

// Enum value maps for OrderItem_Type.
var (
	OrderItem_Type_name = map[int32]string{
		0: "RESERVED",
		1: "INVENTORY",
		2: "DISCOUNT",
		3: "TAX",
		4: "INSURANCE",
		5: "SHIPPING",
	}
	OrderItem_Type_value = map[string]int32{
		"RESERVED":  0,
		"INVENTORY": 1,
		"DISCOUNT":  2,
		"TAX":       3,
		"INSURANCE": 4,
		"SHIPPING":  5,
	}
)

func (x OrderItem_Type) Enum() *OrderItem_Type {
	p := new(OrderItem_Type)
	*p = x
	return p
}

func (x OrderItem_Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OrderItem_Type) Descriptor() protoreflect.EnumDescriptor {
	return file_orders_proto_enumTypes[1].Descriptor()
}

func (OrderItem_Type) Type() protoreflect.EnumType {
	return &file_orders_proto_enumTypes[1]
}

func (x OrderItem_Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OrderItem_Type.Descriptor instead.
func (OrderItem_Type) EnumDescriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{1, 0}
}

type Item struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string            `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Amount    int64             `protobuf:"varint,2,opt,name=amount,proto3" json:"amount,omitempty"`
	Currency  pb.Currency       `protobuf:"varint,3,opt,name=currency,proto3,enum=payments.Currency" json:"currency,omitempty"`
	Status    Item_OrderStatus  `protobuf:"varint,4,opt,name=status,proto3,enum=orders.Item_OrderStatus" json:"status,omitempty"`
	UserId    string            `protobuf:"bytes,5,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	Items     []*OrderItem      `protobuf:"bytes,6,rep,name=items,proto3" json:"items,omitempty"`
	Email     string            `protobuf:"bytes,7,opt,name=email,proto3" json:"email,omitempty"`
	PaymentId string            `protobuf:"bytes,8,opt,name=payment_id,json=paymentId,proto3" json:"payment_id,omitempty"`
	Meta      map[string]string `protobuf:"bytes,9,rep,name=meta,proto3" json:"meta,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Shipping  *ShippingInfo     `protobuf:"bytes,10,opt,name=shipping,proto3" json:"shipping,omitempty"`
	// Add new fields here.
	Created int64 `protobuf:"varint,98,opt,name=created,proto3" json:"created,omitempty"`
	Updated int64 `protobuf:"varint,99,opt,name=updated,proto3" json:"updated,omitempty"`
}

func (x *Item) Reset() {
	*x = Item{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Item) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Item) ProtoMessage() {}

func (x *Item) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Item.ProtoReflect.Descriptor instead.
func (*Item) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{0}
}

func (x *Item) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Item) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *Item) GetCurrency() pb.Currency {
	if x != nil {
		return x.Currency
	}
	return pb.Currency_RESERVED
}

func (x *Item) GetStatus() Item_OrderStatus {
	if x != nil {
		return x.Status
	}
	return Item_RESERVED
}

func (x *Item) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *Item) GetItems() []*OrderItem {
	if x != nil {
		return x.Items
	}
	return nil
}

func (x *Item) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *Item) GetPaymentId() string {
	if x != nil {
		return x.PaymentId
	}
	return ""
}

func (x *Item) GetMeta() map[string]string {
	if x != nil {
		return x.Meta
	}
	return nil
}

func (x *Item) GetShipping() *ShippingInfo {
	if x != nil {
		return x.Shipping
	}
	return nil
}

func (x *Item) GetCreated() int64 {
	if x != nil {
		return x.Created
	}
	return 0
}

func (x *Item) GetUpdated() int64 {
	if x != nil {
		return x.Updated
	}
	return 0
}

type OrderItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type        OrderItem_Type `protobuf:"varint,1,opt,name=type,proto3,enum=orders.OrderItem_Type" json:"type,omitempty"`
	Amount      int64          `protobuf:"varint,2,opt,name=amount,proto3" json:"amount,omitempty"`
	Currency    pb.Currency    `protobuf:"varint,3,opt,name=currency,proto3,enum=payments.Currency" json:"currency,omitempty"`
	ParentId    string         `protobuf:"bytes,4,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	Quantity    int64          `protobuf:"varint,5,opt,name=quantity,proto3" json:"quantity,omitempty"`
	Description string         `protobuf:"bytes,6,opt,name=description,proto3" json:"description,omitempty"`
}

func (x *OrderItem) Reset() {
	*x = OrderItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OrderItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OrderItem) ProtoMessage() {}

func (x *OrderItem) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OrderItem.ProtoReflect.Descriptor instead.
func (*OrderItem) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{1}
}

func (x *OrderItem) GetType() OrderItem_Type {
	if x != nil {
		return x.Type
	}
	return OrderItem_RESERVED
}

func (x *OrderItem) GetAmount() int64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *OrderItem) GetCurrency() pb.Currency {
	if x != nil {
		return x.Currency
	}
	return pb.Currency_RESERVED
}

func (x *OrderItem) GetParentId() string {
	if x != nil {
		return x.ParentId
	}
	return ""
}

func (x *OrderItem) GetQuantity() int64 {
	if x != nil {
		return x.Quantity
	}
	return 0
}

func (x *OrderItem) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type ShippingInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name           string           `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Phone          string           `protobuf:"bytes,2,opt,name=phone,proto3" json:"phone,omitempty"`
	Address        *pb1.LongAddress `protobuf:"bytes,3,opt,name=address,proto3" json:"address,omitempty"`
	Carrier        string           `protobuf:"bytes,4,opt,name=carrier,proto3" json:"carrier,omitempty"`
	TrackingNumber string           `protobuf:"bytes,5,opt,name=trackingNumber,proto3" json:"trackingNumber,omitempty"`
}

func (x *ShippingInfo) Reset() {
	*x = ShippingInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShippingInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShippingInfo) ProtoMessage() {}

func (x *ShippingInfo) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShippingInfo.ProtoReflect.Descriptor instead.
func (*ShippingInfo) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{2}
}

func (x *ShippingInfo) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ShippingInfo) GetPhone() string {
	if x != nil {
		return x.Phone
	}
	return ""
}

func (x *ShippingInfo) GetAddress() *pb1.LongAddress {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *ShippingInfo) GetCarrier() string {
	if x != nil {
		return x.Carrier
	}
	return ""
}

func (x *ShippingInfo) GetTrackingNumber() string {
	if x != nil {
		return x.TrackingNumber
	}
	return ""
}

type Items struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Items []*Item `protobuf:"bytes,1,rep,name=items,proto3" json:"items,omitempty"`
}

func (x *Items) Reset() {
	*x = Items{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Items) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Items) ProtoMessage() {}

func (x *Items) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Items.ProtoReflect.Descriptor instead.
func (*Items) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{3}
}

func (x *Items) GetItems() []*Item {
	if x != nil {
		return x.Items
	}
	return nil
}

type NewOrderReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ItemId  string       `protobuf:"bytes,1,opt,name=item_id,json=itemId,proto3" json:"item_id,omitempty"`
	Rate    *pb2.Rate    `protobuf:"bytes,2,opt,name=rate,proto3" json:"rate,omitempty"`
	Items   []*OrderItem `protobuf:"bytes,3,rep,name=items,proto3" json:"items,omitempty"`
	Email   string       `protobuf:"bytes,4,opt,name=email,proto3" json:"email,omitempty"`
	UserId  string       `protobuf:"bytes,5,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	ChildId string       `protobuf:"bytes,6,opt,name=child_id,json=childId,proto3" json:"child_id,omitempty"`
}

func (x *NewOrderReq) Reset() {
	*x = NewOrderReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NewOrderReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NewOrderReq) ProtoMessage() {}

func (x *NewOrderReq) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NewOrderReq.ProtoReflect.Descriptor instead.
func (*NewOrderReq) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{4}
}

func (x *NewOrderReq) GetItemId() string {
	if x != nil {
		return x.ItemId
	}
	return ""
}

func (x *NewOrderReq) GetRate() *pb2.Rate {
	if x != nil {
		return x.Rate
	}
	return nil
}

func (x *NewOrderReq) GetItems() []*OrderItem {
	if x != nil {
		return x.Items
	}
	return nil
}

func (x *NewOrderReq) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *NewOrderReq) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *NewOrderReq) GetChildId() string {
	if x != nil {
		return x.ChildId
	}
	return ""
}

type PayOrderReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OrderId string                  `protobuf:"bytes,1,opt,name=order_id,json=orderId,proto3" json:"order_id,omitempty"`
	Charges []*PayOrderReq_PaySplit `protobuf:"bytes,2,rep,name=charges,proto3" json:"charges,omitempty"`
}

func (x *PayOrderReq) Reset() {
	*x = PayOrderReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PayOrderReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PayOrderReq) ProtoMessage() {}

func (x *PayOrderReq) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PayOrderReq.ProtoReflect.Descriptor instead.
func (*PayOrderReq) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{5}
}

func (x *PayOrderReq) GetOrderId() string {
	if x != nil {
		return x.OrderId
	}
	return ""
}

func (x *PayOrderReq) GetCharges() []*PayOrderReq_PaySplit {
	if x != nil {
		return x.Charges
	}
	return nil
}

type PayOrderReq_PaySplit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Provider pb.ProviderId `protobuf:"varint,1,opt,name=provider,proto3,enum=payments.ProviderId" json:"provider,omitempty"`
	// Types that are assignable to Charge:
	//	*PayOrderReq_PaySplit_UserId
	//	*PayOrderReq_PaySplit_Card
	//	*PayOrderReq_PaySplit_PaymentRef
	Charge isPayOrderReq_PaySplit_Charge `protobuf_oneof:"Charge"`
}

func (x *PayOrderReq_PaySplit) Reset() {
	*x = PayOrderReq_PaySplit{}
	if protoimpl.UnsafeEnabled {
		mi := &file_orders_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PayOrderReq_PaySplit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PayOrderReq_PaySplit) ProtoMessage() {}

func (x *PayOrderReq_PaySplit) ProtoReflect() protoreflect.Message {
	mi := &file_orders_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PayOrderReq_PaySplit.ProtoReflect.Descriptor instead.
func (*PayOrderReq_PaySplit) Descriptor() ([]byte, []int) {
	return file_orders_proto_rawDescGZIP(), []int{5, 0}
}

func (x *PayOrderReq_PaySplit) GetProvider() pb.ProviderId {
	if x != nil {
		return x.Provider
	}
	return pb.ProviderId_PROVIDER_RESERVED
}

func (m *PayOrderReq_PaySplit) GetCharge() isPayOrderReq_PaySplit_Charge {
	if m != nil {
		return m.Charge
	}
	return nil
}

func (x *PayOrderReq_PaySplit) GetUserId() string {
	if x, ok := x.GetCharge().(*PayOrderReq_PaySplit_UserId); ok {
		return x.UserId
	}
	return ""
}

func (x *PayOrderReq_PaySplit) GetCard() *pb.Card {
	if x, ok := x.GetCharge().(*PayOrderReq_PaySplit_Card); ok {
		return x.Card
	}
	return nil
}

func (x *PayOrderReq_PaySplit) GetPaymentRef() string {
	if x, ok := x.GetCharge().(*PayOrderReq_PaySplit_PaymentRef); ok {
		return x.PaymentRef
	}
	return ""
}

type isPayOrderReq_PaySplit_Charge interface {
	isPayOrderReq_PaySplit_Charge()
}

type PayOrderReq_PaySplit_UserId struct {
	UserId string `protobuf:"bytes,2,opt,name=user_id,json=userId,proto3,oneof"`
}

type PayOrderReq_PaySplit_Card struct {
	Card *pb.Card `protobuf:"bytes,3,opt,name=card,proto3,oneof"`
}

type PayOrderReq_PaySplit_PaymentRef struct {
	PaymentRef string `protobuf:"bytes,4,opt,name=payment_ref,json=paymentRef,proto3,oneof"`
}

func (*PayOrderReq_PaySplit_UserId) isPayOrderReq_PaySplit_Charge() {}

func (*PayOrderReq_PaySplit_Card) isPayOrderReq_PaySplit_Charge() {}

func (*PayOrderReq_PaySplit_PaymentRef) isPayOrderReq_PaySplit_Charge() {}

var File_orders_proto protoreflect.FileDescriptor

var file_orders_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70,
	0x62, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x62, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x70, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2f, 0x70, 0x62, 0x2f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x69, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f,
	0x72, 0x79, 0x2f, 0x70, 0x62, 0x2f, 0x69, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f, 0x72, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb2, 0x04, 0x0a, 0x04, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16,
	0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x08, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e,
	0x63, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12, 0x2e, 0x70, 0x61, 0x79, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x2e, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x52, 0x08, 0x63, 0x75,
	0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x30, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e,
	0x49, 0x74, 0x65, 0x6d, 0x2e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72,
	0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49,
	0x64, 0x12, 0x27, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x11, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x49,
	0x74, 0x65, 0x6d, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x6d,
	0x61, 0x69, 0x6c, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c,
	0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12,
	0x2a, 0x0a, 0x04, 0x6d, 0x65, 0x74, 0x61, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74, 0x65, 0x6d, 0x2e, 0x4d, 0x65, 0x74, 0x61,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x04, 0x6d, 0x65, 0x74, 0x61, 0x12, 0x30, 0x0a, 0x08, 0x73,
	0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x53, 0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x08, 0x73, 0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x18, 0x0a,
	0x07, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x18, 0x62, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x64, 0x18, 0x63, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x64, 0x1a, 0x37, 0x0a, 0x09, 0x4d, 0x65, 0x74, 0x61, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x5e, 0x0a, 0x0b, 0x4f, 0x72,
	0x64, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x0c, 0x0a, 0x08, 0x52, 0x45, 0x53,
	0x45, 0x52, 0x56, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x43, 0x52, 0x45, 0x41, 0x54,
	0x45, 0x44, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x50, 0x41, 0x49, 0x44, 0x10, 0x02, 0x12, 0x0d,
	0x0a, 0x09, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x4c, 0x45, 0x44, 0x10, 0x03, 0x12, 0x0d, 0x0a,
	0x09, 0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x04, 0x12, 0x0c, 0x0a, 0x08,
	0x52, 0x45, 0x54, 0x55, 0x52, 0x4e, 0x45, 0x44, 0x10, 0x05, 0x22, 0xb3, 0x02, 0x0a, 0x09, 0x4f,
	0x72, 0x64, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x2a, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e,
	0x4f, 0x72, 0x64, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x2e, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04,
	0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x08,
	0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x12,
	0x2e, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x43, 0x75, 0x72, 0x72, 0x65, 0x6e,
	0x63, 0x79, 0x52, 0x08, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x1b, 0x0a, 0x09,
	0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x71, 0x75, 0x61,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x71, 0x75, 0x61,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x57, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x0c, 0x0a, 0x08, 0x52, 0x45, 0x53, 0x45, 0x52, 0x56, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0d, 0x0a,
	0x09, 0x49, 0x4e, 0x56, 0x45, 0x4e, 0x54, 0x4f, 0x52, 0x59, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08,
	0x44, 0x49, 0x53, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x54, 0x41,
	0x58, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x49, 0x4e, 0x53, 0x55, 0x52, 0x41, 0x4e, 0x43, 0x45,
	0x10, 0x04, 0x12, 0x0c, 0x0a, 0x08, 0x53, 0x48, 0x49, 0x50, 0x50, 0x49, 0x4e, 0x47, 0x10, 0x05,
	0x22, 0xa7, 0x01, 0x0a, 0x0c, 0x53, 0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x12, 0x2b, 0x0a, 0x07, 0x61,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x6d,
	0x73, 0x67, 0x73, 0x2e, 0x4c, 0x6f, 0x6e, 0x67, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x52,
	0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x61, 0x72, 0x72,
	0x69, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x63, 0x61, 0x72, 0x72, 0x69,
	0x65, 0x72, 0x12, 0x26, 0x0a, 0x0e, 0x74, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x4e, 0x75,
	0x6d, 0x62, 0x65, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x72, 0x61, 0x63,
	0x6b, 0x69, 0x6e, 0x67, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x22, 0x2b, 0x0a, 0x05, 0x49, 0x74,
	0x65, 0x6d, 0x73, 0x12, 0x22, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74, 0x65, 0x6d,
	0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x22, 0xbe, 0x01, 0x0a, 0x0b, 0x4e, 0x65, 0x77, 0x4f,
	0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x74, 0x65, 0x6d, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x74, 0x65, 0x6d, 0x49, 0x64,
	0x12, 0x23, 0x0a, 0x04, 0x72, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f,
	0x2e, 0x69, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f, 0x72, 0x79, 0x2e, 0x52, 0x61, 0x74, 0x65, 0x52,
	0x04, 0x72, 0x61, 0x74, 0x65, 0x12, 0x27, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x4f, 0x72,
	0x64, 0x65, 0x72, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x12, 0x14,
	0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65,
	0x6d, 0x61, 0x69, 0x6c, 0x12, 0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x19, 0x0a,
	0x08, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x63, 0x68, 0x69, 0x6c, 0x64, 0x49, 0x64, 0x22, 0x8d, 0x02, 0x0a, 0x0b, 0x50, 0x61, 0x79,
	0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x12, 0x19, 0x0a, 0x08, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x49, 0x64, 0x12, 0x36, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x72, 0x67, 0x65, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x50, 0x61,
	0x79, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x2e, 0x50, 0x61, 0x79, 0x53, 0x70, 0x6c,
	0x69, 0x74, 0x52, 0x07, 0x63, 0x68, 0x61, 0x72, 0x67, 0x65, 0x73, 0x1a, 0xaa, 0x01, 0x0a, 0x08,
	0x50, 0x61, 0x79, 0x53, 0x70, 0x6c, 0x69, 0x74, 0x12, 0x30, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x70, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x49, 0x64,
	0x52, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x12, 0x19, 0x0a, 0x07, 0x75, 0x73,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x06, 0x75,
	0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x04, 0x63, 0x61, 0x72, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x43,
	0x61, 0x72, 0x64, 0x48, 0x00, 0x52, 0x04, 0x63, 0x61, 0x72, 0x64, 0x12, 0x21, 0x0a, 0x0b, 0x70,
	0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x72, 0x65, 0x66, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x0a, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x66, 0x42, 0x08,
	0x0a, 0x06, 0x43, 0x68, 0x61, 0x72, 0x67, 0x65, 0x32, 0xef, 0x02, 0x0a, 0x06, 0x4f, 0x72, 0x64,
	0x65, 0x72, 0x73, 0x12, 0x48, 0x0a, 0x08, 0x4e, 0x65, 0x77, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12,
	0x13, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x4e, 0x65, 0x77, 0x4f, 0x72, 0x64, 0x65,
	0x72, 0x52, 0x65, 0x71, 0x1a, 0x0c, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74,
	0x65, 0x6d, 0x22, 0x19, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x13, 0x22, 0x0e, 0x2f, 0x6f, 0x72, 0x64,
	0x65, 0x72, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6e, 0x65, 0x77, 0x3a, 0x01, 0x2a, 0x12, 0x48, 0x0a,
	0x08, 0x50, 0x61, 0x79, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x13, 0x2e, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x73, 0x2e, 0x50, 0x61, 0x79, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x1a, 0x0c,
	0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74, 0x65, 0x6d, 0x22, 0x19, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x13, 0x22, 0x0e, 0x2f, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2f, 0x76, 0x31,
	0x2f, 0x70, 0x61, 0x79, 0x3a, 0x01, 0x2a, 0x12, 0x48, 0x0a, 0x0b, 0x52, 0x65, 0x74, 0x75, 0x72,
	0x6e, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x0a, 0x2e, 0x6d, 0x73, 0x67, 0x73, 0x2e, 0x55, 0x55,
	0x49, 0x44, 0x1a, 0x0c, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74, 0x65, 0x6d,
	0x22, 0x1f, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x19, 0x12, 0x17, 0x2f, 0x6f, 0x72, 0x64, 0x65, 0x72,
	0x73, 0x2f, 0x76, 0x31, 0x2f, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x2f, 0x7b, 0x76, 0x61, 0x6c,
	0x7d, 0x12, 0x39, 0x0a, 0x03, 0x47, 0x65, 0x74, 0x12, 0x0b, 0x2e, 0x6d, 0x73, 0x67, 0x73, 0x2e,
	0x55, 0x55, 0x49, 0x44, 0x73, 0x1a, 0x0d, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49,
	0x74, 0x65, 0x6d, 0x73, 0x22, 0x16, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x10, 0x12, 0x0e, 0x2f, 0x6f,
	0x72, 0x64, 0x65, 0x72, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x12, 0x4c, 0x0a, 0x04,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x0d, 0x2e, 0x6d, 0x73, 0x67, 0x73, 0x2e, 0x4c, 0x69, 0x73, 0x74,
	0x52, 0x65, 0x71, 0x1a, 0x0d, 0x2e, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x74, 0x65,
	0x6d, 0x73, 0x22, 0x26, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x20, 0x12, 0x1e, 0x2f, 0x6f, 0x72, 0x64,
	0x65, 0x72, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x2f, 0x7b, 0x70, 0x61, 0x67,
	0x65, 0x7d, 0x2f, 0x7b, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x7d, 0x42, 0x1e, 0x5a, 0x1c, 0x67, 0x69,
	0x74, 0x6c, 0x61, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x2f, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_orders_proto_rawDescOnce sync.Once
	file_orders_proto_rawDescData = file_orders_proto_rawDesc
)

func file_orders_proto_rawDescGZIP() []byte {
	file_orders_proto_rawDescOnce.Do(func() {
		file_orders_proto_rawDescData = protoimpl.X.CompressGZIP(file_orders_proto_rawDescData)
	})
	return file_orders_proto_rawDescData
}

var file_orders_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_orders_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_orders_proto_goTypes = []interface{}{
	(Item_OrderStatus)(0),        // 0: orders.Item.OrderStatus
	(OrderItem_Type)(0),          // 1: orders.OrderItem.Type
	(*Item)(nil),                 // 2: orders.Item
	(*OrderItem)(nil),            // 3: orders.OrderItem
	(*ShippingInfo)(nil),         // 4: orders.ShippingInfo
	(*Items)(nil),                // 5: orders.Items
	(*NewOrderReq)(nil),          // 6: orders.NewOrderReq
	(*PayOrderReq)(nil),          // 7: orders.PayOrderReq
	nil,                          // 8: orders.Item.MetaEntry
	(*PayOrderReq_PaySplit)(nil), // 9: orders.PayOrderReq.PaySplit
	(pb.Currency)(0),             // 10: payments.Currency
	(*pb1.LongAddress)(nil),      // 11: msgs.LongAddress
	(*pb2.Rate)(nil),             // 12: inventory.Rate
	(pb.ProviderId)(0),           // 13: payments.ProviderId
	(*pb.Card)(nil),              // 14: payments.Card
	(*pb1.UUID)(nil),             // 15: msgs.UUID
	(*pb1.UUIDs)(nil),            // 16: msgs.UUIDs
	(*pb1.ListReq)(nil),          // 17: msgs.ListReq
}
var file_orders_proto_depIdxs = []int32{
	10, // 0: orders.Item.currency:type_name -> payments.Currency
	0,  // 1: orders.Item.status:type_name -> orders.Item.OrderStatus
	3,  // 2: orders.Item.items:type_name -> orders.OrderItem
	8,  // 3: orders.Item.meta:type_name -> orders.Item.MetaEntry
	4,  // 4: orders.Item.shipping:type_name -> orders.ShippingInfo
	1,  // 5: orders.OrderItem.type:type_name -> orders.OrderItem.Type
	10, // 6: orders.OrderItem.currency:type_name -> payments.Currency
	11, // 7: orders.ShippingInfo.address:type_name -> msgs.LongAddress
	2,  // 8: orders.Items.items:type_name -> orders.Item
	12, // 9: orders.NewOrderReq.rate:type_name -> inventory.Rate
	3,  // 10: orders.NewOrderReq.items:type_name -> orders.OrderItem
	9,  // 11: orders.PayOrderReq.charges:type_name -> orders.PayOrderReq.PaySplit
	13, // 12: orders.PayOrderReq.PaySplit.provider:type_name -> payments.ProviderId
	14, // 13: orders.PayOrderReq.PaySplit.card:type_name -> payments.Card
	6,  // 14: orders.Orders.NewOrder:input_type -> orders.NewOrderReq
	7,  // 15: orders.Orders.PayOrder:input_type -> orders.PayOrderReq
	15, // 16: orders.Orders.ReturnOrder:input_type -> msgs.UUID
	16, // 17: orders.Orders.Get:input_type -> msgs.UUIDs
	17, // 18: orders.Orders.List:input_type -> msgs.ListReq
	2,  // 19: orders.Orders.NewOrder:output_type -> orders.Item
	2,  // 20: orders.Orders.PayOrder:output_type -> orders.Item
	2,  // 21: orders.Orders.ReturnOrder:output_type -> orders.Item
	5,  // 22: orders.Orders.Get:output_type -> orders.Items
	5,  // 23: orders.Orders.List:output_type -> orders.Items
	19, // [19:24] is the sub-list for method output_type
	14, // [14:19] is the sub-list for method input_type
	14, // [14:14] is the sub-list for extension type_name
	14, // [14:14] is the sub-list for extension extendee
	0,  // [0:14] is the sub-list for field type_name
}

func init() { file_orders_proto_init() }
func file_orders_proto_init() {
	if File_orders_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_orders_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Item); i {
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
		file_orders_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OrderItem); i {
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
		file_orders_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShippingInfo); i {
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
		file_orders_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Items); i {
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
		file_orders_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NewOrderReq); i {
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
		file_orders_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PayOrderReq); i {
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
		file_orders_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PayOrderReq_PaySplit); i {
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
	file_orders_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*PayOrderReq_PaySplit_UserId)(nil),
		(*PayOrderReq_PaySplit_Card)(nil),
		(*PayOrderReq_PaySplit_PaymentRef)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_orders_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_orders_proto_goTypes,
		DependencyIndexes: file_orders_proto_depIdxs,
		EnumInfos:         file_orders_proto_enumTypes,
		MessageInfos:      file_orders_proto_msgTypes,
	}.Build()
	File_orders_proto = out.File
	file_orders_proto_rawDesc = nil
	file_orders_proto_goTypes = nil
	file_orders_proto_depIdxs = nil
}
