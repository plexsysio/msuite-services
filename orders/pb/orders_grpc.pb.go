// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package pb

import (
	context "context"
	pb "github.com/aloknerurkar/msuite-services/common/pb"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// OrdersClient is the client API for Orders service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type OrdersClient interface {
	NewOrder(ctx context.Context, in *NewOrderReq, opts ...grpc.CallOption) (*Item, error)
	PayOrder(ctx context.Context, in *PayOrderReq, opts ...grpc.CallOption) (*Item, error)
	ReturnOrder(ctx context.Context, in *pb.UUID, opts ...grpc.CallOption) (*Item, error)
	Get(ctx context.Context, in *pb.UUIDs, opts ...grpc.CallOption) (*Items, error)
	List(ctx context.Context, in *pb.ListReq, opts ...grpc.CallOption) (*Items, error)
}

type ordersClient struct {
	cc grpc.ClientConnInterface
}

func NewOrdersClient(cc grpc.ClientConnInterface) OrdersClient {
	return &ordersClient{cc}
}

func (c *ordersClient) NewOrder(ctx context.Context, in *NewOrderReq, opts ...grpc.CallOption) (*Item, error) {
	out := new(Item)
	err := c.cc.Invoke(ctx, "/orders.Orders/NewOrder", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ordersClient) PayOrder(ctx context.Context, in *PayOrderReq, opts ...grpc.CallOption) (*Item, error) {
	out := new(Item)
	err := c.cc.Invoke(ctx, "/orders.Orders/PayOrder", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ordersClient) ReturnOrder(ctx context.Context, in *pb.UUID, opts ...grpc.CallOption) (*Item, error) {
	out := new(Item)
	err := c.cc.Invoke(ctx, "/orders.Orders/ReturnOrder", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ordersClient) Get(ctx context.Context, in *pb.UUIDs, opts ...grpc.CallOption) (*Items, error) {
	out := new(Items)
	err := c.cc.Invoke(ctx, "/orders.Orders/Get", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *ordersClient) List(ctx context.Context, in *pb.ListReq, opts ...grpc.CallOption) (*Items, error) {
	out := new(Items)
	err := c.cc.Invoke(ctx, "/orders.Orders/List", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OrdersServer is the server API for Orders service.
// All implementations must embed UnimplementedOrdersServer
// for forward compatibility
type OrdersServer interface {
	NewOrder(context.Context, *NewOrderReq) (*Item, error)
	PayOrder(context.Context, *PayOrderReq) (*Item, error)
	ReturnOrder(context.Context, *pb.UUID) (*Item, error)
	Get(context.Context, *pb.UUIDs) (*Items, error)
	List(context.Context, *pb.ListReq) (*Items, error)
	mustEmbedUnimplementedOrdersServer()
}

// UnimplementedOrdersServer must be embedded to have forward compatible implementations.
type UnimplementedOrdersServer struct {
}

func (UnimplementedOrdersServer) NewOrder(context.Context, *NewOrderReq) (*Item, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NewOrder not implemented")
}
func (UnimplementedOrdersServer) PayOrder(context.Context, *PayOrderReq) (*Item, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PayOrder not implemented")
}
func (UnimplementedOrdersServer) ReturnOrder(context.Context, *pb.UUID) (*Item, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReturnOrder not implemented")
}
func (UnimplementedOrdersServer) Get(context.Context, *pb.UUIDs) (*Items, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Get not implemented")
}
func (UnimplementedOrdersServer) List(context.Context, *pb.ListReq) (*Items, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedOrdersServer) mustEmbedUnimplementedOrdersServer() {}

// UnsafeOrdersServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to OrdersServer will
// result in compilation errors.
type UnsafeOrdersServer interface {
	mustEmbedUnimplementedOrdersServer()
}

func RegisterOrdersServer(s grpc.ServiceRegistrar, srv OrdersServer) {
	s.RegisterService(&Orders_ServiceDesc, srv)
}

func _Orders_NewOrder_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewOrderReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrdersServer).NewOrder(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/orders.Orders/NewOrder",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrdersServer).NewOrder(ctx, req.(*NewOrderReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Orders_PayOrder_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PayOrderReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrdersServer).PayOrder(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/orders.Orders/PayOrder",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrdersServer).PayOrder(ctx, req.(*PayOrderReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _Orders_ReturnOrder_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(pb.UUID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrdersServer).ReturnOrder(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/orders.Orders/ReturnOrder",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrdersServer).ReturnOrder(ctx, req.(*pb.UUID))
	}
	return interceptor(ctx, in, info, handler)
}

func _Orders_Get_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(pb.UUIDs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrdersServer).Get(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/orders.Orders/Get",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrdersServer).Get(ctx, req.(*pb.UUIDs))
	}
	return interceptor(ctx, in, info, handler)
}

func _Orders_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(pb.ListReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrdersServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/orders.Orders/List",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrdersServer).List(ctx, req.(*pb.ListReq))
	}
	return interceptor(ctx, in, info, handler)
}

// Orders_ServiceDesc is the grpc.ServiceDesc for Orders service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Orders_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "orders.Orders",
	HandlerType: (*OrdersServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "NewOrder",
			Handler:    _Orders_NewOrder_Handler,
		},
		{
			MethodName: "PayOrder",
			Handler:    _Orders_PayOrder_Handler,
		},
		{
			MethodName: "ReturnOrder",
			Handler:    _Orders_ReturnOrder_Handler,
		},
		{
			MethodName: "Get",
			Handler:    _Orders_Get_Handler,
		},
		{
			MethodName: "List",
			Handler:    _Orders_List_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "orders.proto",
}