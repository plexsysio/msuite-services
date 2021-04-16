package pb

//go:generate protoc -I../../ -I. --go_out=. --go_opt=paths=source_relative orders.proto
//go:generate protoc -I../../ -I. --go-grpc_out=. --go-grpc_opt=paths=source_relative orders.proto
//go:generate protoc -I../../ -I. --grpc-gateway_out=logtostderr=true,paths=source_relative:. orders.proto
