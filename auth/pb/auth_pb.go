package pb

//go:generate protoc -I$GOPATH/pkg/mod/github.com/grpc-ecosystem/grpc-gateway/v2@v2.0.1/third_party/googleapis/ -I. --go_out=. --go_opt=paths=source_relative auth.proto
//go:generate protoc -I$GOPATH/pkg/mod/github.com/grpc-ecosystem/grpc-gateway/v2@v2.0.1/third_party/googleapis/ -I. --go-grpc_out=. --go-grpc_opt=paths=source_relative auth.proto
//go:generate protoc -I$GOPATH/pkg/mod/github.com/grpc-ecosystem/grpc-gateway/v2@v2.0.1/third_party/googleapis/ -I. --grpc-gateway_out=logtostderr=true,paths=source_relative:. auth.proto
