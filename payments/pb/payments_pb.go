package pb

//go:generate protoc -I$GOPATH/pkg/mod/google.golang.org/genproto@v0.0.0-20210302174412-5ede27ff9881/googleapis/ -I. --go_out=. --go_opt=paths=source_relative payments.proto
//go:generate protoc -I$GOPATH/pkg/mod/google.golang.org/genproto@v0.0.0-20210302174412-5ede27ff9881/googleapis/ -I. --go-grpc_out=. --go-grpc_opt=paths=source_relative payments.proto
