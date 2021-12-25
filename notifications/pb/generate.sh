#!/bin/sh

sh -c "protoc \
    -I ../../ \
    -I . \
    -I \"$(go list -f '{{ .Dir }}' -m github.com/grpc-ecosystem/grpc-gateway/v2)/\" \
    -I \"$(go list -f '{{ .Dir }}' -m github.com/mwitkow/go-proto-validators)/\" \
    --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    --grpc-gateway_out=logtostderr=true,paths=source_relative:. \
    --govalidators_out=paths=source_relative:. \
    --openapiv2_out=../openapiv2/OpenAPI \
    notifications.proto"
