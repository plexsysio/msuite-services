module github.com/plexsysio/msuite-services

go 1.14

require (
	github.com/SWRMLabs/ss-store v0.0.4
	github.com/anachronistic/apns v0.0.0-20151129191123-91763352f7bf
	github.com/golang/protobuf v1.4.3
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.3.0
	github.com/hgfischer/go-otp v1.0.0
	github.com/hsanjuan/ipfs-lite v1.1.18
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-log/v2 v2.1.1
	github.com/maddevsio/fcm v1.0.4
	github.com/messagebird/go-rest-api v5.3.0+incompatible
	github.com/plexsysio/dLocker v0.0.2
	github.com/plexsysio/go-msuite v0.0.1
	github.com/plexsysio/go-radix v0.0.2
	github.com/razorpay/razorpay-go v0.0.0-20201204135735-096d3be7d2df
	go.uber.org/fx v1.13.1 // indirect
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	google.golang.org/genproto v0.0.0-20210302174412-5ede27ff9881
	google.golang.org/grpc v1.36.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.25.1-0.20201208041424-160c7477e0e8
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
)

replace github.com/plexsysio/go-msuite => ../go-msuite
