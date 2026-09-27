// The gRPC contract of TrustMeBroID, published as its own module so consumers
// pull the generated code and its two dependencies instead of the whole
// service with its database, cache and test machinery.
//
// Tag releases as api/vX.Y.Z; consumers then require it as vX.Y.Z.
module github.com/synnfluxx/TrustMeBroID/api

go 1.25.7

require (
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
)
