// Module path is a PLACEHOLDER pending the open-source home (D36).
// Change it once, before first release, then never again — a Go module path
// change is a breaking change for every importer.
module github.com/fullstorydev/sekizui

go 1.25.0

toolchain go1.26.7

require (
	golang.org/x/tools v0.49.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	sigs.k8s.io/yaml v1.6.0
)

require (
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
