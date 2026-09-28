package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/fullstorydev/sekizui/internal/spine"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// TLSConfig is the material a listener needs to prove itself and to demand
// proof in return.
type TLSConfig struct {
	CertFile string
	KeyFile  string

	// ClientCAFile is the pool that client certificates are verified against.
	//
	// REQUIRED, WITH NO "SKIP VERIFY" ESCAPE. The whole identity model rests on
	// the caller being PROVEN rather than claimed (identity.CallerFromContext),
	// and a server that accepts unverified client certificates converts every
	// grant in the system into an honour-system request. There is deliberately
	// no flag to turn this off, because the flag would eventually be set.
	ClientCAFile string
}

// Listener serves the gRPC surface over mTLS.
//
// A spine.Component, so binding participates in the lifecycle rather than
// happening somewhere in main: Validate loads and checks the TLS material before
// ANYTHING starts, Start binds and serves, Stop drains within the budget.
//
// WHY VALIDATE LOADS THE CERTIFICATES: a missing or malformed key discovered at
// Start is a process that has already begun unwinding other components. Loading
// during validation means bad TLS material fails while nothing is running — the
// same reason config.Loader loads in Validate.
type Listener struct {
	addr  string
	tls   TLSConfig
	build func(context.Context) (*Server, error)
	log   *slog.Logger

	mu       sync.Mutex
	srv      *Server
	grpcSrv  *grpc.Server
	ln       net.Listener
	creds    credentials.TransportCredentials
	serveErr chan error
}

// NewListener returns a Listener. Nothing is bound and no file is read until
// Validate runs.
//
// TAKES A BUILDER, NOT A SERVER, and the reason is an ordering constraint worth
// stating. The enforcement stack — policy, resolver, catalog, drivers — is
// constructed FROM the validated configuration document, which does not exist
// until config.Loader.Validate has run. spine calls every Validator in
// registration order within a single phase, so registering config first and this
// second means the document is ready by the time `build` is called.
//
// The alternative — validating config outside spine, then constructing, then
// registering — would move this component's validation out of the phase where
// spine performs its CAPABILITY checks, so the BackgroundWork requirement below
// would silently stop being enforced. Deferring construction is the cheaper
// price.
func NewListener(addr string, tlsCfg TLSConfig, build func(context.Context) (*Server, error),
	log *slog.Logger) *Listener {

	return &Listener{addr: addr, tls: tlsCfg, build: build, log: log,
		serveErr: make(chan error, 1)}
}

// Name identifies this component in the init ledger and readiness output.
func (l *Listener) Name() string { return "gateway:serve" }

// Validate loads the TLS material and builds the credentials, before anything
// starts.
func (l *Listener) Validate(ctx context.Context) error {
	const op = "gateway.Listener.Validate"

	if l.tls.CertFile == "" || l.tls.KeyFile == "" {
		return fault.New(fault.KindConfig, op,
			"the gateway needs a server certificate and key; pass -tls-cert and -tls-key, "+
				"or run `make dev-certs` to generate a local set")
	}
	if l.tls.ClientCAFile == "" {
		return fault.New(fault.KindConfig, op,
			"the gateway needs a client CA to verify callers against; pass -tls-client-ca. "+
				"There is no way to disable client verification: every grant in the system "+
				"assumes the caller is proven rather than claimed")
	}

	cert, err := tls.LoadX509KeyPair(l.tls.CertFile, l.tls.KeyFile)
	if err != nil {
		return fault.Wrap(fault.KindConfig, op, "loading the server certificate", err)
	}

	pem, err := os.ReadFile(l.tls.ClientCAFile)
	if err != nil {
		return fault.Wrap(fault.KindConfig, op, "reading the client CA", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		// AppendCertsFromPEM reports failure by returning false and nothing
		// else, so a file of the wrong kind — a private key, a DER blob, an
		// error page — produces an empty pool that rejects every caller with a
		// TLS error far from the cause.
		return fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%s contains no PEM certificates; an empty pool would reject every caller "+
				"with a handshake failure that names no cause", l.tls.ClientCAFile))
	}

	// The enforcement stack, built from the document config.Loader validated a
	// moment ago. Failing here means a process that never bound a port, which is
	// the whole point of building it during validation rather than at Start.
	// THE BOOT CONTEXT IS PASSED IN, because building the stack does I/O now:
	// §4.7.7's tier-2 ambient probe is a bounded HTTP call, and a boot that is
	// cancelled should stop probing rather than finish on its own schedule.
	srv, err := l.build(ctx)
	if err != nil {
		return err
	}
	if srv == nil {
		return fault.New(fault.KindInternal, op,
			"the enforcement stack builder returned no server")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.srv = srv
	l.creds = credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		// RequireAndVerifyClientCert, not RequireAnyClientCert: the weaker
		// setting accepts a self-signed certificate carrying any principal name
		// the holder chose, which is impersonation with extra steps.
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	})
	return nil
}

// Start binds and serves. Returns once the listener is bound, not when serving
// finishes — the Component contract's "operational, not finished".
func (l *Listener) Start(ctx context.Context) error {
	const op = "gateway.Listener.Start"

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.creds == nil || l.srv == nil {
		return fault.New(fault.KindInternal, op,
			"started without a validated TLS configuration and enforcement stack; "+
				"Validate must run first")
	}

	// Bind before serving so a port clash fails startup, rather than surfacing
	// later as an unexplained absence of traffic.
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fault.Wrap(fault.KindConfig, op, "binding "+l.addr, err)
	}
	l.ln = ln

	// **CEILINGS ON WHAT A CALLER MAY SEND, AS DEFENCE IN DEPTH (D215).** The
	// field-level bounds in `identity.Verify` and `enforceOnce` are the real
	// controls — they know what each field is FOR — and these two are the
	// backstop for the fields nobody has thought about yet.
	//
	// **`MaxHeaderListSize` IS THE ONE THAT MATTERS, because gRPC's default for
	// it is enormous** (megabytes) and headers are the path that bypasses
	// `MaxRecvMsgSize` entirely. 64 KiB is far past every header this service
	// reads — a subject, a trace id, and gRPC's own — and small enough that the
	// metadata of a single request cannot be a disk-amplification payload.
	l.grpcSrv = grpc.NewServer(
		grpc.Creds(l.creds),
		grpc.MaxHeaderListSize(64<<10),
		grpc.MaxRecvMsgSize(4<<20),
	)
	sekizuiv1.RegisterGatewayServiceServer(l.grpcSrv, l.srv)

	go func(s *grpc.Server, ln net.Listener) {
		if err := s.Serve(ln); err != nil {
			// GracefulStop closes the listener, which makes Serve return
			// ErrServerStopped. That is the expected path out, not a failure.
			l.serveErr <- err
		}
	}(l.grpcSrv, ln)

	l.log.Info("gateway listening", "addr", ln.Addr().String(), "mtls", true)
	return nil
}

// Stop drains in-flight RPCs, then forces the rest when the budget runs out.
//
// GracefulStop blocks until every in-flight RPC completes, with no timeout of
// its own. Unbounded, a single slow outbound call would hold the process past
// the platform's grace period and the container would be killed mid-drain —
// which is worse than stopping deliberately, because it can truncate an audit
// write. So the caller's context bounds it and Stop() forces the remainder.
//
// Idempotent, as the Component contract requires.
func (l *Listener) Stop(ctx context.Context) error {
	l.mu.Lock()
	srv := l.grpcSrv
	l.grpcSrv = nil
	l.mu.Unlock()

	if srv == nil {
		return nil
	}

	drained := make(chan struct{})
	go func() { srv.GracefulStop(); close(drained) }()

	select {
	case <-drained:
		l.log.Info("gateway drained cleanly")
	case <-ctx.Done():
		l.log.Warn("drain budget exhausted; forcing remaining connections closed")
		srv.Stop()
		<-drained
	}
	return nil
}

// Needs declares that this component wants background work.
//
// spine refuses at boot where the profile cannot offer it, naming this
// component — rather than serving on a platform that freezes the process
// between requests, which would stall in-flight RPCs at arbitrary points.
//
// SATISFIES spine.CapabilityAware STRUCTURALLY, which is exactly why
// TestListenerSatisfiesSpineInterfaces exists: an optional interface is matched
// by shape, so getting the signature wrong does not fail to compile — the method
// simply never gets called and the requirement silently stops being declared.
// The first draft of this returned three bools and nothing complained.
func (l *Listener) Needs() spine.Needs {
	return spine.Needs{BackgroundWork: true}
}

// Health reports whether the listener is still serving.
//
// Distinct from having started: a Serve error after startup leaves a process
// that is alive, passing /healthz, and accepting nothing.
func (l *Listener) Health(ctx context.Context) error {
	select {
	case err := <-l.serveErr:
		// Put it back: Health may be called repeatedly, and a one-shot read
		// would report healthy from the second probe onwards.
		l.serveErr <- err
		return fault.Wrap(fault.KindUnavailable, "gateway.Listener.Health",
			"the gRPC server stopped serving", err)
	default:
		return nil
	}
}

// Addr returns the bound address, which differs from the requested one when
// the port was :0. Used by tests.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}
