package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/fullstorydev/sekizui/internal/devcert"
	"github.com/fullstorydev/sekizui/internal/spine"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// served is a Listener bound to a real port with real TLS material.
//
// NO bufconn, NO in-process shortcut. The point of these tests is precisely the
// part the acceptance run synthesises: a genuine TLS 1.3 handshake, genuine
// client-certificate verification, and a SPIFFE SAN parsed out of a certificate
// that a CA actually signed. An in-memory transport would skip all three and
// prove only what is already proven elsewhere.
type served struct {
	lis    *Listener
	bundle *devcert.Bundle
	addr   string
}

func serve(t *testing.T) *served {
	t.Helper()

	bundle, err := devcert.Generate(t.TempDir(), []string{"agent:triage", "mesh:primary"})
	if err != nil {
		t.Fatalf("devcert: %v", err)
	}

	h := newHarness(t)
	lis := NewListener("127.0.0.1:0", TLSConfig{
		CertFile:     bundle.ServerCert,
		KeyFile:      bundle.ServerKey,
		ClientCAFile: bundle.CACertFile,
	}, func(context.Context) (*Server, error) { return h.srv, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx := context.Background()
	if err := lis.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := lis.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lis.Stop(stopCtx)
	})

	return &served{lis: lis, bundle: bundle, addr: lis.Addr()}
}

// dial connects as the named principal, using its issued certificate.
func (s *served) dial(t *testing.T, principal string) sekizuiv1.GatewayServiceClient {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(s.bundle.ClientCerts[principal], s.bundle.ClientKeys[principal])
	if err != nil {
		t.Fatalf("loading client material for %s: %v", principal, err)
	}
	return s.dialWith(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      s.caPool(t),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})
}

func (s *served) dialWith(t *testing.T, cfg *tls.Config) sekizuiv1.GatewayServiceClient {
	t.Helper()

	conn, err := grpc.NewClient(s.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return sekizuiv1.NewGatewayServiceClient(conn)
}

func (s *served) caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(s.bundle.CACertFile)
	if err != nil {
		t.Fatalf("reading CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("CA file contained no certificates")
	}
	return pool
}

func executeReq(action, target string, args map[string]any) *sekizuiv1.ExecuteRequest {
	a, _ := structpb.NewStruct(args)
	return &sekizuiv1.ExecuteRequest{Command: &sekizuiv1.Command{
		Action: action, TargetRef: target, Args: a, IdempotencyKey: "serve-" + action,
	}}
}

// TestARealCommandTraversesARealSocket is P0 exit criterion 1 over the wire —
// the half the acceptance run cannot prove, because it constructs the peer.
func TestARealCommandTraversesARealSocket(t *testing.T) {
	s := serve(t)
	client := s.dial(t, "agent:triage")

	resp, err := client.Execute(context.Background(),
		executeReq("kata.create_issue", "kata:alpha", map[string]any{
			"project": "PROJ", "title": "over the wire",
		}))
	if err != nil {
		t.Fatalf("Execute over mTLS: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_OK {
		t.Fatalf("status = %v, reason %q", got, resp.GetResult().GetReason())
	}
	if resp.GetResult().GetDecisionId() == "" {
		t.Error("no decision id returned; the command was not audited")
	}
}

// TestSpiffeIdentitySurvivesTheHandshake — the principal must come out of the
// certificate the CA signed, not from anything the client could set.
//
// Proven via a DENIAL that names the principal: agent:triage is not granted
// kata.comment, so the refusal reason states who was refused. That reads the
// server's own conclusion about identity rather than trusting the client's.
func TestSpiffeIdentitySurvivesTheHandshake(t *testing.T) {
	s := serve(t)
	client := s.dial(t, "agent:triage")

	resp, err := client.Execute(context.Background(),
		executeReq("kata.comment", "kata:alpha", nil))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := resp.GetResult().GetStatus(); got != sekizuiv1.Status_STATUS_DENIED {
		t.Fatalf("status = %v, want DENIED", got)
	}
	if reason := resp.GetResult().GetReason(); !strings.Contains(reason, "agent:triage") {
		t.Errorf("the refusal does not name the principal from the SPIFFE SAN: %q", reason)
	}
}

// TestAClientWithNoCertificateIsRejected — RequireAndVerifyClientCert must
// actually be in force. Without it every grant becomes an honour-system request.
func TestAClientWithNoCertificateIsRejected(t *testing.T) {
	s := serve(t)
	client := s.dialWith(t, &tls.Config{
		RootCAs: s.caPool(t), ServerName: "localhost", MinVersion: tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.Execute(ctx, executeReq("kata.create_issue", "kata:alpha", nil)); err == nil {
		t.Fatal("a client presenting no certificate executed a command")
	}
}

// TestAClientFromAnotherCAIsRejected is the attack the pool exists to stop: a
// well-formed certificate carrying any principal name the holder chose.
//
// A second independently generated CA stands in for "an attacker's own PKI".
func TestAClientFromAnotherCAIsRejected(t *testing.T) {
	s := serve(t)

	rogue, err := devcert.Generate(t.TempDir(), []string{"agent:triage"})
	if err != nil {
		t.Fatalf("rogue CA: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(rogue.ClientCerts["agent:triage"], rogue.ClientKeys["agent:triage"])
	if err != nil {
		t.Fatalf("rogue material: %v", err)
	}

	client := s.dialWith(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      s.caPool(t), // trusts the REAL server, so only the client half is rogue
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.Execute(ctx, executeReq("kata.create_issue", "kata:alpha",
		map[string]any{"project": "PROJ"})); err == nil {
		t.Fatal("a certificate signed by an untrusted CA was accepted; any holder of " +
			"any PKI could then claim to be any principal")
	}
}

// TestValidateRefusesMissingTLSMaterial — a gateway that starts without client
// verification is worse than one that refuses to start.
func TestValidateRefusesMissingTLSMaterial(t *testing.T) {
	h := newHarness(t)
	bundle, err := devcert.Generate(t.TempDir(), []string{"agent:triage"})
	if err != nil {
		t.Fatalf("devcert: %v", err)
	}
	build := func(context.Context) (*Server, error) { return h.srv, nil }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for name, cfg := range map[string]TLSConfig{
		"no certificate": {KeyFile: bundle.ServerKey, ClientCAFile: bundle.CACertFile},
		"no key":         {CertFile: bundle.ServerCert, ClientCAFile: bundle.CACertFile},
		"no client CA":   {CertFile: bundle.ServerCert, KeyFile: bundle.ServerKey},
	} {
		t.Run(name, func(t *testing.T) {
			lis := NewListener("127.0.0.1:0", cfg, build, log)
			if err := lis.Validate(context.Background()); err == nil {
				t.Fatal("validation passed with incomplete TLS material")
			}
		})
	}
}

// TestValidateRefusesACAFileWithNoCertificates — AppendCertsFromPEM reports
// failure by returning false and nothing else, so a wrong-but-present file would
// otherwise produce an empty pool that rejects every caller with a handshake
// error naming no cause.
func TestValidateRefusesACAFileWithNoCertificates(t *testing.T) {
	h := newHarness(t)
	bundle, err := devcert.Generate(t.TempDir(), []string{"agent:triage"})
	if err != nil {
		t.Fatalf("devcert: %v", err)
	}

	junk := t.TempDir() + "/not-a-ca.pem"
	if err := os.WriteFile(junk, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("writing junk: %v", err)
	}

	lis := NewListener("127.0.0.1:0", TLSConfig{
		CertFile: bundle.ServerCert, KeyFile: bundle.ServerKey, ClientCAFile: junk,
	}, func(context.Context) (*Server, error) { return h.srv, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	err = lis.Validate(context.Background())
	if err == nil {
		t.Fatal("a CA file containing no certificates was accepted")
	}
	if !strings.Contains(err.Error(), "no PEM certificates") {
		t.Errorf("the error does not explain the cause: %v", err)
	}
}

// TestStartWithoutValidateIsRefused — Start must not bind with no verified TLS
// material, since the failure would be a serving port with no identity model.
func TestStartWithoutValidateIsRefused(t *testing.T) {
	h := newHarness(t)
	lis := NewListener("127.0.0.1:0", TLSConfig{},
		func(context.Context) (*Server, error) { return h.srv, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := lis.Start(context.Background()); err == nil {
		t.Fatal("Start bound a port without validated TLS material")
	}
}

// TestStopIsIdempotent — the Component contract requires it, and shutdown races
// plus leader-election churn both call Stop more than once.
func TestStopIsIdempotent(t *testing.T) {
	s := serve(t)
	ctx := context.Background()
	for i := range 3 {
		if err := s.lis.Stop(ctx); err != nil {
			t.Fatalf("Stop call %d: %v", i+1, err)
		}
	}
}

// TestListenerSatisfiesSpineInterfaces pins the OPTIONAL interfaces locally.
//
// Go matches these structurally, so a wrong signature does not fail to compile —
// the method simply stops being called and the declaration silently disappears.
// The first draft of Needs() returned three bools instead of spine.Needs and
// nothing complained; this is what would have caught it.
func TestListenerSatisfiesSpineInterfaces(t *testing.T) {
	var l any = &Listener{}

	if _, ok := l.(spine.Component); !ok {
		t.Error("*Listener is not a spine.Component")
	}
	if _, ok := l.(spine.Validator); !ok {
		t.Error("*Listener is not a spine.Validator; TLS material would load at Start")
	}
	if _, ok := l.(spine.HealthReporter); !ok {
		t.Error("*Listener is not a spine.HealthReporter; a server that stopped serving " +
			"would keep passing readiness")
	}
	ca, ok := l.(spine.CapabilityAware)
	if !ok {
		t.Fatal("*Listener is not spine.CapabilityAware; its BackgroundWork requirement " +
			"would silently stop being checked at boot")
	}
	if !ca.Needs().BackgroundWork {
		t.Error("the listener no longer declares that it needs background work")
	}
}

// TestHealthReportsAServeFailureRepeatedly — a one-shot read of the error
// channel would report healthy from the second probe onwards, which is exactly
// the window a load balancer uses to decide the instance recovered.
func TestHealthReportsAServeFailureRepeatedly(t *testing.T) {
	lis := NewListener("127.0.0.1:0", TLSConfig{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	lis.serveErr <- io.ErrUnexpectedEOF

	for i := range 3 {
		if err := lis.Health(context.Background()); err == nil {
			t.Fatalf("probe %d reported healthy after a serve failure", i+1)
		}
	}
}

// TestConcurrentCommandsOverOneConnection is the transport half of the
// concurrency proof: many goroutines, one connection, every command
// independently governed.
//
// gRPC multiplexes concurrent RPCs over a single HTTP/2 connection, so this is
// the real shape of an agent fleet — not N clients, but one mesh issuing many
// commands at once. Run under -race by `make verify`.
//
// SHEDDING IS A CORRECT OUTCOME, NOT A FAILURE. §7.1 sheds load rather than
// queueing it, so firing more commands than the admission limit MUST refuse
// some; the first draft of this test treated that as a bug and was wrong. What
// concurrency has to guarantee is that every command reaches a definite,
// attributable end:
//
//	admitted -> a unique decision id
//	shed     -> ResourceExhausted, and nothing written
//	neither  -> a defect
//
// The uniqueness check is the sharp one. A shared counter without
// synchronisation produces duplicates here, and two actions sharing a decision
// id are indistinguishable in the audit log forever after.
func TestConcurrentCommandsOverOneConnection(t *testing.T) {
	s := serve(t)
	client := s.dial(t, "agent:triage")

	const n = 50
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  = map[string]int{}
		shed int
		odd  []error
	)

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Execute(context.Background(),
				executeReq("kata.create_issue", "kata:alpha", map[string]any{
					"project": "PROJ", "title": "concurrent",
				}))

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && resp.GetResult().GetStatus() == sekizuiv1.Status_STATUS_OK:
				ids[resp.GetResult().GetDecisionId()]++
			case status.Code(err) == codes.ResourceExhausted:
				shed++
			case err != nil:
				odd = append(odd, err)
			default:
				odd = append(odd, fmt.Errorf("status %v: %s",
					resp.GetResult().GetStatus(), resp.GetResult().GetReason()))
			}
		}()
	}
	wg.Wait()

	if len(odd) > 0 {
		t.Fatalf("%d command(s) ended in neither success nor a clean shed; first: %v",
			len(odd), odd[0])
	}
	if len(ids)+shed != n {
		t.Errorf("%d admitted + %d shed = %d, want %d; a command reached no definite end",
			len(ids), shed, len(ids)+shed, n)
	}
	// Non-vacuous: if admission shed everything, uniqueness proves nothing.
	if len(ids) == 0 {
		t.Fatal("every command was shed, so this proves nothing about concurrent admission")
	}
	for id, count := range ids {
		if count > 1 {
			t.Errorf("decision id %q was issued %d times; two actions sharing an id are "+
				"indistinguishable in the audit log", id, count)
		}
	}
	t.Logf("%d admitted, %d shed at the admission limit — both are correct outcomes",
		len(ids), shed)
}
