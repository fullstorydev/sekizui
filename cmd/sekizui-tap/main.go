// Command sekizui-tap is the raw-envelope dev tap (P3 step 15, D273).
//
//	sekizui-tap capture  -addr host:port -cert c.crt -key c.key -ca ca.crt [-subject s ...] [-max n] > capture.jsonl
//	sekizui-tap rehearse -config sekizui.yaml -in capture.jsonl
//
// CAPTURE is an ordinary governed Subscribe, as the certificate's principal:
// authorised by its subscribe grant, recorded once, lensed, scoped by target.
// REHEARSE runs the captured envelopes through the document's reflex rules and
// projections OFFLINE and prints what would have happened — nothing is sent,
// nothing is executed, nothing is recorded. Neither is reachable over the wire:
// this binary is how a human drives them.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/fullstorydev/sekizui/internal/builtin"
	"os"
	"os/signal"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/fullstorydev/sekizui/internal/tap"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch os.Args[1] {
	case "capture":
		err = capture(ctx, os.Args[2:])
	case "rehearse":
		err = rehearse(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sekizui-tap:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sekizui-tap capture|rehearse [flags]  (see the package comment)")
	os.Exit(2)
}

type subjects []string

func (s *subjects) String() string     { return strings.Join(*s, ",") }
func (s *subjects) Set(v string) error { *s = append(*s, v); return nil }

func capture(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	addr := fs.String("addr", "", "gateway gRPC address")
	cert := fs.String("cert", "", "client certificate (the principal the capture runs as)")
	key := fs.String("key", "", "client key")
	ca := fs.String("ca", "", "CA that signed the server certificate")
	max := fs.Int("max", 0, "stop after this many envelopes (0 = until interrupted)")
	var subs subjects
	fs.Var(&subs, "subject", "subject pattern to capture (repeatable; none = everything granted)")
	_ = fs.Parse(args)
	if *addr == "" || *cert == "" || *key == "" || *ca == "" {
		return errors.New("capture needs -addr, -cert, -key and -ca: it is a governed subscription, " +
			"so it authenticates like any consumer")
	}

	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s holds no certificate", *ca)
	}
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS13,
	})))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	n, err := tap.Capture(ctx, sekizuiv1.NewGatewayServiceClient(conn),
		&sekizuiv1.SubscribeRequest{Subjects: subs}, os.Stdout, *max)
	fmt.Fprintf(os.Stderr, "captured %d envelope(s)\n", n)
	return err
}

func rehearse(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rehearse", flag.ExitOnError)
	cfg := fs.String("config", "", "the deployment document whose rules to rehearse")
	in := fs.String("in", "", "a capture file (protojson envelopes, one per line)")
	_ = fs.Parse(args)
	if *cfg == "" || *in == "" {
		return errors.New("rehearse needs -config and -in")
	}
	doc, err := config.NewFileSource(*cfg).Load(ctx)
	if err != nil {
		return err
	}
	// THE SAME VALIDATION A BOOT RUNS: rehearsing rules a deployment would
	// refuse would show what a configuration that cannot exist would do.
	if err := doc.Validate(); err != nil {
		return err
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	// THE SHIPPED CONNECTORS, for their schemas only (D279): built with no
	// pool, and nothing here calls them.
	n, err := tap.Rehearse(ctx, doc, builtin.ByKind(doc, nil), f, os.Stdout)
	fmt.Fprintf(os.Stderr, "rehearsed %d envelope(s); nothing was sent or recorded\n", n)
	return err
}
