// Command sekizui-devcert generates a local CA and mTLS material for
// development.
//
// SEPARATE BINARY, NOT A SUBCOMMAND OF sekizui. A server that can mint client
// certificates is a server that can mint identities, and the value of the whole
// grant model is that it cannot. Keeping the generator in a different binary
// means the serving process never links the code at all.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fullstorydev/sekizui/internal/devcert"
	"github.com/fullstorydev/sekizui/internal/obs"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

func main() {
	slog.SetDefault(obs.NewLogger(os.Stdout, obs.Options{Level: slog.LevelInfo, JSON: false}))

	dir := flag.String("dir", "dev/certs", "directory to write the CA and leaf certificates into")
	who := flag.String("principals", "agent:triage,mesh:primary",
		"comma-separated principals to issue client certificates for")
	flag.Parse()

	principals := strings.Split(*who, ",")
	for i := range principals {
		principals[i] = strings.TrimSpace(principals[i])
	}

	b, err := devcert.Generate(*dir, principals)
	if err != nil {
		slog.Error("generating development certificates", "err", err, "kind", fault.KindOf(err))
		os.Exit(1)
	}

	fmt.Printf("wrote a development CA and %d client identities to %s\n", len(principals), b.Dir)
	fmt.Printf("  trust domain: %s\n", b.TrustDomain)
	fmt.Printf("  expires:      %s (deliberately short — do not build anything on these)\n",
		b.NotAfter.Format("2006-01-02"))
	fmt.Println()
	fmt.Println("run the gateway with:")
	fmt.Printf("  sekizui -config <file> \\\n")
	fmt.Printf("    -tls-cert %s -tls-key %s \\\n", b.ServerCert, b.ServerKey)
	fmt.Printf("    -tls-client-ca %s\n", b.CACertFile)
	fmt.Println()
	fmt.Println("client identities:")
	for _, p := range principals {
		fmt.Printf("  %-16s %s\n", p, b.ClientCerts[p])
	}
}
