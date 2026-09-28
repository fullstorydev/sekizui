package acceptance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fullstorydev/sekizui/pkg/provider/ambient"
)

// forbiddenEndpoint is a metadata server that fails the test if anything reaches
// it. Tier 1.5's whole claim is "definitive, NO NETWORK", and the only way to
// assert an absence of I/O is to make the I/O observable.
func forbiddenEndpoint(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the metadata endpoint was contacted during a tier 1.5 confirmation. " +
			"Two of the three clouds inject a local signal that settles the question " +
			"with one stat, and a uniform network probe would be slower, less reliable, " +
			"and would fail closed on platforms that could answer for free (§4.7.7)")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// step15AmbientTierOneAndAHalfConfirmsFromLocalFiles proves D102's tier 1.5.
//
// The clouds are NOT symmetric, and that asymmetry is the decision rather than
// an implementation detail. EKS injects AWS_WEB_IDENTITY_TOKEN_FILE and AKS
// injects AZURE_FEDERATED_TOKEN_FILE, so both settle the question with a stat;
// GKE Workload Identity injects nothing at all, because it works by intercepting
// the metadata endpoint. Writing one uniform probe for all three would be
// slower, less reliable, and would fail closed on two platforms that had already
// answered.
func step15AmbientTierOneAndAHalfConfirmsFromLocalFiles(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		cloud, tokenVar, idVar, id string
	}{
		{"aws", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "arn:aws:iam::1:role/sekizui"},
		{"azure", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID", "0000-client"},
	}

	for _, c := range cases {
		t.Run(c.cloud+" confirms from the injected token file, with no packet", func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("projected-by-the-webhook"), 0o600); err != nil {
				t.Fatalf("fixture: %v", err)
			}

			t.Setenv(c.tokenVar, token)
			t.Setenv(c.idVar, c.id)
			p := ambient.New(ambient.WithMetadataBase(c.cloud, forbiddenEndpoint(t)))

			// eager=true, so nothing is stopping it from probing EXCEPT tier 1.5
			// having already answered. That is what makes the forbidden endpoint
			// a real assertion rather than a decoration.
			got, err := p.Validate(ctx, c.cloud, true)
			if err != nil {
				t.Fatalf("a fully-injected %s workload identity was not confirmed: %v", c.cloud, err)
			}
			if got != ambient.ConfirmedLocally {
				t.Errorf("confidence = %v, want %v", got, ambient.ConfirmedLocally)
			}
		})

		// THE HALF-CONFIGURED POD. The webhook injects the path and the identity
		// TOGETHER, so a path naming a file that does not exist is worse than no
		// path at all: the platform said where the token would be and there is
		// no token. Accepting that would defer a certain failure to first use.
		t.Run(c.cloud+" refuses a token path with no token behind it", func(t *testing.T) {
			t.Setenv(c.tokenVar, filepath.Join(t.TempDir(), "never-written"))
			t.Setenv(c.idVar, c.id)
			p := ambient.New()

			if _, err := p.Validate(ctx, c.cloud, false); err == nil {
				t.Error("a token file that does not exist was accepted. The identity " +
					"webhook is misconfigured or the volume did not mount, and every " +
					"call to this target will fail")
			} else if !strings.Contains(err.Error(), "does not exist") {
				t.Errorf("the refusal does not say what is wrong: %v", err)
			}
		})

		// ONE SIGNAL IS NOT THE SIGNAL. A token file with no identity is not a
		// working workload identity, and treating it as one would confirm a
		// deployment that cannot authenticate.
		t.Run(c.cloud+" does not confirm on the token file alone", func(t *testing.T) {
			token := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(token, []byte("x"), 0o600); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			t.Setenv(c.tokenVar, token)
			t.Setenv(c.idVar, "")
			p := ambient.New()

			// No identity variable, so tier 1.5 declines to answer and this
			// falls through to tier 3 rather than confirming.
			got, err := p.Validate(ctx, c.cloud, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == ambient.ConfirmedLocally {
				t.Error("confirmed from a token file with no AWS_ROLE_ARN/AZURE_CLIENT_ID " +
					"beside it — a token with no subject is not an identity")
			}
		})
	}

	// GKE HAS NO LOCAL SIGNAL, and that is why tier 2 exists at all. Asserted
	// here rather than assumed, because a future edit adding a gcp entry to the
	// local-signal table would silently skip the probe.
	t.Run("gcp has no local signal and falls through to the probe", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Every variable the other two clouds look at, set and valid. GKE must
		// still probe: Workload Identity there works by intercepting the
		// metadata endpoint and leaves nothing on disk.
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/dev/null")
		t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::1:role/sekizui")
		p := ambient.New(ambient.WithMetadataBase("gcp", srv.URL))

		if _, err := p.Validate(ctx, "gcp", true); err != nil {
			t.Fatalf("gcp probe failed against a healthy endpoint: %v", err)
		}
		if hits.Load() == 0 {
			t.Error("gcp was confirmed without contacting the metadata endpoint. " +
				"Environment variables cannot tell GKE from EKS, AKS or a kind " +
				"cluster — KUBERNETES_SERVICE_HOST is present in all four")
		}
	})
}

// step16AmbientTierTwoProbesRetriesAndBoundsItsTimeout proves D102's tier 2 and
// tier 3.
//
// Three properties, each from a real failure mode rather than a guess: a short
// timeout, because a boot check that HANGS is worse than one that was skipped —
// the platform kills the pod and nothing explains why; retry with backoff,
// because on GKE the metadata server is a DaemonSet and a pod can start before
// it is ready; and REFUSE rather than warn once it has genuinely failed, because
// a target whose ambient identity does not work fails every call.
func step16AmbientTierTwoProbesRetriesAndBoundsItsTimeout(t *testing.T) {
	ctx := context.Background()

	t.Run("a healthy endpoint confirms", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The header is what tells a metadata server from anything else
			// answering on that address, and GCP requires it.
			if r.Header.Get("Metadata-Flavor") != "Google" {
				t.Error("the gcp probe sent no Metadata-Flavor header; the real endpoint " +
					"refuses without it, so this would pass here and fail on GKE")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		got, err := ambient.New(ambient.WithMetadataBase("gcp", srv.URL)).Validate(ctx, "gcp", true)
		if err != nil {
			t.Fatalf("healthy endpoint: %v", err)
		}
		if got != ambient.ConfirmedByProbe {
			t.Errorf("confidence = %v, want %v", got, ambient.ConfirmedByProbe)
		}
	})

	// LATE BUT READY — the startup race the retry exists for. Refusing on the
	// first failure would make Sekizui lose a race it wins 250ms later, and the
	// symptom would be a deployment that fails roughly whenever the node is busy.
	t.Run("a server that is late but ready is retried into success", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if hits.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		got, err := ambient.New(
			ambient.WithMetadataBase("gcp", srv.URL),
			ambient.WithProbeBounds(time.Second, 3, time.Millisecond),
		).Validate(ctx, "gcp", true)

		if err != nil {
			t.Fatalf("a metadata server ready on the third attempt was refused: %v. On "+
				"GKE it is a DaemonSet and a pod can start before it is ready", err)
		}
		if got != ambient.ConfirmedByProbe {
			t.Errorf("confidence = %v, want %v", got, ambient.ConfirmedByProbe)
		}
		if hits.Load() != 3 {
			t.Errorf("attempts = %d, want 3", hits.Load())
		}
	})

	t.Run("a hard failure refuses, with the cloud named", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		_, err := ambient.New(
			ambient.WithMetadataBase("gcp", srv.URL),
			ambient.WithProbeBounds(time.Second, 2, time.Millisecond),
		).Validate(ctx, "gcp", true)

		if err == nil {
			t.Fatal("an endpoint refusing every probe was accepted. Unlike D104's " +
				"rotation WARNING, this one refuses: if ambient identity does not work, " +
				"every call to the target fails, and starting to fail every request is " +
				"strictly worse than refusing to start with the target named")
		}
		if !strings.Contains(err.Error(), "ambient://gcp") {
			t.Errorf("the refusal does not name the declaration that failed: %v", err)
		}
	})

	// THE BOUND. A boot check that hangs is worse than one that was skipped,
	// because the platform kills the pod on a liveness probe and the logs say
	// nothing about why.
	t.Run("a hanging server hits the bound rather than hanging the boot", func(t *testing.T) {
		block := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-block:
			case <-r.Context().Done():
			}
		}))
		defer func() { close(block); srv.Close() }()

		started := time.Now()
		_, err := ambient.New(
			ambient.WithMetadataBase("gcp", srv.URL),
			ambient.WithProbeBounds(50*time.Millisecond, 2, time.Millisecond),
		).Validate(ctx, "gcp", true)
		elapsed := time.Since(started)

		if err == nil {
			t.Fatal("a metadata endpoint that never answers was accepted")
		}
		// Two attempts at 50ms plus a 1ms backoff. A generous ceiling, because
		// the assertion is "bounded", not "fast".
		if elapsed > time.Second {
			t.Errorf("the probe took %v against a server that never answers; the "+
				"per-attempt deadline is not being applied, and a boot that hangs is "+
				"killed by the platform with nothing in the logs to explain it", elapsed)
		}
	})

	// TIER 3. Where eager validation is forbidden, the declaration is ACCEPTED
	// and reported unverified — a boot that refuses on the strength of a check
	// it was not allowed to run is worse than one that says so and fails at
	// first use with the target named.
	t.Run("where probing is forbidden the claim is accepted unverified", func(t *testing.T) {
		got, err := ambient.New(
			ambient.WithMetadataBase("gcp", forbiddenEndpoint(t)),
		).Validate(ctx, "gcp", false)

		if err != nil {
			t.Fatalf("a claim that could not be checked was refused: %v. That refuses "+
				"every valid Lambda deployment for want of a check it may not run", err)
		}
		if got != ambient.Unverified {
			t.Errorf("confidence = %v, want %v — the operator has to be told the "+
				"difference between confirmed and merely accepted", got, ambient.Unverified)
		}
	})
}
