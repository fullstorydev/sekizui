package acceptance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fullstorydev/sekizui/internal/credential"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
)

// P1 step 55: chained references resolve inner-first, in the cache (D131).

// recordingSecrets stands in for a secret manager, and counts reads so the step
// can prove the inner reference went through the CACHE rather than being
// fetched afresh by the OAuth provider.
type recordingSecrets struct {
	mu      sync.Mutex
	reads   int
	refs    []string
	secret  string
	version string
}

func (p *recordingSecrets) Scheme() string { return "vault" }

func (p *recordingSecrets) Resolve(_ context.Context, ref string) (config.Resolution, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	p.refs = append(p.refs, ref)
	return config.Resolution{Material: []byte(p.secret), Version: p.version}, nil
}

func (p *recordingSecrets) stats() (int, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reads, append([]string(nil), p.refs...)
}

// step55ChainedReferencesResolveInnerFirst is D131.
//
// The property is not "OAuth works" — it is WHO resolved the inner reference.
// If the provider had fetched its own client secret, every assertion about
// caching, auditing and versioning would be about code Sekizui does not own,
// and a third-party provider (D35) would hold a capability to read any secret
// in the process.
func step55ChainedReferencesResolveInnerFirst(t *testing.T) {
	t.Run("inner_first_through_the_cache", step55InnerFirst)
	t.Run("dynamic_chaining_is_refused", step55bDynamicChainingIsRefused)
}

func step55InnerFirst(t *testing.T) {
	var (
		mu       sync.Mutex
		exchange int
		gotAuth  string
	)
	// TLS, because endpointOf forces https:// — a token exchange sends a client
	// secret, and over plaintext that is a credential handed to anyone on the
	// path. httptest's own client trusts the generated certificate.
	token := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		exchange++
		gotAuth = r.Header.Get("Authorization")
		n := exchange
		mu.Unlock()

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials (RFC 6749 §4.4)",
				r.PostForm.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		// A DIFFERENT TOKEN EACH TIME, which is what a real endpoint does and
		// what makes the version assertion below meaningful.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "minted-token-" + string(rune('A'+n-1)),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer token.Close()

	secrets := &recordingSecrets{secret: "the-client-secret", version: "7"}

	// The OAuth provider is pointed at the test server. Note it is given NO
	// resolver — that is the point of D131.
	op := oauth.New(oauth.WithHTTPClient(token.Client()))

	cache := credential.New([]config.Provider{secrets, op})

	ref := "oauth-cc://" + strings.TrimPrefix(token.URL, "https://") +
		"/oauth/token?client_id=abc123" +
		"&client_secret=vault://secret/data/fs-oauth" +
		"&scope=sessions.read"

	material, version, err := cache.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolving a chained reference: %v", err)
	}

	// --- the exchange happened, with the INNER secret ------------------------
	if got := string(material); !strings.HasPrefix(got, "minted-token-") {
		t.Fatalf("resolved material = %q, want a minted access token", got)
	}
	mu.Lock()
	auth := gotAuth
	mu.Unlock()
	if auth == "" {
		t.Error("the token exchange sent no Authorization header; client_secret_basic " +
			"is RFC 6749 §2.3.1's preferred client authentication and the default here")
	}

	// --- the INNER reference went through the CACHE --------------------------
	reads, refs := secrets.stats()
	if reads != 1 {
		t.Fatalf("the secret manager was read %d times, want 1", reads)
	}
	if len(refs) != 1 || refs[0] != "vault://secret/data/fs-oauth" {
		t.Fatalf("the secret manager saw %v, want the nested reference alone", refs)
	}

	// Resolving the INNER ref directly must now be a cache HIT, which is only
	// true if the chained resolution went through Resolve rather than the
	// provider reaching for it privately. That is the whole governance claim:
	// one audited, cached, singleflighted path for every credential read.
	if _, _, err := cache.Resolve(context.Background(), "vault://secret/data/fs-oauth"); err != nil {
		t.Fatalf("resolving the inner ref directly: %v", err)
	}
	if reads, _ = secrets.stats(); reads != 1 {
		t.Errorf("the secret manager was read %d times after a direct resolve of the "+
			"inner reference, want 1. The chained resolution bypassed the cache, so a "+
			"provider is fetching secrets on a path nothing audits, caches or versions "+
			"(D131)", reads)
	}

	// --- a REFRESH must not move the version ---------------------------------
	//
	// D47's table, restated where it can actually break: the access token
	// changes on every mint, the client secret has not rotated, so the pooled
	// client must not be evicted.
	cache2 := credential.New([]config.Provider{secrets, op})
	_, v2, err := cache2.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatalf("second cache resolve: %v", err)
	}
	if mu.Lock(); exchange < 2 {
		mu.Unlock()
		t.Fatal("the second cache did not mint a new token, so the assertion below " +
			"would pass vacuously")
	}
	mu.Unlock()
	if v2 != version {
		t.Errorf("credVer moved %q -> %q across a token mint. The access token differs "+
			"every time; the CLIENT SECRET did not rotate. Reporting the token evicts "+
			"every pooled client on refresh and re-initialises MCP sessions on a timer "+
			"(§4.7.1, D130)", version, v2)
	}
}

// step55bDynamicChainingIsRefused is the limit D131 states rather than discovers.
func step55bDynamicChainingIsRefused(t *testing.T) {
	op := oauth.New()

	// A literal secret rather than a reference. Configuration carries
	// references and never material (§4.7), and accepting this would put a
	// client secret in the config file, in git, and in every config dump.
	_, err := op.Inner("oauth-cc://vendor.example/oauth/token" +
		"?client_id=abc&client_secret=literal-secret-value")
	if err == nil {
		t.Fatal("a literal client_secret in a reference was accepted")
	}
	if fault.KindOf(err) != fault.KindConfig {
		t.Errorf("refused with kind %v, want config — this is an operator's mistake to "+
			"fix, not a runtime failure", fault.KindOf(err))
	}
	if strings.Contains(err.Error(), "literal-secret-value") {
		t.Error("the refusal echoed the secret back into an error string, which reaches " +
			"logs (§4.3.3)")
	}

	// Reaching a chained provider through plain Resolve must refuse rather than
	// send the literal "vault://..." string to a token endpoint as a password.
	_, err = op.Resolve(context.Background(),
		"oauth-cc://vendor.example/oauth/token?client_id=abc&client_secret=vault://x")
	if err == nil {
		t.Fatal("a chained provider resolved without its inner reference; the token " +
			"endpoint would have received the reference string as the client secret")
	}
}
