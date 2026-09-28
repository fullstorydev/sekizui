// Package oauth implements the `oauth-cc://` credential scheme: OAuth 2.0
// client credentials (RFC 6749 §4.4), chained onto a secret manager.
//
// PUBLIC API (D35), and in its own package on purpose. `pkg/config` holds the
// Provider interface and the trivial EnvProvider, and is imported by twelve
// packages including the schema checker and the gateway. A provider that speaks
// HTTP does not belong in everyone's dependency graph, and §4.7.2's table
// already anticipates `aws-sm://`, `azure-kv://` and `vault://` wanting the same
// home.
//
// WHAT D47 SETTLED, AND WHY IT MATTERS TO A CONNECTOR AUTHOR. OAuth is a
// CHAINED PROVIDER rather than a driver concern:
//
//	oauth-cc://token.vendor.com/oauth/token
//	    ?client_id=abc123
//	    &client_secret=gcp-sm://projects/p/secrets/vendor-oauth/versions/7
//	    &scope=sessions.read
//
// The client secret lives in the secret manager like every other credential and
// is versioned there; this provider exchanges it and returns the access token as
// ordinary material. A driver therefore never implements a token exchange, never
// implements a refresh loop, and cannot tell whether it is holding a static API
// key or a freshly minted bearer token. Switching a target from one to the other
// is a configuration change.
//
// THE SPLIT THAT MAKES POOLING WORK (§4.7.1's table, D130):
//
//	client secret  — secret manager, version in the ref — rotation invalidates
//	                 the pool, which is correct
//	access token   — minted here, cached to its own expiry — refresh must be
//	                 INVISIBLE to pooling, which is why Version below reports
//	                 the inner secret's version and never the token
//
// Getting that backwards evicts every pooled client on every refresh, and for a
// session-oriented target (§4.7.4 class 3) re-runs the MCP `initialize`
// handshake on a timer, destroying server-side state for a credential that never
// rotated.
//
// NOT IMPLEMENTED HERE, deliberately and loudly: authorization_code and its
// refresh tokens. That grant needs a human to authorise once via a redirect, and
// its stored credential is a refresh token which providers commonly ROTATE ON
// USE — meaning Sekizui would have to write the new value back to the secret
// manager, and `Provider` has no write path. Refused by name at boot rather than
// half-supported (D53).
//
// DESIGN.md references: §4.7.1, §4.7.2, §4.7.6, D35, D47, D53, D130, D131.
package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Scheme is the reference scheme this provider serves.
const Scheme = "oauth-cc"

// clientSecretParam is the query parameter holding the nested reference. Named
// once because both Inner and ResolveChained must agree about it, and a typo
// across the two would silently produce an unresolved chain.
const clientSecretParam = "client_secret"

// DefaultTimeout bounds a token exchange.
//
// A token endpoint sits on the enforcement path — a cold cache means a command
// waits for this — so it is bounded tightly rather than left to the caller's
// context. §4.3.4's rule that every outbound call has a deadline applies here
// even though the call is ours rather than a driver's.
const DefaultTimeout = 10 * time.Second

// Provider mints access tokens via the client credentials grant.
type Provider struct {
	client *http.Client
}

// New returns a provider using a bounded HTTP client.
func New(opts ...Option) *Provider {
	p := &Provider{client: &http.Client{Timeout: DefaultTimeout}}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient substitutes the client, for tests against httptest and for
// deployments needing a proxy or a custom trust store.
func WithHTTPClient(c *http.Client) Option { return func(p *Provider) { p.client = c } }

func (p *Provider) Scheme() string { return Scheme }

// Inner declares that the client secret is a nested reference (D131).
func (p *Provider) Inner(ref string) ([]string, error) {
	const op = "oauth.Inner"

	q, err := parse(op, ref)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(q.Get(clientSecretParam), "://") {
		// A literal secret in the reference. Refused rather than accepted:
		// configuration carries REFERENCES, never material (§4.7), and a
		// client secret pasted into a target ref would land in the config
		// file, in git, and in every `sekizui config` dump.
		return nil, fault.New(fault.KindConfig, op,
			"the client_secret in "+redactRef(ref)+" is not a reference. Configuration "+
				"carries references and never material (§4.7) — point it at a secret "+
				"manager, e.g. client_secret=gcp-sm://projects/p/secrets/s/versions/7")
	}
	return []string{clientSecretParam}, nil
}

// Resolve without a resolved inner reference cannot work, and says so.
//
// EXISTS TO REFUSE. Provider requires this method, and a chained provider
// reached through it has been called by something that did not notice the
// chaining — which would otherwise send the literal string "gcp-sm://..." to a
// token endpoint as a password.
func (p *Provider) Resolve(context.Context, string) (config.Resolution, error) {
	return config.Resolution{}, fault.New(fault.KindInternal, "oauth.Resolve",
		"oauth-cc:// is a chained reference and must be resolved through "+
			"ResolveChained with its client_secret already resolved (D131). Reaching "+
			"this means the caller did not check for config.ChainedProvider")
}

// ResolveChained performs the client credentials exchange.
func (p *Provider) ResolveChained(ctx context.Context, ref string,
	inner map[string]config.Resolution) (config.Resolution, error) {

	const op = "oauth.ResolveChained"

	q, err := parse(op, ref)
	if err != nil {
		return config.Resolution{}, err
	}

	secret, ok := inner[clientSecretParam]
	if !ok {
		return config.Resolution{}, fault.New(fault.KindInternal, op,
			"the client_secret for "+redactRef(ref)+" was not resolved before dispatch")
	}

	endpoint, err := endpointOf(op, ref)
	if err != nil {
		return config.Resolution{}, err
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	if scope := q.Get("scope"); scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindConfig, op,
			"building the token request for "+redactRef(ref), err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// CLIENT AUTHENTICATION defaults to client_secret_basic (RFC 6749 §2.3.1),
	// which the spec says a server MUST support and SHOULD prefer, because
	// `_post` puts the secret in a body that intermediaries log more readily.
	// `auth_method=post` selects the alternative for endpoints that only take
	// that, which is common enough to need the escape hatch.
	if q.Get("auth_method") == "post" {
		form.Set("client_id", q.Get("client_id"))
		form.Set("client_secret", string(secret.Material))
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
	} else {
		req.SetBasicAuth(url.QueryEscape(q.Get("client_id")),
			url.QueryEscape(string(secret.Material)))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		// **`KindCredentialUnavailable`, NOT `KindTargetUnavailable` (D200).** The
		// TARGET is fine — it has not been contacted, and will not be. Reporting
		// this as the target being unreachable made the breaker record a failure
		// against it, so one token-endpoint blip opened the breaker on every
		// target whose credential chained through this provider: a credential
		// hiccup amplified into a fleet-wide outage, with every log line naming
		// the innocent party.
		return config.Resolution{}, fault.Wrap(fault.KindCredentialUnavailable, op,
			"the token endpoint for "+redactRef(ref)+" could not be reached", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindCredentialUnavailable, op,
			"reading the token response for "+redactRef(ref), err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is NOT included. RFC 6749 §5.2 error responses are
		// well-behaved, but a misconfigured endpoint can echo the request —
		// including the client secret — and this string reaches logs.
		// **`KindUnauthenticated`, and it is the apt reading rather than a
		// convenience (D200).** A non-200 from a token endpoint is
		// overwhelmingly a client_id, secret or scope that is wrong — an
		// authentication problem with the CREDENTIAL, not evidence about the
		// target, which has not been contacted.
		return config.Resolution{}, fault.New(fault.KindUnauthenticated, op,
			"the token endpoint for "+redactRef(ref)+" returned "+resp.Status+
				"; the response body is withheld because a misbehaving endpoint can "+
				"echo the client secret back in it")
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindCredentialUnavailable, op,
			"the token endpoint for "+redactRef(ref)+" returned a body that is not JSON", err)
	}
	if tok.AccessToken == "" {
		return config.Resolution{}, fault.New(fault.KindCredentialUnavailable, op,
			"the token endpoint for "+redactRef(ref)+" returned 200 with no access_token")
	}

	res := config.Resolution{
		Material: []byte(tok.AccessToken),

		// THE VERSION IS THE INNER SECRET'S, NEVER THE TOKEN'S (D130).
		//
		// This one line is what keeps D47's promise that "refresh is invisible
		// to pooling". Reporting anything derived from the access token would
		// change `credVer` on every refresh and evict every pooled client on a
		// timer.
		//
		// **AN EMPTY INNER VERSION CANNOT REACH HERE, AND THIS COMMENT USED TO
		// SAY OTHERWISE (D234).** It warned that an empty version would be
		// passed through, making the cache fall back to digesting the material —
		// "wrong for this scheme". That hazard is unreachable through the only
		// caller: `credential.Cache` resolves a nested reference THROUGH ITSELF
		// and passes the inner ref's POOL KEY as the inner version
		// (`file:///…/x.key#1`), so `secret.Version` is non-empty even for a
		// provider that reports none of its own — `file://` reports none, and
		// `file://` is the whole Kubernetes secret surface (D151).
		//
		// **PROVEN AGAINST A REAL IdP THAT MINTS A FRESH TOKEN PER REQUEST**,
		// which is the one vendor behaviour that could falsify it: two
		// resolutions, two different tokens, one unchanged pool key. A fixture
		// returning a constant token would pass either way — and the fixtures
		// here do vary it, which the real endpoint has now confirmed is faithful.
		Version: secret.Version,
	}
	if tok.ExpiresIn > 0 {
		// Honoured by the cache as a hard ceiling, with jitter moving it only
		// earlier (D130).
		res.Expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return res, nil
}

func parse(op, ref string) (url.Values, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, "credential reference is not a URL", err)
	}
	if u.Scheme != Scheme {
		return nil, fault.New(fault.KindConfig, op,
			"reference "+redactRef(ref)+" is not an "+Scheme+":// reference")
	}
	q := u.Query()
	if q.Get("client_id") == "" {
		return nil, fault.New(fault.KindConfig, op,
			"reference "+redactRef(ref)+" has no client_id")
	}
	return q, nil
}

// endpointOf rebuilds the token URL from the reference, dropping the query
// parameters that configure this provider.
func endpointOf(op, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fault.Wrap(fault.KindConfig, op, "credential reference is not a URL", err)
	}
	if u.Host == "" {
		return "", fault.New(fault.KindConfig, op,
			"reference "+redactRef(ref)+" names no token endpoint host")
	}
	// https, always. A token exchange sends a client secret; over plaintext it
	// is a credential handed to anyone on the path.
	return "https://" + u.Host + u.Path, nil
}

// redactRef strips the query string before a reference reaches an error
// message.
//
// D112 keeps secret-manager paths out of logs, and this reference embeds one in
// `client_secret`. It also carries a `client_id`, which is not secret but is
// tenant-identifying. Errors travel further than anyone expects, so only the
// endpoint survives.
func redactRef(ref string) string {
	if i := strings.IndexByte(ref, '?'); i >= 0 {
		return ref[:i] + "?[REDACTED]"
	}
	return ref
}
