package identity

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/internal/signedsubject"
	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// SubjectTokenHeader is the metadata key carrying a signed subject token (D318)
// — beside `sekizui-subject`, never a payload field (CONTRACTS §2.2).
const SubjectTokenHeader = "sekizui-subject-token"

// KeySource reads an issuer's key file by its credential reference — in
// production the `file://` provider under its root (D286). Asked on every
// verification, so a rotated file is seen at once and a retired key refuses.
type KeySource func(ctx context.Context, ref string) ([]byte, error)

// Option configures a Verifier.
type Option func(*Verifier)

// WithKeySource supplies how issuers' key files are read. Without it a
// deployment with issuers refuses every token rather than accepting one it
// cannot check.
func WithKeySource(ks KeySource) Option { return func(v *Verifier) { v.keys = ks } }

// signedState is what the verifier knows about tier two (D303, D318).
type signedState struct {
	issuers map[string]config.IssuerSpec
	// roles are the `role:` principals, with each one's allow patterns — what
	// a token's role selects and what its grants may only narrow.
	roles  map[string][]string
	lenses map[string]bool
	keys   KeySource
	now    func() time.Time
}

func (v *Verifier) initSigned(doc *config.Document) {
	v.issuers = map[string]config.IssuerSpec{}
	for _, is := range doc.Issuers {
		v.issuers[is.Issuer] = is
	}
	v.roles = map[string][]string{}
	for _, g := range doc.Grants {
		if strings.HasPrefix(g.Principal, config.RolePrefix) {
			for _, c := range g.Allow {
				v.roles[g.Principal] = append(v.roles[g.Principal], c.Action)
			}
		}
	}
	v.lenses = map[string]bool{}
	for _, l := range doc.Shin {
		if l.Enabled {
			v.lenses[l.Name] = true
		}
	}
	if v.now == nil {
		v.now = time.Now
	}
}

// signedSubject verifies a subject token presented by caller (D303, D318).
// Every refusal happens here, before policy ever sees the request.
func (v *Verifier) signedSubject(ctx context.Context, caller *sekizuiv1.Caller, token, asserted string,
	thumbprint string) (*sekizuiv1.Subject, error) {
	const op = "identity.signedSubject"
	refuse := func(format string, args ...any) error {
		return fault.New(fault.KindUnauthenticated, op, fmt.Sprintf(format, args...))
	}
	iss, err := signedsubject.PeekIssuer(token)
	if err != nil {
		return nil, err
	}
	is, known := v.issuers[iss]
	if !known {
		return nil, refuse("the token's issuer %q is not one this deployment pins (issuers: %v)", iss, v.issuerNames())
	}
	if !slices.Contains(is.Callers, caller.GetPrincipal()) {
		return nil, refuse("caller %q may not present tokens from %q; its issuer entry enumerates the callers "+
			"that may (D318)", caller.GetPrincipal(), iss)
	}
	if v.keys == nil {
		return nil, fault.New(fault.KindInternal, op, "issuers are configured and no key source is wired, so no "+
			"token can be checked; refusing rather than accepting one unchecked")
	}
	raw, err := v.keys(ctx, is.Keys)
	if err != nil {
		return nil, fault.Wrap(fault.KindUnauthenticated, op, fmt.Sprintf("reading %q's keys", iss), err)
	}
	keys, err := signedsubject.ParseJWKS(raw)
	if err != nil {
		return nil, fault.Wrap(fault.KindConfig, op, fmt.Sprintf("%q's key file", iss), err)
	}
	claims, err := signedsubject.Verify(token, keys, signedsubject.Policy{Issuer: is.Issuer, Audience: is.Audience,
		Algorithms: is.Algorithms, Leeway: is.Leeway(), RequireBound: is.Bound(), RoleClaim: is.RoleClaim},
		thumbprint, v.now())
	if err != nil {
		return nil, err
	}
	if asserted != "" && asserted != claims.Subject {
		return nil, refuse("the request asserts subject %q and its token names %q; one request, one subject",
			asserted, claims.Subject)
	}
	role := config.RolePrefix + claims.Role
	allowed, hasRole := v.roles[role]
	if !hasRole {
		return nil, refuse("the token's role %q selects %q, which has no grant in this deployment — a role claim "+
			"is an input, never an authorisation (D303)", claims.Role, role)
	}
	for _, l := range claims.Lenses {
		if !v.lenses[l] {
			return nil, refuse("the token adds lens %q, which this deployment does not declare; a restriction that "+
				"cannot be applied is refused, never skipped", l)
		}
	}
	// A TOKEN MAY ONLY NARROW (D303): a grant it lists that the role does not
	// hold is noted, and grants nothing — the engine intersects.
	var excess []string
	for _, g := range claims.Grants {
		if !coveredBy(allowed, g) {
			excess = append(excess, g)
		}
	}
	return &sekizuiv1.Subject{
		Principal:    claims.Subject,
		Assertion:    sekizuiv1.Assertion_ASSERTION_SIGNED,
		Proof:        claims.Proof,
		Issuer:       iss,
		Role:         role,
		Unbound:      !claims.Bound,
		TokenGrants:  claims.Grants,
		TokenLenses:  claims.Lenses,
		ExcessGrants: excess,
	}, nil
}

// coveredBy reports whether any allow pattern covers g (itself possibly a
// pattern): equal, or a trailing-star pattern whose prefix g starts with.
func coveredBy(allow []string, g string) bool {
	for _, a := range allow {
		if a == g {
			return true
		}
		if prefix, star := strings.CutSuffix(a, "*"); star && strings.HasPrefix(g, prefix) {
			return true
		}
	}
	return false
}

func (v *Verifier) issuerNames() []string {
	out := make([]string, 0, len(v.issuers))
	for n := range v.issuers {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
