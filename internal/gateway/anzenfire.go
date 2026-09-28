package gateway

import (
	"context"

	"github.com/fullstorydev/sekizui/internal/anzen"
	"github.com/fullstorydev/sekizui/internal/verb"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// THE ANZEN MINT SITE, IN A FILE OF ITS OWN (D332), for driftgate.go's reason:
// the identity-minter registry names FILES, and naming server.go would let any
// identity literal anywhere in it pass. It lived in cmd/sekizui/main.go until
// the acceptance harness needed the same firer rather than a copy of it.

// AnzenFirer is how the anzen dispatcher fires a rule: `fire_anzen` through
// this server's own enforcement path, as the rule's own principal (D122). ONE
// FUNCTION for `main` and the acceptance harness (D332), so the harness proves
// the wiring rather than a copy of it.
func (s *Server) AnzenFirer() anzen.Firer {
	return func(ctx context.Context, rule string) error {
		_, err := s.Enforce(ctx, AnzenIdentity(rule), &sekizuiv1.Command{
			Action:    verb.FireAnzen,
			TargetRef: anzenRefPrefix + rule,
			// NO IDEMPOTENCY KEY, DELIBERATELY. D113 refuses to retry a
			// mutating action without one, and that is the wanted behaviour
			// here: a revocation this fired must not be replayed, because the
			// second attempt lands on a target the first already withdrew and
			// reports a failure for a job that succeeded.
		})
		return err
	}
}

// AnzenIdentity is the principal an anzen rule acts as: `anzen:<rule>` (D122).
//
// **PER RULE, SYNTHESISED, AND NEVER GRANTED.** The first version of this used a
// single `anzen:dispatcher` principal and assumed an operator would grant it
// "may fire credential-compromise". D122 rules that out twice over: the `anzen:`
// namespace is REFUSED to configuration, so no such grant can exist, and anzen's
// authority is meant to come from its closed vocabulary rather than from a grant
// — because a grant "would misstate where the power comes from and would let
// arbitrary capabilities be attached to something an audit log reads as anzen".
//
// So the identity is the rule itself, and `Server.anzenAuthorise` is where the
// vocabulary's authority became real rather than declared. It authorises exactly
// one thing: firing the rule the subject names.
//
// **THIS ALSO MAKES D121'S RECURSION GUARD STRUCTURAL.** Anzen ignores decisions
// whose subject sits in the namespace, and — because configuration cannot mint
// one — nothing else can produce such a record. A convention would have been a
// rule somebody could forget; this is a shape nothing else can take.
//
// AUTH_METHOD_INTERNAL rather than the zero value (D57): an audit row must be
// able to tell a deliberate in-process action from a field somebody forgot.
func AnzenIdentity(rule string) *sekizuiv1.Identity {
	principal := "anzen:" + rule
	return &sekizuiv1.Identity{
		Caller: &sekizuiv1.Caller{
			Principal:    principal,
			Method:       sekizuiv1.AuthMethod_AUTH_METHOD_INTERNAL,
			CredentialId: "anzen:reactive-dispatcher",
		},
		Subject: &sekizuiv1.Subject{
			Principal: principal,
			Assertion: sekizuiv1.Assertion_ASSERTION_ASSERTED,
		},
		Chain: []string{principal},
	}
}
