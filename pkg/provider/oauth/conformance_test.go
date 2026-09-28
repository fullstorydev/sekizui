package oauth_test

import (
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/provider/conformance"
	"github.com/fullstorydev/sekizui/pkg/provider/oauth"
)

// TestConformance runs the CHAINED contract against this provider (D131, D156).
//
// RunChained rather than Run, and the distinction is not cosmetic: `Run` would
// pass vacuously here. Every refusal assertion holds because a chained provider
// refuses the plain path for everything, and no working case could ever succeed —
// so the suite would report coverage it does not have.
func TestConformance(t *testing.T) {
	conformance.RunChained(t, oauth.New(), []conformance.ChainedCase{{
		Name: "a client-credentials reference with a chained secret",
		Ref:  "oauth-cc://token.vendor.invalid/oauth/token?client_id=abc&client_secret=env://VENDOR_SECRET",
		Inner: map[string]config.Resolution{
			"client_secret": {Material: []byte("the-secret")},
		},
	}})
}
