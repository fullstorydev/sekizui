package config_test

import (
	"testing"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/provider/conformance"
)

// TestEnvProviderConformance runs the published contract against the built-in
// env provider.
//
// IN AN EXTERNAL TEST PACKAGE, both because that is how the suite is consumed and
// because `pkg/config`'s in-package tests cannot import `pkg/provider/...`
// without a cycle — the same constraint that moved the credential posture off
// `connector.Target` (CONTRACTS item 50).
func TestEnvProviderConformance(t *testing.T) {
	t.Setenv("SEKIZUI_CONFORMANCE_TOKEN", "conformance-material")

	conformance.Run(t, config.EnvProvider{}, []conformance.Case{
		{Name: "a set environment variable", Ref: "env://SEKIZUI_CONFORMANCE_TOKEN"},
	})
}
