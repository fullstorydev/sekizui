package main

// READINESS PROSE. The handler is in probeMux; what lives here is the wording,
// which is load-bearing enough to be worth reading on its own (CONTRACTS 83).

import (
	"github.com/fullstorydev/sekizui/internal/spine"
)

// readinessRefusal is what /readyz says when the process is not serving.
//
// **THE DIRECTION IS THE INFORMATION (CONTRACTS 83).** A 503 during a rollout
// and a 503 during a cold start call for opposite reactions: one is expected and
// self-resolving, the other may mean a config the deployment cannot load. Both
// used to read "initializing", so the body actively misled during the case an
// operator is more likely to be watching.
//
// PHRASED FOR A HUMAN AND NOT FOR THE PROBE, because the probe reads the status
// code and discards this. Kubernetes withdrawing the pod from its endpoints on a
// failing readiness probe during termination is the DESIGNED behaviour, not a
// fault — so the stopping case says what is happening rather than sounding like
// an error.
func readinessRefusal(p spine.Phase) string {
	switch p {
	case spine.PhaseStopping:
		return "stopping: readiness withdrawn first, in-flight work is draining — " +
			"this instance is deliberately no longer accepting traffic"
	case spine.PhaseStopped:
		return "stopped: every component has stopped; this process is about to exit"
	case spine.PhaseInitializing, spine.PhaseServing:
		return "initializing"
	default:
		return "initializing"
	}
}
