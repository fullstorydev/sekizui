// Package withdrawal is the durable store for break-glass state.
//
// PUBLIC API (D35), and for a sharper reason than most of pkg/. §5.1 claims the
// command path has "no shared mutable state" and therefore scales horizontally.
// Break-glass invalidated that: a withdrawal gates every command, and it lives
// in one process. So a revocation on replica A leaves replica B serving the
// credential somebody just declared compromised — which is a HOLE IN BREAK-GLASS
// rather than a performance characteristic, and it needs no restart to appear.
//
// The local implementation makes a withdrawal survive a RESTART, which is what
// D133's stated guarantee already promises and did not deliver. Making it
// survive across REPLICAS needs a shared implementation, and this interface is
// where a self-hoster or a later phase supplies one — the same shape pkg/limiter
// uses for the distributed rate limiter D14 declined to build now.
//
// DESIGN.md references: §4.7.10, §5.1, §5.3, D35, D106, D129, D133.
package withdrawal

import (
	"context"
	"time"
)

// Record is one withdrawn target, in the shape an audit reader needs.
//
// CARRIES WHO AND WHEN, not merely the fact. A withdrawal that survives a
// restart and cannot say who ordered it is a target that is mysteriously dead
// after a deploy — the operator's first question is "why is this refused", and a
// store that cannot answer sends them to the audit log to correlate timestamps.
type Record struct {
	TargetRef string `json:"target_ref"`

	// Severity is "quarantine" or "revoke". A STRING on the wire rather than the
	// internal enum, because this file outlives any given build and an integer
	// whose meaning lives in a Go constant is unreadable in an incident.
	Severity string `json:"severity"`

	// At is when the withdrawal was ordered, and Trigger is what ordered it —
	// `operator:oncall` or `anzen:<rule>` (D134).
	At      time.Time `json:"at"`
	Trigger string    `json:"trigger,omitempty"`

	// NO DECISION ID, AND THE ORDERING IS WHY. The audit record for a withdrawal
	// is written AFTER the withdrawal, because it reports what the withdrawal
	// actually did — how many calls were cancelled, how many clients torn down.
	// So the decision id does not exist when this record is written, and a field
	// for it would be one nothing could ever populate: the defect this codebase
	// has found thirteen times, added deliberately for tidiness.
	//
	// `At` plus `Trigger` correlate to the audit log without it.
}

// Store persists withdrawals.
//
// THE FAILURE DIRECTION IS THE WHOLE CONTRACT. A store that cannot RECORD a
// withdrawal must make the withdrawal fail, because reporting a successful
// revocation that will not survive a restart is the false reassurance D133 and
// §4.7.10 both refuse. A store that cannot LOAD at boot must make the boot fail,
// for the same reason inverted: starting with an empty withdrawal set silently
// restores every revoked credential, which is exactly the attack D133 named.
type Store interface {
	// Load returns every withdrawal in force. Called once at boot.
	Load(ctx context.Context) ([]Record, error)

	// Put records a withdrawal. Must be durable before it returns.
	Put(ctx context.Context, r Record) error

	// Delete lifts one, and is called only by `sekizui.restore_target` (D133) —
	// never by a timer, a config reload, or a restart.
	Delete(ctx context.Context, targetRef string) error
}
