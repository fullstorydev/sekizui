package acceptance

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/fullstorydev/sekizui/internal/connectors/kata"
	"github.com/fullstorydev/sekizui/internal/pool"
	"github.com/fullstorydev/sekizui/pkg/connector"
)

// step63WithdrawalsSurviveARestart proves D133's stated guarantee actually holds
// (D145).
//
// THE GUARANTEE WAS TRUE WITHIN ONE PROCESS LIFETIME AND NOWHERE ELSE. D133 says
// "withdrawn stays withdrawn until explicitly told otherwise, and *explicitly*
// means an authorised, audited act by a named principal" — and the withdrawal
// set was a map in memory, so a restart lifted every one of them. A restart is
// not authorised, not audited as a restoration, not explicit, and not by a named
// principal; it is the most routine operation a deployment has.
//
// A SECOND POOL OVER THE SAME STORE IS A RESTART, for every purpose this
// property cares about. Nothing survives in the new process except what the
// store holds, which is exactly the question.
func step63WithdrawalsSurviveARestart(t *testing.T) {
	ctx := context.Background()

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	path := filepath.Join(t.TempDir(), "audit.jsonl.withdrawn")

	target, err := connector.NewTarget(connector.TargetParams{
		Ref: "kata:alpha", Kind: kata.Kind, Tenant: "alpha",
		BaseURL: "https://alpha.invalid",
	})
	if err != nil {
		t.Fatalf("target: %v", err)
	}

	// --- the process that revokes ------------------------------------------
	first := pool.New(kataBuild(), quiet, pool.WithStore(pool.NewFileStore(path)))
	if _, rerr := first.Revoke(ctx, target.Ref(), "operator:oncall"); rerr != nil {
		t.Fatalf("revoking: %v", rerr)
	}
	if _, withdrawn := first.Withdrawn(target.Ref()); !withdrawn {
		t.Fatal("the target is not withdrawn in the process that revoked it")
	}

	// --- the process that comes after --------------------------------------
	second := pool.New(kataBuild(), quiet, pool.WithStore(pool.NewFileStore(path)))
	if _, withdrawn := second.Withdrawn(target.Ref()); withdrawn {
		t.Fatal("the new pool reports the target withdrawn BEFORE rehydrating, so " +
			"this test cannot tell durability from shared memory")
	}

	restored, herr := second.Rehydrate(ctx)
	if herr != nil {
		t.Fatalf("rehydrating: %v", herr)
	}
	if restored != 1 {
		t.Fatalf("rehydrated %d withdrawals, want 1", restored)
	}

	sev, withdrawn := second.Withdrawn(target.Ref())
	if !withdrawn {
		t.Fatal("the target came back ALIVE across a restart. A revocation that " +
			"evaporates when the process does is not break-glass — and a restart is " +
			"the most routine operation a deployment has, so this is an unaudited " +
			"mass-restoration triggered by a deploy (D133, D145)")
	}

	// THE SEVERITY SURVIVES TOO, not merely the fact of a withdrawal. §4.7.10
	// splits the two deliberately: a quarantine lets in-flight calls finish, a
	// revocation cancels them. Restoring a revocation as a quarantine would
	// leave calls running with a credential believed compromised.
	if sev != pool.SeverityRevoke {
		t.Errorf("severity = %v after the restart, want revoke_credential. §4.7.10's "+
			"two withdrawals are not interchangeable, and downgrading one across a "+
			"restart is the quietest way to lose the distinction", sev)
	}

	// --- and restore still lifts it, durably --------------------------------
	//
	// NON-VACUITY IN THE DIRECTION THAT MATTERS. Without this, a store that never
	// deleted anything would pass every assertion above — and would make a
	// target impossible to restore, which is worse than the bug being fixed.
	if _, was, derr := second.Restore(ctx, target.Ref()); derr != nil || !was {
		t.Fatalf("restoring: was=%v err=%v", was, derr)
	}

	third := pool.New(kataBuild(), quiet, pool.WithStore(pool.NewFileStore(path)))
	if _, herr := third.Rehydrate(ctx); herr != nil {
		t.Fatalf("rehydrating after restore: %v", herr)
	}
	if _, withdrawn := third.Withdrawn(target.Ref()); withdrawn {
		t.Error("the target is still withdrawn after an explicit restore survived a " +
			"restart; a lift that does not persist means the target rises from the " +
			"dead at the next deploy")
	}

	// --- a corrupt store REFUSES rather than starting empty -----------------
	//
	// The sharpest case, and the reason Load does not treat an unreadable file
	// as an absent one: an empty withdrawal set is not the safe default, it IS
	// the attack. A truncated file must fail the boot, not quietly re-enable
	// every revoked credential.
	if werr := os.WriteFile(path, []byte(`[{"target_ref":`), 0o600); werr != nil {
		t.Fatalf("corrupting the store: %v", werr)
	}
	fourth := pool.New(kataBuild(), quiet, pool.WithStore(pool.NewFileStore(path)))
	if _, herr := fourth.Rehydrate(ctx); herr == nil {
		t.Error("a corrupt withdrawal store was treated as empty. That is not a " +
			"degraded start, it is every revoked credential silently live again — " +
			"and a corrupt file is not evidence that nothing was revoked")
	}
}
