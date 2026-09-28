package acceptance

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/fullstorydev/sekizui/internal/safestruct"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// p3Step9 — the envelope round-trips protobuf and protojson losslessly (P3
// criterion 4).
//
// **A PROPERTY TEST OVER GENERATED ENVELOPES**, seeded so a failure reproduces,
// because the values that break a round trip are the ones nobody writes down.
// Every payload goes through `safestruct.Convert` — the path translation
// actually takes (D177) — so the property is about envelopes Sekizui can
// produce, not about hand-built ones it never would.
func p3Step9(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the envelope round-trips protobuf and protojson losslessly")

	const n = 500
	rng := rand.New(rand.NewSource(20260923)) //nolint:gosec // reproducible generation, not security
	for i := 0; i < n; i++ {
		env := generateEnvelope(rng, i)

		wire, err := proto.Marshal(env)
		if err != nil {
			t.Fatalf("step 9: envelope %d does not marshal to protobuf: %v", i, err)
		}
		back := &sekizuiv1.Envelope{}
		if err := proto.Unmarshal(wire, back); err != nil || !proto.Equal(env, back) {
			t.Fatalf("step 9: envelope %d did not survive protobuf: %v", i, err)
		}

		js, err := protojson.Marshal(env)
		if err != nil {
			t.Fatalf("step 9: envelope %d (seed 20260923) cannot be written as protojson: %v — an "+
				"envelope the bus carries and a JSON sink cannot is data lost in D177's shape", i, err)
		}
		fromJSON := &sekizuiv1.Envelope{}
		if err := protojson.Unmarshal(js, fromJSON); err != nil {
			t.Fatalf("step 9: envelope %d's protojson does not read back: %v\n%s", i, err, js)
		}
		if !proto.Equal(env, fromJSON) {
			t.Fatalf("step 9: envelope %d changed across protojson:\nbefore %v\nafter  %v", i, env, fromJSON)
		}
	}
	r.detail(t, "%d generated envelopes, payloads through safestruct, survived protobuf and "+
		"protojson unchanged — NaN and ±Inf included, substituted and recorded rather than lost", n)
}

// generateEnvelope builds one envelope whose fields and payload vary across the
// values that tend to break encodings.
func generateEnvelope(rng *rand.Rand, i int) *sekizuiv1.Envelope {
	payload, _ := safestruct.Convert(randomMap(rng, 0), safestruct.DefaultBudget)
	times := []time.Time{
		time.Unix(0, 0).UTC(),
		time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		time.Date(2026, 9, 23, 10, 0, 0, rng.Intn(1e9), time.UTC),
	}
	env := &sekizuiv1.Envelope{
		Id:          fmt.Sprintf("env-%d", i),
		Source:      pick(rng, "fs:sessions", "kata:alpha", ""),
		SpecVersion: "1.0",
		Type:        pick(rng, "kata.row.v1", "fullstory.session.v1"),
		Subject:     pick(rng, "", "6606828898126528473:5450116830618425003", "ünïcødé/✓"),
		Stage:       pick(rng, "raw", "enriched"),
		Residency:   pick(rng, "eu", "us", ""),
		Data:        payload,
	}
	// OPTIONAL FIELDS SOMETIMES UNSET, so an unset one beside a zero one is covered.
	if rng.Intn(2) == 0 {
		env.Time = timestamppb.New(times[rng.Intn(len(times))])
	}
	if rng.Intn(2) == 0 {
		env.Causation = &sekizuiv1.Causation{RootId: "job-1", ParentId: "p", Depth: uint32(rng.Intn(9)), ProducedBy: "translator:kata"}
	}
	if rng.Intn(3) == 0 {
		env.Projection, _ = safestruct.Convert(randomMap(rng, 1), safestruct.DefaultBudget)
	}
	return env
}

func randomMap(rng *rand.Rand, depth int) map[string]any {
	m := map[string]any{}
	for k := 0; k < 1+rng.Intn(4); k++ {
		m[fmt.Sprintf("k%d_%s", k, pick(rng, "", "ü", "a b"))] = randomValue(rng, depth)
	}
	return m
}

func randomValue(rng *rand.Rand, depth int) any {
	switch rng.Intn(10) {
	case 0:
		return pick(rng, "", "plain", "ünïcødé ✓", "6606828898126528473")
	case 1:
		return []float64{0, math.Copysign(0, -1), math.MaxFloat64, math.SmallestNonzeroFloat64}[rng.Intn(4)]
	case 2:
		return []float64{math.NaN(), math.Inf(1), math.Inf(-1)}[rng.Intn(3)]
	case 3:
		return rng.Intn(2) == 0
	case 4:
		return nil
	case 5:
		if depth < 3 {
			return randomMap(rng, depth+1)
		}
		return "deep"
	case 6:
		if depth < 3 {
			return []any{randomValue(rng, depth+1), randomValue(rng, depth+1)}
		}
		return []any{}
	case 7:
		return map[string]any{}
	default:
		return rng.Float64() * 1e6
	}
}

func pick(rng *rand.Rand, opts ...string) string { return opts[rng.Intn(len(opts))] }
