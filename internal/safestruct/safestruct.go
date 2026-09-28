// Package safestruct converts driver-supplied data into protobuf Structs
// without ever losing information as a side effect of a type it cannot
// represent.
//
// # The defect this replaces, and why it is a security control
//
// `structpb.NewStruct` accepts a fixed set of Go types — nil, bool, the numeric
// kinds, string, []byte, []any and map[string]any — and fails ALL-OR-NOTHING on
// anything else. The gateway called it in three places and discarded the error
// in all three (CONTRACTS 73), which produced three different disappearances
// from one cause:
//
//   - the audit Effect detail was silently OMITTED, while the record went on
//     reporting a successful effect
//   - a command result became EMPTY, so the caller reasoned over nothing
//   - a query row was silently DROPPED from the result set
//
// **THE DATA COMES FROM A DRIVER, AND DRIVERS ARE THIRD-PARTY (D35).** Worse,
// drivers legitimately echo upstream responses, so an UPSTREAM ultimately
// influences the shape. That makes each of the three an attacker-reachable way
// to remove information: make your effect unauditable, blank a caller's result,
// or hide chosen rows from a query — by returning one value of an awkward type.
//
// The all-or-nothing behaviour is the amplifier. Control of ONE field erased the
// WHOLE object, including every field Sekizui itself had put there.
//
// # The rule
//
// **AN UNREPRESENTABLE VALUE MUST NEVER REMOVE INFORMATION THAT WAS GOING TO BE
// RECORDED OR RETURNED. Substitute, never drop, and say what was substituted.**
//
// That is §5.2.2's "the one unacceptable failure" — losing a record — applied to
// losing PART of one, and D77's rule that an expected boundary must be
// distinguishable from tampering: a field nobody could represent is a fact worth
// recording, and a field that vanished is indistinguishable from one that was
// never there.
//
// # What it deliberately does not do
//
// It does not FAIL the call. By the time this runs the side effect has already
// happened, and refusing afterwards tells a caller the write did not land when
// it did — which invites the retry that double-writes. Recording honestly is the
// only answer that does not create a worse problem than it solves.
//
// DESIGN.md references: §5.2.2, §5.4, §6, D35, D53, D77, D177.
package safestruct

import (
	"fmt"
	"math"
	"sort"

	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultBudget bounds one converted object, in approximate bytes.
//
// **AN UNBOUNDED RESULT IS A DISK-AMPLIFICATION DENIAL OF SERVICE, and the
// amplification is what makes it severe (D178).** A driver's result reaches the
// audit Effect detail, which reaches the WAL, which is FSYNCED — so a hostile or
// compromised upstream returning a large payload writes to Sekizui's disk once
// per command. Fill the audit volume and the sink fails; because a governance
// system cannot execute what it cannot record, the failure direction is
// FAIL-CLOSED, so an availability attack on the disk becomes a total outage.
// D147 names that inversion in another context: "an audit outage becomes a TOTAL
// outage where today it is a shipping backlog."
//
// 256 KiB because an effect detail describes an action rather than carrying a
// dataset, and a quarter of a megabyte is far past anything legitimate while
// still leaving room for a verbose upstream response. It is a DEPLOYMENT-level
// safety ceiling, not a per-principal budget: CapabilitySpec.MaxBytes is the
// per-principal question and is a different control that may only narrow this
// one (CONTRACTS 70, D71's asymmetry).
const DefaultBudget = 256 << 10

// TruncatedKey records that the budget was reached, so a short object is
// distinguishable from a complete one.
//
// The same rule as UnrepresentableKey and QueryResponse.truncated: an agent
// reasoning over a silently shortened result reaches confident wrong
// conclusions, so the shortening is stated rather than inferred.
const TruncatedKey = "sekizui.truncated"

// maxDepth bounds recursion into nested maps and slices.
//
// AN ATTACKER SUPPLIES THIS SHAPE, so the walk must not be the thing that fails.
// Deeply nested driver data is not a legitimate case — protobuf Structs are for
// describing an effect, not for carrying a tree — and a bound turns a stack
// overflow into a marker. Beyond it the value is substituted like any other
// unrepresentable one.
const maxDepth = 32

// UnrepresentableKey is where the list of substituted paths is recorded, so a
// reader of an audit row can tell "this field could not be represented" from
// "this field was not set".
//
// NAMESPACED, AND OVERWRITTEN RATHER THAN MERGED. A driver setting this key
// itself would otherwise be able to forge a clean bill of health, so whatever it
// wrote is replaced by what actually happened.
const UnrepresentableKey = "sekizui.unrepresentable_fields"

// Report says what had to be done to fit the data into a Struct.
type Report struct {
	// Substituted are the paths whose values protobuf could not represent.
	Substituted []string

	// Truncated is true when the budget was reached and fields were left out.
	Truncated bool
}

// Convert turns m into a Struct within budget, substituting a marker for any
// value protobuf cannot represent.
//
// The Struct is never nil for a non-nil map, and loses a key only to the budget
// — which is then recorded rather than left to be inferred.
func Convert(m map[string]any, budget int) (*structpb.Struct, Report) {
	if m == nil {
		return nil, Report{}
	}

	var rep Report
	fields := make(map[string]*structpb.Value, len(m)+1)

	// **SORTED, AND THAT IS A CORRECTNESS REQUIREMENT RATHER THAN TIDINESS.** Go
	// randomises map iteration, so truncating an unsorted walk would drop a
	// DIFFERENT set of fields on every run — and this object is hashed into the
	// audit chain. The same command would produce a different record each time,
	// two replicas would disagree, and a replay would report tampering for a
	// system working correctly (D77, D78). Sorting makes truncation deterministic.
	keys := make([]string, 0, len(m))
	for k := range m {
		// Whatever a driver put in a reserved key is not evidence about itself.
		if k == UnrepresentableKey || k == TruncatedKey {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	spent := 0
	for _, k := range keys {
		if spent >= budget {
			rep.Truncated = true
			break
		}
		v := convertValue(k, m[k], 0, &rep.Substituted)
		spent += len(k) + sizeOf(v)
		fields[k] = v
	}
	substituted := rep.Substituted

	if len(substituted) > 0 {
		sort.Strings(substituted)
		list := make([]*structpb.Value, 0, len(substituted))
		for _, p := range substituted {
			list = append(list, structpb.NewStringValue(p))
		}
		fields[UnrepresentableKey] = structpb.NewListValue(&structpb.ListValue{Values: list})
	}
	if rep.Truncated {
		fields[TruncatedKey] = structpb.NewBoolValue(true)
	}

	return &structpb.Struct{Fields: fields}, rep
}

// SizeOf is sizeOf, exported for the aggregate budget a caller spends across
// several objects — a query response bounds the whole set rather than each row,
// because a per-row bound does nothing against a million small rows.
//
// sizeOf approximates a converted value's serialised size.
//
// APPROXIMATE ON PURPOSE. `proto.Size` would be exact and would walk the value
// again on every field, turning a linear conversion into a quadratic one — which
// is a denial of service defending against a denial of service. What the budget
// needs is a BOUND, and an estimate within a small factor bounds just as well.
func SizeOf(s *structpb.Struct) int {
	n := 0
	for k, v := range s.GetFields() {
		n += len(k) + sizeOf(v)
	}
	return n
}

func sizeOf(v *structpb.Value) int {
	switch k := v.GetKind().(type) {
	case *structpb.Value_StringValue:
		return len(k.StringValue)
	case *structpb.Value_StructValue:
		n := 0
		for key, inner := range k.StructValue.GetFields() {
			n += len(key) + sizeOf(inner)
		}
		return n
	case *structpb.Value_ListValue:
		n := 0
		for _, inner := range k.ListValue.GetValues() {
			n += sizeOf(inner)
		}
		return n
	default:
		// Numbers, bools and null: small and fixed.
		return 8
	}
}

// convertValue converts one value, recording the path of anything substituted.
func convertValue(path string, v any, depth int, substituted *[]string) *structpb.Value {
	if depth > maxDepth {
		*substituted = append(*substituted, path)
		return structpb.NewStringValue(fmt.Sprintf(
			"<unrepresentable: nesting deeper than %d>", maxDepth))
	}

	switch typed := v.(type) {
	case map[string]any:
		fields := make(map[string]*structpb.Value, len(typed))
		for k, inner := range typed {
			fields[k] = convertValue(path+"."+k, inner, depth+1, substituted)
		}
		return structpb.NewStructValue(&structpb.Struct{Fields: fields})

	case []any:
		values := make([]*structpb.Value, 0, len(typed))
		for i, inner := range typed {
			values = append(values, convertValue(
				fmt.Sprintf("%s[%d]", path, i), inner, depth+1, substituted))
		}
		return structpb.NewListValue(&structpb.ListValue{Values: values})
	}

	// EVERYTHING ELSE GOES THROUGH structpb's OWN CONVERSION, so the set of
	// representable types is protobuf's rather than a list here that would drift
	// from it as the library changes (D155's copies-drift argument, applied to a
	// dependency's contract).
	val, err := structpb.NewValue(v)
	// **A NON-FINITE NUMBER IS UNREPRESENTABLE TOO, THOUGH structpb ACCEPTS IT.**
	// `NewValue(math.NaN())` succeeds, and the value then survives binary
	// protobuf — the bus, gRPC — and fails protojson with "invalid NaN value",
	// which is P3 criterion 4's encoding and every JSON sink's. So an envelope
	// the bus carried could not be written out, in D177's all-or-nothing shape.
	// P3 step 9's property test found it on its third generated envelope. The
	// marker names the kind and never the value, as below.
	if err == nil {
		if n, isNum := val.GetKind().(*structpb.Value_NumberValue); !isNum ||
			(!math.IsNaN(n.NumberValue) && !math.IsInf(n.NumberValue, 0)) {
			return val
		}
		*substituted = append(*substituted, path)
		return structpb.NewStringValue("<unrepresentable: non-finite number>")
	}

	*substituted = append(*substituted, path)
	// **THE TYPE, NEVER THE VALUE.** A driver's unrepresentable field could hold
	// credential material, and this string reaches the audit log and the caller.
	// Secret is self-redacting by type (§4.3.3), but an arbitrary struct holding
	// one is not, so the value never appears here at all.
	return structpb.NewStringValue(fmt.Sprintf("<unrepresentable: %T>", v))
}
