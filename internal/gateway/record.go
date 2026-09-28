package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// maxRecordedString bounds one string in a RECORDED result (D289). It was the
// MCP driver's cap on every text result, which cut the PAYLOAD too — so a 40 KB
// JSON transcript was truncated before anything could parse it. The payload is
// now whole; the record, which is fsynced, is what is bounded.
const maxRecordedString = 4096

// forRecord is the copy of a result that is WRITTEN, as distinct from the copy
// that is RETURNED (D289).
//
// **THE ONE DELIBERATE BREAK FROM D177's "caller and record agree", and each of
// its three differences is a thing the record must not hold:**
//
//   - A callerOnly field (Fullstory's seven-day signed screenshot URL — a bearer
//     link to customer imagery) is replaced by a TRACE: its name and a hash, so
//     the audit trail stays complete and a leaked link can be matched to the
//     call that produced it, without the record holding the link.
//   - That value is SCRUBBED from every other string in the record, because a
//     text result carries it too — a caller-only URL beside an admitted `text`
//     containing it would reach the log through `text`.
//   - Any string over maxRecordedString is cut, and says so.
//
// Returns data unchanged — no copy — when there is nothing to do.
func (s *Server) forRecord(spec connector.ActionSpec, data map[string]any) map[string]any {
	var callerOnly []string
	if s.payloads != nil && spec.OutputType != "" {
		callerOnly = s.payloads.CallerOnly(spec.OutputType)
	}
	if data == nil {
		return nil
	}
	out := deepCopy(data).(map[string]any)
	type secret struct{ field, value string }
	var secrets []secret
	for _, f := range callerOnly {
		v, present := out[f]
		if !present {
			continue
		}
		str := fmt.Sprint(v)
		sum := sha256.Sum256([]byte(str))
		out[f] = "[caller-only: returned to the caller, not recorded — sha256:" +
			hex.EncodeToString(sum[:])[:16] + "]"
		if str != "" {
			secrets = append(secrets, secret{f, str})
		}
	}
	// LONGEST FIRST, so a value containing another is scrubbed whole.
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i].value) > len(secrets[j].value) })
	var walk func(v any) any
	walk = func(v any) any {
		switch val := v.(type) {
		case map[string]any:
			for k, x := range val {
				if isCallerOnly(k, callerOnly) {
					continue // the trace itself
				}
				val[k] = walk(x)
			}
			return val
		case []any:
			for i, x := range val {
				val[i] = walk(x)
			}
			return val
		case string:
			for _, sec := range secrets {
				val = strings.ReplaceAll(val, sec.value, "[caller-only: "+sec.field+"]")
			}
			if len(val) > maxRecordedString {
				val = val[:maxRecordedString] + "… (truncated in the record; the caller received all of it)"
			}
			return val
		}
		return v
	}
	return walk(out).(map[string]any)
}

func isCallerOnly(k string, fields []string) bool {
	for _, f := range fields {
		if f == k {
			return true
		}
	}
	return false
}

// deepCopy copies the JSON-shaped values a result carries, so the recorded copy
// never aliases the returned one.
func deepCopy(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, x := range val {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, x := range val {
			out[i] = deepCopy(x)
		}
		return out
	}
	return v
}
