package acceptance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/internal/driver/mcp"
	"github.com/fullstorydev/sekizui/internal/retry"
	"github.com/fullstorydev/sekizui/pkg/config"
	sekizuiv1 "github.com/fullstorydev/sekizui/pkg/schema/sekizui/v1"
)

// The shapes the Fullstory MCP returned on 2026-09-24 (the maintainers' test org, synthetic),
// with values replaced — the step asserts shape and routing, never data.
const (
	reviewOpenText = `{"client_id":"REVIEW-HANDLE-1","events":[` +
		`{"page_id":"7263712229143864855","summary":"navigate^to^/","timestamp":5,"type":"navigate"},` +
		`{"page_id":"1059109945600013344","summary":"click^on^Login","timestamp":27009,"type":"click"}]}`
	reviewTreeText = "<session-data>\n[root ]\n  [textbox fs-1306] \"WHERE\"\n</session-data>"
	signedURL      = "https://storage.googleapis.com/example-mcp-artifacts/EXAMPLE/artifacts/SENTINELSHOT.png?Expires=1&Signature=SENTINELSIG"
	reviewShotText = "<session-data>\nScreenshot hosted in cloud storage.\nArtifact ID: SENTINELSHOT\n" +
		"URL (expires in 168h): " + signedURL + "\n\nFetch or share this URL to view the screenshot.\n</session-data>"
)

func textResult(text string) map[string]any {
	return map[string]any{"resultType": "complete",
		"content": []map[string]any{{"type": "text", "text": text}}}
}

// loadReviewSpec reads the SHIPPED fragment strictly — the file a deployment
// drops into its config directory is the file this step tests.
//
// **`fullstory-mcp.yaml` SINCE D308, `session-review.yaml` BEFORE.** The
// session-review tools now ship inside the whole MCP's one vetted fragment (D278
// refuses two fragments for one target), and this step still tests them there.
func loadReviewSpec(t *testing.T) config.MCPSpec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "connectors", "fullstory", "mcp.yaml"))
	if err != nil {
		t.Fatalf("step 25: the shipped spec: %v", err)
	}
	var frag struct {
		MCPSpecs map[string]config.MCPSpec `json:"mcp_specs"`
	}
	if err := yaml.UnmarshalStrict(raw, &frag); err != nil {
		t.Fatalf("step 25: the shipped spec does not load strictly: %v", err)
	}
	spec, ok := frag.MCPSpecs["fullstory-mcp"]
	if !ok {
		t.Fatal("step 25: the shipped spec names no `fullstory-mcp`")
	}
	return spec
}

// p3Step25 — the Fullstory MCP's session-review tools are callable, governed
// (D289, criterion 13).
func p3Step25(t *testing.T) {
	r := newRun(t)
	r.narrate(t, "the Fullstory MCP's session-review tools are callable through the governed path, "+
		"as the shipped vetted spec says")
	spec := loadReviewSpec(t)

	// 25a — THE SHIPPED SPEC IS WHAT IT CLAIMS, and valid beside a real target.
	byName := map[string]config.MCPToolSpec{}
	for _, tool := range spec.Tools {
		byName[tool.Name] = tool
		// EVERY TOOL THAT TAKES org_id PINS IT (D308). The pin exists because the
		// MCP reaches any org BY ARGUMENT; a tool with no org_id argument acts on
		// the credential's own org and has nothing to pin.
		takesOrg := strings.Contains(string(tool.InputSchema), `"org_id"`)
		if takesOrg && (len(tool.Pin) != 1 || tool.Pin[0] != "org_id") {
			t.Errorf("step 25a: %s takes org_id and pins %v; one target is one org", tool.Name, tool.Pin)
		}
		if !takesOrg && len(tool.Pin) != 0 {
			t.Errorf("step 25a: %s pins %v but takes no org_id — a pin on an absent argument", tool.Name, tool.Pin)
		}
	}
	switch {
	case spec.Host != "api.fullstory.com":
		t.Errorf("step 25a: the shipped spec is vetted against host %q", spec.Host)
	case byName["session_view"].Name != "":
		t.Error("step 25a: the shipped spec includes session_view, which Fullstory removed")
	case !byName["session_open"].Mutating || byName["session_open"].Idempotency != "none":
		t.Error("step 25a: session_open allocates a slot; it must be mutating and class none, never retried")
	case byName["session_close"].Idempotency != "natural":
		t.Error("step 25a: session_close releases a slot and is safe to repeat: class natural")
	case !byName["session_get_a11y_tree"].UserContent || !byName["session_diff"].UserContent:
		t.Error("step 25a: the tree and the diff carry what users typed; they are user_content")
	case !strings.Contains(string(byName["session_screenshot"].DataSchema), `"callerOnly":true`):
		t.Error("step 25a: the screenshot's signed URL is not callerOnly")
	}
	real := &config.Document{
		Targets: []config.TargetSpec{{Ref: "fullstory-mcp", Kind: mcp.Kind, Tenant: "acme", Residency: "eu",
			BaseURL: "https://api.fullstory.com/mcp/fullstory", CredentialRef: "env://FS_MCP_TOK",
			Settings: map[string]string{"org_id": "EXAMPLE"}}},
		MCPSpecs: map[string]config.MCPSpec{"fullstory-mcp": spec},
	}
	if err := real.Validate(); err != nil {
		t.Fatalf("step 25a: the shipped spec does not validate beside a real target: %v", err)
	}
	// session_open is never retried; session_close may be.
	drv := mcp.New(real.MCPSpecs)
	for _, a := range drv.Actions() {
		_, unsafe := retry.UnsafeToRetry(a.Mutating, a.Idempotency, "k")
		switch a.Name {
		case "mcp.fullstory.session_open":
			if !unsafe {
				t.Error("step 25a: a timed-out session_open would be RETRIED, leaking a slot nobody closes")
			}
		case "mcp.fullstory.session_close":
			if unsafe {
				t.Error("step 25a: session_close is repeat-safe and was refused a retry")
			}
		}
	}
	r.detail(t, "the shipped spec: host api.fullstory.com, org_id pinned on all %d tools, "+
		"session_open never retried, the URL caller-only", len(spec.Tools))

	// --- through the governed path, against a fixture standing in for Fullstory ---
	stack := newMCPStack(context.Background(), t, func(d *config.Document) {
		fixture := spec
		fixture.Host = "127.0.0.1" // the fixture stands in for api.fullstory.com
		d.MCPSpecs = map[string]config.MCPSpec{"fixture-mcp": fixture}
		d.Targets[0].Settings = map[string]string{"org_id": "EXAMPLE"}
		var allow []config.CapabilitySpec
		for _, tool := range spec.Tools {
			allow = append(allow, config.CapabilitySpec{Action: "mcp.fullstory." + tool.Name, TargetRef: "fixture-mcp"})
		}
		d.Grants = append(d.Grants, config.GrantSpec{Principal: "agent:dev", Allow: allow})
	})
	var live []mcp.LiveTool
	for _, tool := range spec.Tools {
		// A VENDOR-ORIGIN OUTPUT SCHEMA IS DRIFT-CHECKED TOO (§4.9a.7), so the
		// fixture advertises it exactly as the real server does (D308).
		lt := mcp.LiveTool{Name: tool.Name, InputSchema: tool.InputSchema}
		if tool.OutputSchemaOrigin == "vendor" {
			lt.OutputSchema = tool.OutputSchema
		}
		live = append(live, lt)
	}
	stack.up.offer(live...)
	stack.up.answer("session_open", textResult(reviewOpenText))
	stack.up.answer("session_get_a11y_tree", textResult(reviewTreeText))
	stack.up.answer("session_screenshot", textResult(reviewShotText))
	stack.up.answer("session_close", textResult(`{"success":true}`))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	call := func(tool string, args map[string]any) *sekizuiv1.CommandResult {
		t.Helper()
		res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
			Action: "mcp.fullstory." + tool, TargetRef: "fixture-mcp", Args: mustArgs(t, args)})
		if err != nil {
			t.Fatalf("step 25: %s: %v", tool, err)
		}
		return res
	}

	// 25b — THE PAYLOAD RULE: JSON-as-text arrives shaped, text as text.
	open := call("session_open", map[string]any{"session_id": "1:2"})
	got := open.GetResult().AsMap()
	if open.GetStatus() != sekizuiv1.Status_STATUS_OK || got["client_id"] != "REVIEW-HANDLE-1" || got["events"] == nil {
		t.Fatalf("step 25b: session_open's JSON-as-text did not arrive shaped: %s %v (%s)",
			open.GetStatus(), got, open.GetReason())
	}
	tree := call("session_get_a11y_tree", map[string]any{"client_id": "REVIEW-HANDLE-1",
		"page_id": "1059109945600013344", "timestamp": 27009})
	if s, _ := tree.GetResult().AsMap()["text"].(string); !strings.Contains(s, "textbox") {
		t.Errorf("step 25b: the accessibility tree did not arrive as text: %v (%s)", tree.GetResult().AsMap(), tree.GetReason())
	}

	// 25c — ARGUMENTS: the pin reaches the server; a foreign org, an argument
	// nobody vetted, and a wrong type are refused BEFORE it sees anything.
	if seen := stack.up.argsFor("session_open"); len(seen) != 1 || seen[0]["org_id"] != "EXAMPLE" {
		t.Fatalf("step 25c: the server saw %v; the target's own org_id must be injected", seen)
	}
	for _, c := range []struct {
		name string
		args map[string]any
		says string
	}{
		{"another org", map[string]any{"session_id": "1:2", "org_id": "OTHERORG"}, "pinned"},
		{"an argument nobody vetted", map[string]any{"session_id": "1:2", "exfiltrate": "x"}, "takes no argument"},
		{"a wrong type", map[string]any{"session_id": 12}, "must be string"},
	} {
		res := call("session_open", c.args)
		if res.GetStatus() == sekizuiv1.Status_STATUS_OK || !strings.Contains(res.GetReason(), c.says) {
			t.Errorf("step 25c: %s was not refused saying %q: %s (%s)", c.name, c.says, res.GetStatus(), res.GetReason())
		}
	}
	if n := len(stack.up.argsFor("session_open")); n != 1 {
		t.Errorf("step 25c: the server received %d session_open calls; the refused three must never reach it", n)
	}
	r.detail(t, "org_id injected at the far side; another org, an unvetted argument and a wrong type "+
		"refused before sending")

	// 25d — CALLER-ONLY: the caller gets the signed URL; the record holds a
	// trace and the URL nowhere, `text` included.
	shot := call("session_screenshot", map[string]any{"client_id": "REVIEW-HANDLE-1",
		"page_id": "1059109945600013344", "timestamp": 36259})
	sm := shot.GetResult().AsMap()
	if sm["url"] != signedURL || sm["artifact_id"] != "SENTINELSHOT" {
		t.Fatalf("step 25d: the caller did not get the featured fields: %v (%s)", sm, shot.GetReason())
	}
	var recorded string
	for _, d := range readLog(t, stack.logPath) {
		if d.GetId() == shot.GetDecisionId() && d.GetPhase() == sekizuiv1.Phase_PHASE_OUTCOME {
			b, _ := json.Marshal(d.GetEffect().GetDetail().AsMap())
			recorded = string(b)
		}
	}
	switch {
	case recorded == "":
		t.Fatal("step 25d: the screenshot's outcome is not in the log")
	case strings.Contains(recorded, "SENTINELSIG") || strings.Contains(recorded, "SENTINELSHOT.png"):
		t.Errorf("step 25d: the signed URL reached the audit record: %s", recorded)
	case !strings.Contains(recorded, "caller-only") || !strings.Contains(recorded, "sha256:"):
		t.Errorf("step 25d: the record carries no trace of the caller-only field: %s", recorded)
	}
	r.detail(t, "the caller received the signed URL; the record holds a trace and no copy of it")

	// 25e — CONFORMANCE: a type break is refused; an added field is stripped
	// and raised as tool_nonconforming.
	// A TARGET ERROR, SO IT ARRIVES AS A FAILURE rather than a deliberate
	// refusal (D135): the vendor broke its contract, which is not the caller's
	// request being refused. Either form must say the contract broke.
	stack.up.answer("session_close", textResult(`{"success":"yes"}`))
	res, err := stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fullstory.session_close", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"client_id": "REVIEW-HANDLE-1"})})
	said := res.GetReason()
	if err != nil {
		said = err.Error()
	}
	if (err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK) || !strings.Contains(said, "broke its output contract") {
		t.Errorf("step 25e: a type break in session_close's result was not refused as a broken contract: %s", said)
	}
	stack.up.answer("session_close", textResult(`{"success":true,"slots_left":3}`))
	closed := call("session_close", map[string]any{"client_id": "REVIEW-HANDLE-1"})
	if closed.GetStatus() != sekizuiv1.Status_STATUS_OK || closed.GetResult().AsMap()["slots_left"] != nil {
		t.Errorf("step 25e: an added field must pass, stripped: %s %v", closed.GetStatus(), closed.GetResult().AsMap())
	}
	if !strings.Contains(stack.driver.Nonconforming()["fixture-mcp"], "slots_left") {
		t.Error("step 25e: the added field raised no tool_nonconforming level")
	}
	// SEVERAL JSON BLOCKS FOR A TOOL THAT DECLARES NO `combine` ARE REFUSED — the
	// parity rule sekizui-mcpspec applies to the same result.
	stack.up.answer("session_close", map[string]any{"resultType": "complete", "content": []map[string]any{
		{"type": "text", "text": `{"success":true}`}, {"type": "text", "text": `{"success":true}`}}})
	res, err = stack.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fullstory.session_close", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"client_id": "REVIEW-HANDLE-1"})})
	said = res.GetReason()
	if err != nil {
		said = err.Error()
	}
	if (err == nil && res.GetStatus() == sekizuiv1.Status_STATUS_OK) || !strings.Contains(said, "declares no `combine`") {
		t.Errorf("step 25e: two JSON blocks were accepted by a tool that declares no combine: %s", said)
	}
	r.detail(t, "a type break refused; an added field stripped and raised as tool_nonconforming; "+
		"two JSON blocks refused without a declared combine")

	// 25f — THE VETTED HOST. The shipped spec pointed at another host is refused
	// at load and by the driver: its credential would go to a server nobody
	// reviewed (CONTRACTS 117, closed for MCP).
	elsewhere := *real
	elsewhere.Targets = []config.TargetSpec{real.Targets[0]}
	elsewhere.Targets[0].BaseURL = "https://mcp.example.test/fullstory"
	if err := elsewhere.Validate(); err == nil || !strings.Contains(err.Error(), "vetted against host") {
		t.Errorf("step 25f: the shipped spec pointed at another host loaded: %v", err)
	}
	if err := drv.AdmitBaseURL("fullstory-mcp", "https://mcp.example.test/fullstory"); err == nil {
		t.Error("step 25f: the driver admitted a host the spec was not vetted against")
	}
	r.detail(t, "the shipped spec pointed at another host: refused at load and by the driver")

	// 25g — A LENS REACHES AN MCP RESULT (D290). Imposed on the agent, it
	// withholds the tree's prose — the carrier of anything planted in it
	// (CONTRACTS 141) — so the agent's call is answered and it receives no text.
	lensed := newMCPStack(context.Background(), t, func(d *config.Document) {
		fixture := spec
		fixture.Host = "127.0.0.1"
		d.MCPSpecs = map[string]config.MCPSpec{"fixture-mcp": fixture}
		d.Targets[0].Settings = map[string]string{"org_id": "EXAMPLE"}
		d.Grants = append(d.Grants, config.GrantSpec{Principal: "agent:dev", Allow: []config.CapabilitySpec{
			{Action: "mcp.fullstory.session_get_a11y_tree", TargetRef: "fixture-mcp"}}})
		d.Shin = append(d.Shin, config.ShinSpec{
			Name: "agents-get-no-session-prose", Enabled: true, Mode: "imposed",
			AppliesTo: []string{"agent:dev"}, Type: "fullstory.review_a11y.v1",
			Withholds: []string{"text"},
			Because:   "an agent that acts must not receive prose a user or an attacker could have written (CONTRACTS 141)",
		})
	})
	lensed.up.offer(live...)
	lensed.up.answer("session_get_a11y_tree", textResult(reviewTreeText))
	lres, lerr := lensed.gw.Enforce(ctx, assertedIdentity("agent:dev"), &sekizuiv1.Command{
		Action: "mcp.fullstory.session_get_a11y_tree", TargetRef: "fixture-mcp",
		Args: mustArgs(t, map[string]any{"client_id": "REVIEW-HANDLE-1", "page_id": "p", "timestamp": 1})})
	switch {
	case lerr != nil || lres.GetStatus() != sekizuiv1.Status_STATUS_OK:
		t.Fatalf("step 25g: the lensed call failed: %v %s (%s)", lerr, lres.GetStatus(), lres.GetReason())
	case lres.GetResult().AsMap()["text"] != nil:
		t.Errorf("step 25g: an imposed lens withholding `text` did not reach the MCP result: %v",
			lres.GetResult().AsMap())
	}
	r.detail(t, "an imposed lens withheld the tree's prose from the agent; the call itself was answered")
}
