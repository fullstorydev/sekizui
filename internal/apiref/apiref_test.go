package apiref

import (
	"strings"
	"testing"
)

// The minifier writes chunk 5000 as `5e3`; a key read as "3" fetches the wrong
// chunk and silently loses the page (D312).
func TestChunkIDNormalisesExponentKeys(t *testing.T) {
	for in, want := range map[string]string{"5e3": "5000", "1e4": "10000", "4931": "4931"} {
		if got := chunkID(in); got != want {
			t.Errorf("chunkID(%q) = %q, want %q", in, got, want)
		}
	}
}

// The page metadata is JSON inside a JavaScript single-quoted string: `\\` is one
// backslash and `\'` one quote, and every other escape belongs to the JSON.
func TestJSStringUndoesOnlyTheJavaScriptLayer(t *testing.T) {
	got, err := jsString(`{"a":"it\'s","b":"x\\\\y","c":"\\u00e9"}' + more`)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":\"it's\",\"b\":\"x\\\\y\",\"c\":\"\\u00e9\"}"; got != want {
		t.Errorf("jsString = %s, want %s", got, want)
	}
	if _, err := jsString(`never closes`); err == nil {
		t.Error("an unterminated literal must be an error, not a partial string")
	}
}

func TestOperationOfReadsTheResolvedContract(t *testing.T) {
	chunk := []byte(`x=JSON.parse('{"frontMatter":{"api":{"operationId":"ctx","method":"post",` +
		`"path":"/v2/sessions/{session_id}/context","x-fullstory-permission-level":"Standard",` +
		`"parameters":[{"name":"session_id","in":"path","required":true}],` +
		`"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"slice":{"type":"object"}}}}}},` +
		`"responses":{"400":{"content":{"application/json":{"schema":{"type":"object"}}}},` +
		`"200":{"content":{"application/json":{"schema":{"type":"object","properties":{"context_data":{}}}}}}},` +
		`"servers":[{"url":"https://api.fullstory.com"}]}}}')`)
	op, ok, err := operationOf(chunk)
	if err != nil || !ok {
		t.Fatalf("operationOf: %v %v", ok, err)
	}
	switch {
	case op.Key() != "POST /v2/sessions/{session_id}/context":
		t.Errorf("key %q", op.Key())
	case !strings.Contains(string(op.RequestBody), "slice"):
		t.Errorf("request body %s", op.RequestBody)
	case !strings.Contains(string(op.Response), "context_data"):
		t.Errorf("the SUCCESS response must be read, not the first status: %s", op.Response)
	case op.Permission != "Standard" || len(op.Servers) != 1:
		t.Errorf("permission %q servers %v", op.Permission, op.Servers)
	}
	if _, ok, _ := operationOf([]byte(`x=JSON.parse('{"frontMatter":{"title":"prose"}}')`)); ok {
		t.Error("a prose page produced an operation")
	}
}
