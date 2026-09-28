// Package obs is observability: logging today, OpenTelemetry later.
//
// PRIVATE (D35).
//
// TWO LAYERS OF SECRET REDACTION, and the first one is the real defence:
//
//  1. TYPE-BASED, in pkg/connector. connector.Secret implements slog.LogValuer,
//     so it renders as [REDACTED] through any handler including slog's stock
//     ones. It cannot be defeated by naming a field something unexpected,
//     because it consults no names (§4.3.3).
//
//  2. NAME-BASED, here. A backstop for values that are NOT self-redacting types
//     — a plain string that happens to hold a bearer token, a map from a vendor
//     response. Weaker by construction, since it can only catch keys it
//     recognises.
//
// The upgrade over Lexicon is in how layer 2 is applied. There, redaction was
// OPT-IN (loggerFramework.js:360 — infoSensitive() sanitised only if the caller
// remembered) and there were TWO DIVERGENT LISTS (loggerFramework.js:216 and
// initialization.js:218). Here it is one list, in one place, applied to every
// record unconditionally. A caller cannot forget.
//
// DESIGN.md references: §3 (loggerFramework port), §4.3.3, §12 P0.
package obs

import (
	"context"
	"log/slog"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/connector"
)

// Redacted is the replacement text. Shared with pkg/connector so a log line
// reads identically whichever layer caught the value.
const Redacted = connector.Redacted

// sensitiveFragments are matched as substrings against a normalised key
// (lowercased, with "_", "-", and "." removed). So "client_secret",
// "clientSecret", and "CLIENT-SECRET" all match "secret".
//
// DELIBERATELY NOT EXHAUSTIVE, and deliberately not aggressive. Over-redaction
// has a real cost: it destroys the debuggability that logs exist to provide, and
// a log full of [REDACTED] trains people to stop reading it. Bare "key" and bare
// "auth" are excluded for exactly this reason — they would swallow poolKey,
// idempotency_key, and auth_method, none of which are secrets. See
// TestDoesNotOverRedact, which pins those.
//
// THE RIGHT FIX for a new secret-bearing field is to give it a self-redacting
// TYPE (layer 1), not to extend this list. This list is what catches the case
// where somebody did not.
//
// Immutable, read-only after compile. It becomes configurable once config can
// carry it — a self-hoster with an unusual field name should not have to fork
// (D35) — at which point it stops being a package variable altogether.
//
//nolint:gochecknoglobals // immutable list; see above
var sensitiveFragments = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"credential",
	"apikey",
	"authorization",
	"cookie",
	"privatekey",
	"bearer",
}

// IsSensitive reports whether an attribute key should have its value redacted.
// Exported for tests and for anywhere else needing the same judgement.
func IsSensitive(key string) bool {
	k := strings.ToLower(key)
	k = strings.NewReplacer("_", "", "-", "", ".", "").Replace(k)

	for _, frag := range sensitiveFragments {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

// RedactingHandler wraps another slog.Handler and redacts by attribute name.
//
// Implements slog.Handler by delegation. The four methods are the whole
// interface: Enabled and WithGroup pass straight through, while Handle and
// WithAttrs rewrite attributes on the way past.
type RedactingHandler struct {
	next slog.Handler
}

// NewRedactingHandler wraps next. Returns slog.Handler rather than the concrete
// type so callers compose it without depending on the implementation.
func NewRedactingHandler(next slog.Handler) slog.Handler {
	return &RedactingHandler{next: next}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle rewrites the record's attributes, then delegates.
//
// A new Record is built rather than mutating the original: slog.Record is
// copied by value but shares backing storage for attributes, so mutating in
// place can corrupt a record another handler is holding.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redact(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs redacts the attributes being attached, so a secret bound once with
// logger.With() does not leak on every subsequent record.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cleaned := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		cleaned[i] = redact(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(cleaned)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

// redact resolves and, if needed, replaces one attribute.
//
// RESOLVE FIRST, deliberately. Resolve invokes LogValuer, which is layer 1 — so
// a connector.Secret has already become [REDACTED] before the name check runs,
// and a LogValuer returning a group gets walked rather than treated as opaque.
func redact(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()

	// Groups recurse: a secret nested three levels down is still a secret.
	if a.Value.Kind() == slog.KindGroup {
		src := a.Value.Group()
		dst := make([]slog.Attr, len(src))
		for i, g := range src {
			dst[i] = redact(g)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(dst...)}
	}

	if IsSensitive(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// Options configures the process logger.
type Options struct {
	Level slog.Level

	// JSON selects the machine-readable handler. True in any deployed
	// environment; text is for a terminal.
	JSON bool

	// AddSource attaches file:line. Off by default — it is measurably
	// expensive, and the message plus attributes usually locate a line anyway.
	AddSource bool
}

// NewLogger builds the process logger: a stock handler wrapped in redaction.
//
// The wrapping is not optional and there is no constructor that omits it. An
// "unredacted logger for debugging" is precisely the thing that ends up in
// production, so the type system does not offer one.
func NewLogger(w interface{ Write([]byte) (int, error) }, opt Options) *slog.Logger {
	ho := &slog.HandlerOptions{Level: opt.Level, AddSource: opt.AddSource}

	var base slog.Handler
	if opt.JSON {
		base = slog.NewJSONHandler(w, ho)
	} else {
		base = slog.NewTextHandler(w, ho)
	}
	return slog.New(NewRedactingHandler(base))
}
