# Sekizui build entrypoints.
#
# EVERY target confines Go's caches and tool binaries to this directory. Nothing
# is written outside this directory (D34): an ambient GOPATH belongs to whatever
# else is on the machine, and Sekizui must not add to it. Hence the explicit
# overrides below rather than inheriting.

SEKIZUI_ROOT := $(shell pwd)
# THE TOOLCHAIN: whatever `go` is on PATH — a CI runner after actions/setup-go, or a
# contributor's laptop. go.mod's `toolchain` line asks for the patched release
# (D343). An explicit GOROOT=... still wins.
GOROOT       ?= $(shell go env GOROOT 2>/dev/null)
GO           := $(GOROOT)/bin/go

# Everything Go writes lands here.
export GOPATH      := $(SEKIZUI_ROOT)/.gocache/gopath
export GOMODCACHE  := $(SEKIZUI_ROOT)/.gocache/mod
export GOCACHE     := $(SEKIZUI_ROOT)/.gocache/build
export GOBIN       := $(SEKIZUI_ROOT)/bin
export GOWORK      := off
# Live switches are never inherited from the shell: only acceptance-live, demo-live and
# capture-seiren set them, for their own recipes.
unexport SEKIZUI_FULLSTORY_WRITE SEKIZUI_DEMO_LIVE SEKIZUI_CAPTURE_STEP18
# GOROOT/bin is on PATH because some tools SHELL OUT to `go` rather than using
# the toolchain we hand them — golangci-lint runs `go env` and `go list`, and
# fails with "go command required, not found" without this. The repo toolchain
# may not be on the ambient PATH, so it is added here.
export PATH        := $(SEKIZUI_ROOT)/bin:$(GOROOT)/bin:$(PATH)

# Pinned tool versions. Bump deliberately, never with @latest — a floating
# codegen version means generated code that differs between machines, which
# defeats committing it (D34).
# protoc-gen-go MUST match the google.golang.org/protobuf version in go.mod.
# They are one module: the plugin emits code against the runtime it shipped
# with, so a plugin older than the runtime is drift that compiles today and
# stops compiling on some later bump. It was v1.36.5 against a runtime that
# `go mod tidy` had resolved to v1.36.11 — aligned to v1.36.12, and go.mod
# pins the library to the same number. Change both together, always.
PROTOC_GEN_GO      := v1.36.12

# Separate module with its own version line — NOT tied to google.golang.org/grpc
# (v1.83.2 in go.mod). v1.5.1 -> v1.6.2 is current stable.
PROTOC_GEN_GO_GRPC := v1.6.2

BUF                := v1.47.2

# §6 item 4 asks for a CI lint banning package-level mutable state. Pinned like
# everything else: a floating linter version means `make lint` passes on one
# machine and fails on another.
GOLANGCI_LINT      := v2.6.2

.PHONY: help
help:
	@echo "tools     install pinned codegen tools into ./bin"
	@echo "generate  buf generate -> pkg/schema (requires tools)"
	@echo "lint      buf lint + go vet + gofmt check"
	@echo "build     go build ./..."
	@echo "test      go test -race ./..."
	@echo "verify    lint + build + test"
	@echo "acceptance run EVERY phase's graduation scenario -> ./out/{acceptance.jsonl,.md,.prom}"
	@echo "acceptance-live  the same, PLUS the three steps that reach the real Fullstory org"
	@echo "live-config  write dev/fullstory-live.yaml: the org, user and session the live arms reach"
	@echo "dev-certs generate a local CA and mTLS identities into ./dev/certs"
	@echo "demo      drive a LIVE sekizui (run \`make run\` in another terminal first)"
	@echo "demo-refusals  run the real binary and watch a BOOT and a REQUEST refusal happen"
	@echo "mutate    break one guarantee at a time and check its step notices (scoped, D281)"
	@echo "mutate-full  the same, re-running the whole suite per mutation"
	@echo "run       run the gateway locally against the acceptance config"
	@echo "breaking  buf breaking against a baseline ref (D44)"
	@echo "ci        everything CI runs, locally (CI itself is a skeleton until P4)"
	@echo "clean     remove ./bin and ./.gocache"

# Installs into ./bin using ./.gocache as the module cache. buf is installed
# locally too: the ambient buf is 1.8.0 (2022) and lives outside this directory,
# so depending on it would violate self-containment (D34).
.PHONY: tools
tools:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC)
	$(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT)
	@echo "installed:" && ls ./bin

.PHONY: generate
generate:
	./bin/buf generate proto
	$(GO) mod tidy

# Listed literally, NOT via $(wildcard). All three exist, and if one stops
# existing that should fail loudly rather than being silently skipped — a lint
# target that quietly checks less than it claims is worse than one that breaks.
#
# This briefly was a wildcard, while cmd/ did not yet exist. That hid a real
# formatting error behind "stat cmd: no such file or directory".
GOFMT_DIRS := pkg internal cmd

.PHONY: lint
lint:
	./bin/buf lint
	@test -z "$$($(GOROOT)/bin/gofmt -l $(GOFMT_DIRS))" \
		|| { echo "gofmt needed:"; $(GOROOT)/bin/gofmt -l $(GOFMT_DIRS); exit 1; }
	$(GO) vet ./...
	./bin/golangci-lint run ./...

# D44: the evolution rules in D41 only hold if a machine checks them.
# Guards the envelope. Payload JSON Schemas have their own checker in
# internal/schemareg; wiring the two together is CONTRACTS §4 item 4.
#
# The baseline is read from the repository's own history, so a guard that exists
# cannot silently compare against nothing.
GIT_ROOT := $(shell git rev-parse --show-toplevel)

BREAKING_BASELINE ?= main

.PHONY: breaking
breaking:
	@if ! git -C $(GIT_ROOT) ls-tree -r --name-only $(BREAKING_BASELINE) \
		-- proto 2>/dev/null | grep -q '\.proto$$'; then \
		echo "SKIPPED: $(BREAKING_BASELINE) has no sekizui protos to compare against."; \
		echo "  A compatibility check needs a baseline. This becomes meaningful once the"; \
		echo "  contracts are on $(BREAKING_BASELINE) — and per D38 they are v0.x and"; \
		echo "  deliberately breakable until P4, so there is nothing to protect yet."; \
		echo "  Override with: make breaking BREAKING_BASELINE=<ref>"; \
		exit 0; \
	fi; \
	./bin/buf breaking \
		--against '$(GIT_ROOT)/.git#branch=$(BREAKING_BASELINE)'

.PHONY: build
build:
	$(GO) build ./...

# -race is not optional here. The cross-pollination guarantee (§6) is a test
# artifact, not a review artifact.
.PHONY: test
test:
	$(GO) test -race ./...

# P0's graduation evidence: one scripted run through every capability that
# exists, writing an audit log a human can read (D74).
#
# Separate from `test` because the ARTIFACT is the point. The same assertions
# run under `make test`; this target puts the log somewhere you will look.
.PHONY: acceptance
acceptance:
	@mkdir -p ./out
	@# Regenerated evidence, not an accumulating log. The JSONL sink APPENDS —
	@# correct for a real audit trail, wrong for an artifact rebuilt each run,
	@# where it would stitch two process lifetimes into one file.
	@# The shipper's cursors go WITH the WAL they index (D321): left behind, they
	@# point past the end of the new file, and the shipper refuses to go on.
	@rm -f ./out/acceptance.jsonl ./out/acceptance.jsonl.ship.* ./out/acceptance.prom ./out/acceptance.md
	@# EVERY phase, not just the newest (D107). The runs are a regression suite:
	@# P0's assertions get re-checked against whatever the system currently is,
	@# which is what catches a later phase breaking an earlier guarantee.
	@# Unbuilt steps skip loudly with the assertion they will make.
	SEKIZUI_ACCEPTANCE_OUT=$(SEKIZUI_ROOT)/out/acceptance.jsonl \
		$(GO) test -count=1 -v -run 'TestP[0-9]+Acceptance' ./internal/acceptance/
	@echo
	@echo "audit log written to ./out/acceptance.jsonl"
	@echo "evidence report     ./out/acceptance.md      (every step cites its audit lines)"
	@echo "metrics scrape      ./out/acceptance.prom"

# THE SAME RUN, PLUS THE TWO STEPS THAT WRITE TO A REAL FULLSTORY ORG (D229).
#
# Separated from `acceptance` because possession of dev/secrets/fullstory.key
# is a capability and not a decision to use it. `make acceptance` on the machine
# holding that key used to append an event and upsert a user on EVERY run, and
# `mutate` re-runs the suite once per mutation — so `make ci` wrote about 140
# undoable records into the maintainers' test org and spent ten minutes doing it. The intent
# belongs in the target a human types.
.PHONY: acceptance-live
acceptance-live: export SEKIZUI_FULLSTORY_WRITE=1
acceptance-live: acceptance

# LIVE COORDINATES: dev/fullstory-live.yaml (gitignored), each field overridable by
# SEKIZUI_LIVE_KEY / _UID / _SESSION / _SESSION_URL; `make live-config` writes a commented
# template. The org is read from the session URL. Values are read INSIDE the recipe and never
# spliced into shell source, and the key must sit under dev/secrets, the declared credential root.
LIVE_CONFIG ?= dev/fullstory-live.yaml

.PHONY: live-config
live-config:
	@test ! -e $(LIVE_CONFIG) || { echo "$(LIVE_CONFIG) exists; not overwriting it"; exit 1; }
	@mkdir -p $(dir $(LIVE_CONFIG))
	@cp internal/acceptance/fullstory-live.example.yaml $(LIVE_CONFIG)
	@echo "wrote $(LIVE_CONFIG) — fill in every field; each says where its value comes from"

# THE LIVE DEMO (D324): D52's union against Fullstory's REAL MCP on the maintainers' test org. TWO TERMINALS:
#
#   make run-live     # renders internal/acceptance/live.d into out/live.d and serves it, -residency us
#   make demo-live    # agent:union is refused every MCP tool by the union, before any call out;
#                     # agent:union-native holds both doors and one read is served through the real MCP
#
# Its own instance because it reaches the REAL MCP; both serve us since D326. The keys are the capture
# deployment's, gitignored under dev/secrets. Each `make demo-live` makes one real, read-only MCP call.
.PHONY: run-live demo-live
run-live: dev-certs
	@field() { v=$$(printenv "$$2"); [ -n "$$v" ] || v=$$(sed -n "s/^$$1:[[:space:]]*//p" $(LIVE_CONFIG) 2>/dev/null); printf '%s' "$$v"; }; \
	key=$$(field key SEKIZUI_LIVE_KEY); url=$$(field session_url SEKIZUI_LIVE_SESSION_URL); \
	case "$$key" in /*) ;; ?*) key="$(SEKIZUI_ROOT)/$$key";; esac; \
	org=$$(printf '%s' "$$url" | sed -n 's|^https://app\.fullstory\.com/ui/\([A-Za-z0-9-]*\)/session/[0-9][0-9]*\(:\|%3A\)[0-9][0-9]*$$|\1|p'); \
	case "$$key" in "$(SEKIZUI_ROOT)/dev/secrets/"*) ;; *) echo "the live demo's key must be a file under dev/secrets/ (the credential root); $(LIVE_CONFIG) or SEKIZUI_LIVE_KEY names '$$key' — run: make live-config"; exit 1;; esac; \
	[ -f "$$key" ] || { echo "no key file at $$key"; exit 1; }; \
	[ -n "$$org" ] || { echo "the live demo needs session_url, an NA1 Fullstory session link — run: make live-config"; exit 1; }; \
	rm -rf ./out/live.d && mkdir -p ./out/live.d ./out/live; \
	for f in internal/acceptance/live.d/*.yaml; do \
		sed -e 's#@SEKIZUI_ROOT@#$(SEKIZUI_ROOT)#g' -e "s#@SEKIZUI_LIVE_ORG@#$$org#g" -e "s#@SEKIZUI_LIVE_KEY@#$$key#g" \
			"$$f" > ./out/live.d/$$(basename "$$f"); done
	$(GO) run ./cmd/sekizui \
		-config ./out/live.d -demo \
		-wal ./out/live -residency us -log-text -log-level debug \
		-file-credential-root $(SEKIZUI_ROOT)/dev/secrets \
		-tls-cert dev/certs/server.crt \
		-tls-key dev/certs/server.key \
		-tls-client-ca dev/certs/ca.crt

demo-live:
	@test -f dev/certs/ca.crt || { echo "no development certificates — run: make dev-certs"; exit 1; }
	SEKIZUI_DEMO_LIVE=1 \
	SEKIZUI_ACCEPTANCE_TARGET=localhost:8443 \
	SEKIZUI_ACCEPTANCE_CERTS=$(SEKIZUI_ROOT)/dev/certs \
		$(GO) test -count=1 -v -run 'TestP4Acceptance/12_' ./internal/acceptance/

# P4 STEP 18's FIXTURE (D317): real Generate Context rows from the maintainers' test org, fetched
# THROUGH THE REAL BINARY — governed, recorded, shaped — into
# internal/connectors/fullstory/testdata/seiren/. READ-ONLY: the capture
# deployment's one grant is two reads. TWO TERMINALS:
#
#   make run-capture       # serves internal/acceptance/capture.local.d (gitignored)
#   make capture-seiren    # drives it; output kept in out/capture-seiren.log
#
# The binary, not the in-process harness, because the harness resolves env://
# credentials only and the MCP target uses the client-credentials grant (D307).
# Discovery reads an error-click metric through the MCP;
# SEKIZUI_STEP18_SESSION=<session url> skips it.
CAPTURE_CONFIG ?= internal/acceptance/capture.local.d

.PHONY: run-capture
run-capture: dev-certs
	@test -d $(CAPTURE_CONFIG) || { echo "no $(CAPTURE_CONFIG) — it is local and gitignored"; exit 1; }
	@mkdir -p ./out/capture
	$(GO) run ./cmd/sekizui \
		-config $(CAPTURE_CONFIG) \
		-wal ./out/capture -residency us -log-text -log-level debug \
		-file-credential-root $(SEKIZUI_ROOT)/dev/secrets \
		-tls-cert dev/certs/server.crt \
		-tls-key dev/certs/server.key \
		-tls-client-ca dev/certs/ca.crt

.PHONY: capture-seiren
capture-seiren:
	@mkdir -p ./out
	@set -o pipefail; \
	SEKIZUI_CAPTURE_STEP18=1 \
	SEKIZUI_ACCEPTANCE_TARGET=localhost:8443 \
	SEKIZUI_ACCEPTANCE_CERTS=$(SEKIZUI_ROOT)/dev/certs \
	SEKIZUI_ACCEPTANCE_OUT=$$(mktemp -d)/capture.jsonl \
		$(GO) test -count=1 -v -timeout 20m -run 'TestCaptureStep18Fixture' ./internal/acceptance/ \
		2>&1 | tee ./out/capture-seiren.log

# TEST THE TESTS. A test that has never been made to fail is a test whose passing
# means nothing (CONTRACTS 59), and sabotaging 68 steps by hand does not scale —
# worse, it checks the steps somebody thought to check.
#
# This inverts the question: break a real guarantee in the PRODUCT, and ask which
# step notices. A mutation nothing catches is a guarantee nothing proves. It found
# three on its first run, one of which — nothing proved that a refused audit record
# leaves the hash chain unadvanced (D89) — had been asserted in a decision for
# months.
#
# NOT PART OF `verify`, deliberately: it rebuilds once per mutation. Run it when
# the guarantees change, not on every save.
#
# **SCOPED SINCE D281.** Each mutation runs only the acceptance steps expected to
# catch it, not the whole suite — the full-suite-per-mutation form had grown to
# over thirty minutes and grows with every phase. A too-narrow scope fails loud,
# as a survivor; a scope naming a missing step is refused. `mutate-full` is the
# unscoped audit, for when you want to know a scope has not drifted.
.PHONY: mutate mutate-full
mutate:
	python3 scripts/mutate.py

mutate-full:
	python3 scripts/mutate.py --full

# REFUSE TO PROCEED ON A SABOTAGED TREE.
#
# `mutate` restores each file in a `finally`, which covers a failure and an
# exception and NOT a SIGKILL — so an interrupted run (a pkill, a CI timeout, a
# closed laptop) leaves exactly one file mutated and every later test result is
# about sabotaged code. The leftover that prompted this was D177's, and it
# surfaced as a failing acceptance step in a subsystem nobody had touched.
#
# In `verify` because that is what everybody runs first, and it costs a few
# string searches.
.PHONY: mutation-clean
mutation-clean:
	@python3 scripts/mutate.py --check-clean

.PHONY: verify
verify: mutation-clean lint build test

# Everything .github/workflows/verify.yml runs, in the same order.
#
# The workflow is inert where it sits (GitHub reads workflows from the REPO
# root, and Sekizui is a subdirectory), so this target is how the pipeline is
# actually exercised until Sekizui gets its own repository. Keeping them in step
# is manual and worth doing: a CI config nobody can run locally drifts.
.PHONY: ci
# ci is verify plus the artefacts too slow for a save loop.
#
# **MUTATE RUNS HERE, AND THAT IS WHAT MAKES "RUN IT WHEN THE GUARANTEES CHANGE"
# ENFORCEABLE RATHER THAN REMEMBERED (D162).** It stays out of `verify` for the
# reason D161 gives — one rebuild and one full suite run per mutation, minutes
# rather than seconds, and a check that slows every save is a check people route
# around. But a discipline nobody is required to follow is the same shape as a
# conformance suite nobody is required to run (D160), and this session proved it:
# `isMutating` was removed, `verify` went green, and the D140 mutation's anchor
# had silently vanished until `mutate` was run by hand. The coverage claim was
# false in between, and nothing would have said so.
ci: lint build test breaking acceptance mutate

.PHONY: clean
clean:
	rm -rf ./bin ./.gocache ./out

# DEVELOPMENT CERTIFICATES. The gateway requires verified client certificates
# with no way to disable that, so a local run needs a CA — this generates one.
#
# ./dev is gitignored. A committed private key is a committed private key
# whatever the comment above it says.
.PHONY: dev-certs
# THIS LIST MUST MATCH `acceptancePrincipals` in the harness, and P1 step 39
# fails when it does not.
#
# It drifted the moment break-glass added `operator:oncall` and the binding
# classes added `agent:binding`: `make demo` then failed with a message telling
# the operator to run `make dev-certs` — which regenerated the SAME five
# identities and did not fix it. An error naming a remedy that does not work is
# worse than one naming none, and it is the same disconnect-between-two-files
# shape D115 produced in the demo target itself.
dev-certs:
	$(GO) run ./cmd/sekizui-devcert -dir dev/certs \
		-principals "agent:triage,mesh:primary,agent:global,agent:bulk,agent:analytics,operator:oncall,agent:binding,agent:idempotency,agent:jobs,agent:metered,agent:scoped,agent:analyst,agent:support,agent:auditor,agent:union,agent:union-native,agent:showcase"

# RUN THE REAL THING LOCALLY, against the acceptance configuration.
#
# -log-level debug, because a developer watching a terminal IS the human the
# level policy exists to serve. Production defaults to info, where stdout carries
# what someone should NOTICE — refusals and failures — while the audit log keeps
# what must be RECORDED. Locally there is no separation worth making: you want
# to see everything, and `make demo` is far more convincing when you can.
#
# Depends on dev-certs rather than documenting the prerequisite in a comment
# nobody reads: a target that fails with "no such file: dev/certs/server.crt"
# has taught the operator nothing.
.PHONY: run
# CONFIG is overridable so a LOCAL configuration can be driven without editing
# the committed one. `*.local.yaml` and `*.local.d/` are gitignored, which is
# where a real client id and an absolute credential path belong — the
# acceptance config is reviewed and must not carry either. A local config is a
# DIRECTORY since D278: the shared document symlinked in, plus local files,
# composed with nothing overriding — so it cannot drift from the shared one.
#
#   make run CONFIG=internal/acceptance/acceptance.local.d
# THE DEMO DEPLOYMENT BY DEFAULT (D315): acceptance.yaml COMPOSED with the fragments a connector
# ships (the Fullstory anzen ceiling) and a showcase grant, so `make run` then `make demo` shows
# what the in-process steps prove. The in-process run still loads acceptance.yaml alone.
CONFIG ?= internal/acceptance/demo.d

run: dev-certs
	@# AUDIT SHIPPING, VISIBLE (D319, D324): two destinations routed by residency.
	@# The boot log names each route; out/demo-audit/ is for a person to read —
	@# no remote demo arm reads the instance's disk (the maintainer).
	@mkdir -p ./out/demo-audit
	SEKIZUI_ACCEPT_TOK=local-development-token \
	SEKIZUI_REGION=us-central1 \
	$(GO) run ./cmd/sekizui \
		-config $(CONFIG) -demo \
		-wal ./out -residency us -log-text -log-level debug \
		-audit-sink ./out/demo-audit/eu.jsonl:eu,./out/demo-audit/us.jsonl:us \
		-tls-cert dev/certs/server.crt \
		-tls-key dev/certs/server.key \
		-tls-client-ca dev/certs/ca.crt

# WATCH IT HAPPEN, rather than read that it did (D115).
#
# `make run` in one terminal, `make demo` in another. Drives the wire-traversable
# acceptance steps against a real instance over mTLS, so the evidence is
# something a person sees. Reflex steps are skipped and say why — they call the
# engine in-process by design (D69), which is the architecture rather than a
# limitation of this target.
.PHONY: demo
demo:
	@test -f dev/certs/ca.crt || { \
		echo "no development certificates — run: make dev-certs"; exit 1; }
	SEKIZUI_ACCEPTANCE_TARGET=localhost:8443 \
	SEKIZUI_ACCEPTANCE_CERTS=$(SEKIZUI_ROOT)/dev/certs \
		$(GO) test -count=1 -v -run 'TestP[0-9]+Acceptance' ./internal/acceptance/

# THE OTHER HALF OF "WATCH IT HAPPEN" (D115).
#
# `make demo` drives a RUNNING instance, which is the right shape for everything
# the enforcement path does and structurally incapable of showing a boot
# refusal — a refused boot leaves nothing to drive. P1 has since filled up with
# them: D97's env:// rule, D98's empty credential and cross-cloud claim, D142's
# operational ceilings, D150's config identity. This target runs the real binary
# against deliberately broken configurations and prints each refusal.
#
# **AND, SINCE D235, THE THIRD KIND OF REFUSAL: a refusal of a REQUEST.** D215
# bounds a caller-controlled string that would otherwise be fsynced onto every
# decision a command produces, and that refusal was watchable by nothing: it
# needs a LIVE instance and a client willing to send something malformed, which
# `demo` (no bad clients) and the boot cases here (no live instance) could
# neither of them express. `TestRuntimeRefusalsAreVisible` launches the binary on
# free ports, dials it over mTLS with a CA-signed certificate, sends an oversized
# idempotency key, and prints the status, kind, decision id and reason — then
# proves the instance is STILL SERVING, because a caller's mistake must not take
# the deployment with it.
#
# **AND, SINCE D188, THE POSITIVE HALF OF BOOT TOO.** Refusals were the only part
# anybody checked; what a SUCCESSFUL boot says was read by nobody, which is how
# D186 could trade an init-ledger entry for a WARN line that nothing verified was
# emitted. `TestBootDisclosuresAreVisible` requires every ledger entry, every
# unimplemented idempotency class and every non-rotating credential to be named,
# each DERIVED from its own source rather than listed. Both run here so a person
# watches boot succeed and boot refuse in one place; both are ordinary tests, so
# `make verify` checks them on every save.
#
# Needs dev certs, because gateway:serve validates TLS before it builds the
# enforcement stack — so a config error is invisible until the certificates are
# right. No server required, and it does not touch a running one.
#
# DOES NOT DEPEND ON dev-certs, and that is deliberate rather than an omission.
# `dev-certs` regenerates the CA every time it runs, so depending on it here
# invalidated the certificates a running `make run` was already serving with —
# and the next `make demo` failed with "certificate signed by unknown authority",
# which reads exactly like a Sekizui bug and is not one. `make demo` had already
# solved this by CHECKING rather than depending; this copied `make run` instead.
# THE CONNECTOR KATA'S EXERCISE (D218).
#
# **IT IS MEANT TO FAIL, which is why it is not part of `test` or `ci`.** A
# teaching artefact that must fail cannot live inside a runner that requires
# green, so the exercise's tests are behind `-tags hako` and this is how a human
# runs them. Each failure names the hako/BLUEPRINT.md step that closes it.
#
# The half that IS in CI is `hako/solution`, which runs the same published
# conformance suite and passes — so if the suite gains an arm, the answer key
# breaks in CI rather than a release later.
.PHONY: hako
hako:
	@echo "The connector kata. Every failure below names a blueprint step."
	@echo "Answer key: hako/solution. Read hako/BLUEPRINT.md alongside."
	@echo
	-$(GO) test -race -count=1 -tags hako -v ./hako/exercise/

.PHONY: demo-refusals
demo-refusals:
	@test -f dev/certs/ca.crt || { \
		echo "no development certificates — run: make dev-certs"; exit 1; }
	$(GO) test -count=1 -v -run 'Test(Boot(RefusalsAreVisible|DisclosuresAreVisible)|RuntimeRefusalsAreVisible)' ./internal/acceptance/
