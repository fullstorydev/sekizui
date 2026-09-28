// Package ambient resolves and validates `ambient://<cloud>` workload identity
// (D98, D102, §4.7.2, §4.7.7).
//
// PUBLIC (D35), like every other provider — a self-hoster on a platform Sekizui
// has not met supplies their own.
//
// SEKIZUI SUPPLIES NO BYTES FOR AMBIENT IDENTITY, and that is the shape of the
// scheme rather than an omission. The platform authenticates the workload and
// the cloud SDK picks the identity up on its own; there is no material for a
// broker to hold, version or rotate — which is why §4.7.2's table records the
// version column as "n/a; the platform rotates". What the declaration buys is
// everything an absence could not: a boot check, an audit posture, and a
// configuration that says what it means.
//
// DESIGN.md references: §4.7.2, §4.7.7, D75, D98, D102.
package ambient

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Scheme is the reference scheme this provider answers for.
const Scheme = "ambient"

// Confidence is how sure boot is that a declared ambient identity exists
// (§4.7.7). Three tiers rather than a bool, because D75's house rule is that
// *cannot confirm* and *refuted* are different answers and reporting them
// identically means either refusing valid configurations or accepting
// impossible ones.
type Confidence int

const (
	// Unverified is tier 3: nothing local settled it and nothing was allowed to
	// probe. ACCEPTED and logged, because a boot that refuses on the strength of
	// a check it could not run is worse than one that says so and fails at the
	// first real call with the target named.
	Unverified Confidence = iota

	// ConfirmedLocally is tier 1.5 — a file the platform injects. One `stat`,
	// no packet, and definitive.
	ConfirmedLocally

	// ConfirmedByProbe is tier 2 — the metadata endpoint answered.
	ConfirmedByProbe
)

func (c Confidence) String() string {
	switch c {
	case ConfirmedLocally:
		return "confirmed-locally"
	case ConfirmedByProbe:
		return "confirmed-by-probe"
	default:
		return "unverified"
	}
}

// Clouds is the set `ambient://` accepts, in one place so the boot refusal and
// the provider cannot disagree about what a valid cloud is.
//
//nolint:gochecknoglobals // immutable table, read once
var Clouds = []string{"gcp", "aws", "azure"}

// localSignal is what a platform injects into a pod when it wires up workload
// identity — tier 1.5 (§4.7.7).
//
// THE CLOUDS ARE NOT SYMMETRIC, and knowing that BEFORE writing the probe is
// what stops this being one uniform network call. Two of the three settle the
// question with a `stat`; only GKE works by intercepting the metadata endpoint
// and so leaves nothing on disk to look at. A uniform probe would be slower,
// less reliable, and would fail closed on two platforms that could have answered
// for free.
type localSignal struct {
	// tokenFile is the env var naming a file the platform writes.
	tokenFile string
	// identity is the env var naming WHO the workload is. Both are required:
	// the file alone is a token with no subject, and the pod identity webhook
	// injects them together, so one without the other is a half-configured
	// deployment rather than a working one.
	identity string
}

//nolint:gochecknoglobals // immutable table, read once
var localSignals = map[string]localSignal{
	"aws":   {tokenFile: "AWS_WEB_IDENTITY_TOKEN_FILE", identity: "AWS_ROLE_ARN"},
	"azure": {tokenFile: "AZURE_FEDERATED_TOKEN_FILE", identity: "AZURE_CLIENT_ID"},
	// GKE Workload Identity injects NOTHING. It works by intercepting the
	// metadata endpoint, so the only way to know is to ask — which is why
	// Kubernetes is tier 2 and why the probe exists at all.
}

// metadataProbe is the tier-2 request for one cloud.
type metadataProbe struct {
	url    string
	header map[string]string
}

//nolint:gochecknoglobals // immutable table, read once
var metadataProbes = map[string]metadataProbe{
	"gcp": {
		url:    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/",
		header: map[string]string{"Metadata-Flavor": "Google"},
	},
	"aws": {
		url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	},
	"azure": {
		url:    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		header: map[string]string{"Metadata": "true"},
	},
}

// Provider validates and resolves ambient references.
type Provider struct {
	env  func(string) string
	stat func(string) (fs.FileInfo, error)

	client   *http.Client
	baseURL  map[string]string
	timeout  time.Duration
	attempts int
	backoff  time.Duration
	sleep    func(context.Context, time.Duration) error
}

var _ config.Provider = (*Provider)(nil)

// Option configures a Provider.
type Option func(*Provider)

// WithMetadataBase points a cloud's probe at another address — an httptest
// server standing in for a metadata endpoint.
//
// A BASE URL RATHER THAN A FAKE TRANSPORT, because the thing worth testing is
// the timeout, the retry and the status handling, and all three are properties
// of a real http.Client talking to a real socket. A stubbed RoundTripper would
// let a hang pass as a success.
func WithMetadataBase(cloud, base string) Option {
	return func(p *Provider) {
		if p.baseURL == nil {
			p.baseURL = map[string]string{}
		}
		p.baseURL[cloud] = base
	}
}

// WithProbeBounds sets the per-attempt timeout, the attempt count and the pause
// between attempts.
//
// THREE OPTIONS WERE WRITTEN BESIDE THIS ONE AND DELETED — substitutions for the
// environment lookup, the `stat` and the sleep. Two had no caller at all and one
// was replaceable by `t.Setenv`, which the rest of this tree already uses.
// internal/archcheck caught all three (D139), which is the guard working on code
// written the same hour: a seam added because it MIGHT be wanted is the same
// defect as a config field nothing reads.
func WithProbeBounds(timeout time.Duration, attempts int, backoff time.Duration) Option {
	return func(p *Provider) { p.timeout, p.attempts, p.backoff = timeout, attempts, backoff }
}

// New builds a Provider with the bounds §4.7.7 argues for.
//
// THE DEFAULTS ARE THE DECISION, not placeholders. The metadata endpoint is
// link-local and answers in single-digit milliseconds, so a per-attempt bound of
// one second is already generous — and a boot check that HANGS is worse than one
// that was skipped, because the platform kills the pod and nothing explains why.
// Three attempts because on GKE the metadata server is a DaemonSet and a pod can
// start before it is ready: refusing on the first failure would lose a startup
// race Sekizui wins a second later.
func New(opts ...Option) *Provider {
	p := &Provider{
		env:      os.Getenv,
		stat:     func(name string) (fs.FileInfo, error) { return os.Stat(name) },
		timeout:  time.Second,
		attempts: 3,
		backoff:  250 * time.Millisecond,
		sleep:    sleepCtx,
	}
	for _, o := range opts {
		o(p)
	}
	if p.client == nil {
		// NO CLIENT-LEVEL TIMEOUT: the per-attempt bound is applied with a
		// context deadline instead, so the retry loop owns the budget and one
		// slow attempt cannot spend another attempt's time.
		p.client = &http.Client{}
	}
	return p
}

// Scheme is "ambient".
func (p *Provider) Scheme() string { return Scheme }

// CloudOf extracts the cloud from an ambient reference.
func CloudOf(ref string) (string, error) {
	const op = "ambient.CloudOf"

	cloud, ok := strings.CutPrefix(ref, Scheme+"://")
	if !ok {
		return "", fault.New(fault.KindInvalidArgument, op,
			fmt.Sprintf("ref %q is not an %s:// reference", ref, Scheme))
	}
	for _, c := range Clouds {
		if cloud == c {
			return cloud, nil
		}
	}
	return "", fault.New(fault.KindConfig, op, fmt.Sprintf(
		"%q is not a cloud Sekizui knows; expected one of %s",
		cloud, strings.Join(Clouds, ", ")))
}

// Resolve returns no material, which is the honest answer for ambient identity.
//
// THE SDK AUTHENTICATES, NOT SEKIZUI. There is nothing to fetch: the platform
// has already given the workload an identity, and a driver constructed without
// explicit credentials picks it up. Returning empty material is therefore a
// COMPLETE resolution rather than a failed one, and the version says which
// identity it is so a decision record and a PoolKey can name it.
//
// THE VERSION IS STABLE, which is correct and worth stating because D99's
// content-addressing makes a changing version tear down pooled clients. The
// platform rotates the underlying token continuously and transparently; that is
// not a credential rotation in D99's sense, and reporting it as one would
// re-initialise every pooled client on the platform's schedule for no reason.
func (p *Provider) Resolve(ctx context.Context, ref string) (config.Resolution, error) {
	const op = "ambient.Resolve"

	// HONOURED, AND IT WAS NOT — see file.Resolve's note. This provider does no
	// I/O at all in Resolve, which makes the omission easier to make and no more
	// defensible: the contract is what a third-party implementer copies.
	if err := ctx.Err(); err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindTimeout, op, "context done", err)
	}

	cloud, err := CloudOf(ref)
	if err != nil {
		return config.Resolution{}, err
	}
	return config.Resolution{Version: Scheme + ":" + cloud}, nil
}

// Posture declares what workload identity offers (D111, D153).
//
// VERSIONING IS **NOT APPLICABLE**, not absent, and the distinction is the whole
// reason config.Versioning has three states. The platform mints a credential per
// use, so there is no version to pin and nothing staleness could mean — and a
// bool would have collapsed that into "unversioned" and refused the posture
// §4.7.8 recommends above every other.
//
// ROTATION IS LIVE because the platform rotates continuously and transparently,
// which is also why `Resolve` reports a STABLE version: that rotation is not a
// credential rotation in D99's sense and must not tear down pooled clients.
//
// AUDITED READS IS TRUE: the cloud's own IAM logs record every token minted for
// this workload, which is the property a mounted file cannot offer at all.
func (p *Provider) Posture(ref string) (config.Posture, error) {
	cloud, err := CloudOf(ref)
	if err != nil {
		return config.Posture{}, err
	}
	return config.Posture{
		Versioning:   config.VersioningNotApplicable,
		Rotation:     config.RotationLive,
		AuditedReads: true,
		AtRest:       "platform",
		Why: "workload identity on " + cloud + ": the platform mints a credential per " +
			"use, so nothing is stored, nothing needs rotating and every mint is in the " +
			"cloud's own audit log",
	}, nil
}

// COMPILE-TIME ASSERTION (D139): Postured is optional, so nothing would fail if
// this stopped satisfying it — the deployment would simply start refusing
// `ambient://` under a `versioned` requirement, having lost the declaration that
// says the requirement does not apply.
var _ config.Postured = (*Provider)(nil)

// Validate reports how confident boot can be that this ambient identity exists,
// implementing §4.7.7's tiers 1.5, 2 and 3.
//
// TIER 1 IS NOT HERE. "Refuted by the environment" — `ambient://gcp` while the
// profile reports AWS — is answerable from the profile alone with no I/O and no
// provider, so it lives in the boot refusal beside the other free checks
// (`credential.RefuseAtBoot`). Splitting them keeps the check that needs a
// network from being the check that decides whether a typo boots.
//
// `eager` is `Profile.EagerValidation()`, and gating on it is the same rule
// §4.9a.7 applies to MCP's `tools/list`: on FaaS, work at construction time is
// forbidden, so the declaration is accepted UNVERIFIED and fails at first use
// with the target named.
func (p *Provider) Validate(ctx context.Context, cloud string, eager bool) (Confidence, error) {
	const op = "ambient.Validate"

	// TIER 1.5 FIRST, ALWAYS, and before the `eager` gate. A `stat` is not the
	// I/O that gate exists to forbid — §4.9a.7 is about network calls at
	// construction — and skipping it on FaaS would report UNVERIFIED for a
	// platform that had already answered the question on disk.
	if sig, ok := localSignals[cloud]; ok {
		file, id := p.env(sig.tokenFile), p.env(sig.identity)
		if file != "" && id != "" {
			if _, err := p.stat(file); err == nil {
				return ConfirmedLocally, nil
			} else if !errors.Is(err, fs.ErrNotExist) {
				return Unverified, fault.Wrap(fault.KindConfig, op,
					"reading the workload identity token at "+file, err)
			}
			// THE FILE IS NAMED AND ABSENT, which is worse than nothing being
			// named at all: the webhook told this pod where its token would be
			// and the token is not there.
			return Unverified, fault.New(fault.KindConfig, op, fmt.Sprintf(
				"%s points at %s, which does not exist. The platform injected a "+
					"workload identity token path and no token — the identity webhook "+
					"is misconfigured, or the volume did not mount",
				sig.tokenFile, file))
		}
	}

	if !eager {
		// TIER 3. Accepted, and the caller logs it. Refusing here would refuse a
		// valid Lambda deployment for lack of a check it is not allowed to run.
		return Unverified, nil
	}
	return p.probe(ctx, cloud)
}

// probe is tier 2: one bounded HTTP call, retried, then a refusal.
func (p *Provider) probe(ctx context.Context, cloud string) (Confidence, error) {
	const op = "ambient.probe"

	mp, ok := metadataProbes[cloud]
	if !ok {
		return Unverified, nil
	}
	url := mp.url
	if base, ok := p.baseURL[cloud]; ok {
		url = base
	}

	var last error
	for attempt := 1; attempt <= p.attempts; attempt++ {
		if attempt > 1 {
			// BACKOFF BEFORE THE RETRY, not after the last attempt: sleeping
			// once more on the way out spends the caller's boot budget to learn
			// nothing.
			if err := p.sleep(ctx, p.backoff); err != nil {
				return Unverified, fault.Wrap(fault.KindInternal, op, "waiting to retry", err)
			}
		}
		if err := p.attemptProbe(ctx, url, mp.header); err != nil {
			last = err
			continue
		}
		return ConfirmedByProbe, nil
	}

	// REFUSE, NOT WARN, and the asymmetry with D104's rotation warning is
	// deliberate: a target whose ambient identity does not work fails EVERY
	// call, so starting and failing every request is strictly worse than
	// refusing to start with the target named.
	return Unverified, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
		"ambient://%s declared, and the metadata endpoint did not confirm it after "+
			"%d attempts. Either this is not a %s workload, or workload identity is "+
			"not configured for it", cloud, p.attempts, cloud), last)
}

func (p *Provider) attemptProbe(ctx context.Context, url string, header map[string]string) error {
	const op = "ambient.attemptProbe"

	// THE DEADLINE IS PER ATTEMPT and comes from a context rather than
	// http.Client.Timeout, so the retry loop owns the total budget and a hung
	// endpoint cannot eat the attempts that would have succeeded.
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fault.Wrap(fault.KindInvalidArgument, op, "building the metadata request", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}

	res, err := p.client.Do(req)
	if err != nil {
		return fault.Wrap(fault.KindUnavailable, op, "probing "+url, err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fault.New(fault.KindUnavailable, op, fmt.Sprintf(
			"metadata endpoint answered %d", res.StatusCode))
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
