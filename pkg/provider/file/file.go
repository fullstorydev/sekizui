// Package file resolves `file://` credential references — every Kubernetes
// secret-delivery mechanism, and local development (D103, D151, §4.7.8).
//
// ONE ADAPTER FOR SIX MECHANISMS. Plain Secrets, Helm-templated Secrets,
// `helm-secrets`/SOPS, External Secrets Operator, the Secrets Store CSI Driver
// and Vault Agent Injector all terminate as a file in the pod, so Sekizui needs
// one scheme rather than one per mechanism.
//
// **`helm-secrets` AND SOPS DO NOTHING AT RUNTIME**, which is worth stating here
// because it is routinely conflated. They encrypt values at rest in version
// control — a real problem, genuinely solved — and by the time Sekizui starts,
// `helm upgrade` has decrypted them into an ordinary Kubernetes Secret. That is
// base64 rather than encryption, readable by anyone holding `get secrets` RBAC in
// the namespace unless `EncryptionConfiguration` is enabled on the API server. An
// operator who adopted SOPS may reasonably believe otherwise, which is why D104
// makes `material` a REPORTED fact rather than a paragraph in a document.
//
// DESIGN.md references: §4.7.2, §4.7.8, §4.7.9, D99, D103, D104, D130, D151.
package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fullstorydev/sekizui/pkg/config"
	"github.com/fullstorydev/sekizui/pkg/fault"
)

// Scheme is the reference scheme this provider answers for.
const Scheme = "file"

// DataLink is the symlink the kubelet maintains inside a Secret or projected
// volume, pointing at a timestamped directory it swaps atomically.
//
// THIS IS THE WHOLE BASIS OF THE ROTATION POSTURE, so it is named rather than
// inlined. Its presence is what distinguishes a mount the kubelet can update
// from one it cannot — a `subPath` mount has none of it, which is the silent
// failure D104 exists to report.
const DataLink = "..data"

// VersionedByContent is §4.7.2's "by content" for this scheme.
//
// AN ALIAS, so the reason appears once. A file has no version the filesystem can
// report, and the cache digests the material instead (D123, D130) — so the
// CONTENT is the identity. That satisfies a `versioned` requirement without
// claiming a version number the source does not have.
const VersionedByContent = config.VersionedByReference

// Rotation values are config's, not this package's — a boot report and a
// decision record must speak one vocabulary (D104).
//
// The three cases here, and why the middle one needs the environment:
//
//   - config.RotationLive — a `..data` link is present, so the kubelet swaps
//     contents atomically. Kubernetes documents this mechanism, and D99's
//     content-addressed PoolKey is what turns an updated file into an
//     invalidated pooled client: rotation with no redeploy, which `env://`
//     structurally cannot offer (D97, D103).
//
//     **THE CLAIM IS ABOUT THE DELIVERY PATH, AND IT IS CONDITIONAL** — *a
//     rotated Secret is picked up*. It does not assert that this Secret ever
//     will be rotated, and two ordinary configurations make that distinction
//     real. An **immutable Secret** (`immutable: true`) can never change, so
//     rotating it means creating a new object and pointing the Pod at it, which
//     costs a redeploy. **External Secrets Operator** syncs a manager into a
//     Secret on a refresh interval, so rotation is real but lagged.
//
//     NEITHER NEEDS A FOURTH POSTURE, and the reason is what D104 is actually
//     for: it exists to catch SILENT failure. An immutable Secret is rejected by
//     the API server the moment somebody tries to update it — loud, immediate,
//     at the point of the attempt — which is the opposite of the `subPath` case
//     below, where the update is ACCEPTED and simply never arrives. A lagged
//     sync is live with a longer timeframe, which is the operator's own
//     configuration rather than a property of this path.
//
//   - config.RotationNone — no link, in a pod. That means `subPath`, and the
//     documentation is explicit: "A container using a ConfigMap as a subPath
//     volume mount will not receive updates when the ConfigMap changes." The
//     same holds for a Secret. **This is the dangerous case**: the operator
//     rotates the Secret, the API server accepts it, every dashboard agrees,
//     and the pod presents the old credential until something restarts it.
//
//   - config.RotationOnChange — no link, not in a pod. An ordinary file, picked
//     up at the next resolution because the version is the content.

// Provider reads credential material from the filesystem.
type Provider struct {
	// inKubernetes decides how to read the ABSENCE of a ..data link, and it is
	// the only reason this provider knows anything about its environment.
	//
	// The presence of the link is definitive; its absence is not. On a laptop it
	// means an ordinary file, which rotates when somebody edits it. In a pod it
	// means a `subPath` mount, which never rotates at all. Reporting those
	// identically would either alarm every developer or hide the failure that
	// matters, so the profile settles which reading applies.
	inKubernetes bool

	// roots, deny and allowUnrooted confine which files may be read at all
	// (D286, confine.go).
	roots, deny   []string
	allowUnrooted bool
}

var _ config.Provider = (*Provider)(nil)

// COMPILE-TIME ASSERTION, following D139's lesson. `Postured` is optional and
// discovered by type assertion, so nothing in the tree would fail if this
// provider stopped satisfying it — the posture report would simply say "unknown"
// for every file credential, and the boot line an operator relies on would go
// quiet without anything looking broken. That is the exact shape of a published
// interface separating silently from the thing honouring it.
var _ config.Postured = (*Provider)(nil)

// Option configures a Provider.
type Option func(*Provider)

// InKubernetes tells the provider it is running in a pod, which is what makes a
// missing `..data` link mean `subPath` rather than "an ordinary file".
func InKubernetes(yes bool) Option { return func(p *Provider) { p.inKubernetes = yes } }

// New builds a Provider.
func New(opts ...Option) *Provider {
	p := &Provider{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Scheme is "file".
func (p *Provider) Scheme() string { return Scheme }

// PathOf extracts the filesystem path from a reference.
//
// WHATEVER FOLLOWS THE SCHEME IS THE PATH, with no host component parsed out.
// `file:///etc/sekizui/token` gives `/etc/sekizui/token` and `file://./dev/tok`
// gives `./dev/tok`. RFC 8089 would read the segment after `//` as a host, which
// for a credential reference is a distinction with no meaning and one more thing
// to get wrong in a YAML file — the reference names a path on this machine.
func PathOf(ref string) (string, error) {
	const op = "file.PathOf"

	path, ok := strings.CutPrefix(ref, Scheme+"://")
	if !ok {
		return "", fault.New(fault.KindInvalidArgument, op,
			fmt.Sprintf("ref %q is not a %s:// reference", ref, Scheme))
	}
	if strings.TrimSpace(path) == "" {
		return "", fault.New(fault.KindConfig, op,
			"a file:// reference with no path. Write file:///absolute/path")
	}
	return path, nil
}

// Resolve reads the file.
//
// THE VERSION IS DELIBERATELY EMPTY, which D130 defines as "I cannot tell you"
// and which is the RIGHT answer here rather than an omission. A file has no
// version the filesystem can report — mtime is not an identity, and two rotations
// to the same bytes are the same credential — so the cache falls back to
// digesting the material, which is D123's mechanism and exactly what §4.7.2's
// table means by "versioned by content".
//
// A consequence worth naming: content-addressing gives no ORDER, so D152's
// monotonic guard does not apply to `file://`. There is no such thing as an
// older digest, and a guard that pretended otherwise would refuse a legitimate
// edit half the time.
func (p *Provider) Resolve(ctx context.Context, ref string) (config.Resolution, error) {
	const op = "file.Resolve"

	// **HONOURED, AND IT WAS NOT.** The published conformance suite caught this on
	// its first run: `EnvProvider` checks cancellation and carries a comment
	// saying it does so "because the Provider contract says every implementation
	// honours cancellation, and an implementation that quietly does not becomes
	// the one people copy when writing the Vault provider" — and the next two
	// providers written in this tree, this one and ambient, quietly did not.
	//
	// Reading a file cannot block for long, so the check buys little HERE. It is
	// present because a boot being torn down, or a request whose caller has gone,
	// must not still be fetching credentials — and because the contract is what a
	// third-party implementer copies.
	if err := ctx.Err(); err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindTimeout, op, "context done", err)
	}

	// **CONFINED ON EVERY READ, NOT ONLY AT BOOT (D286)**, because a symlink
	// inside a root can be pointed somewhere else after the boot checked it.
	path, root, err := p.confined(ref)
	if err != nil {
		return config.Resolution{}, err
	}

	// **AND THE READ ITSELF IS CONFINED (D344).** The check above resolves a
	// NAME; reading that name again re-walks it, so a directory on the path
	// swapped for a symlink in between sent a file from outside every root
	// off-host as an Authorization header — the check and the read were two
	// different walks. Opening through os.Root makes the confinement a property
	// of the open: a walk that leaves the root is refused as it happens.
	// Kubernetes' `..data` links resolve inside the mount, so they still pass.
	//
	// OPENED ONCE: the directory check and the read use the same handle, so
	// nothing can be swapped between asking what the file is and reading it.
	f, err := openConfined(root, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// NAMED AS A CONFIG PROBLEM, not an I/O one. The overwhelmingly
			// likely cause is a volume that did not mount or a key that is not
			// in the Secret, and both are fixed in a manifest.
			return config.Resolution{}, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
				"no credential at %s. Check the volume is mounted and the key exists "+
					"in the Secret", path), err)
		}
		return config.Resolution{}, fault.Wrap(fault.KindConfig, op, fmt.Sprintf(
			"reading %s within -file-credential-root %s: a path that leaves the root "+
				"while it is being read is refused (D344)", path, root), err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindConfig, op, "reading "+path, err)
	}
	if info.IsDir() {
		// A REAL MISTAKE WITH A HELPFUL SHAPE: a Secret volume mounted at
		// /etc/secrets contains one file per key, so an operator naming the
		// directory has forgotten the key rather than mistyped a path.
		return config.Resolution{}, fault.New(fault.KindConfig, op, fmt.Sprintf(
			"%s is a directory. A Secret volume holds one file per key — name the "+
				"key, as in %s/token", path, strings.TrimSuffix(path, "/")))
	}

	material, err := io.ReadAll(f)
	if err != nil {
		return config.Resolution{}, fault.Wrap(fault.KindConfig, op, "reading "+path, err)
	}
	if len(material) == 0 {
		// EMPTY IS REFUSED, because it authenticates nothing and would otherwise
		// surface as an upstream 401 several layers away from the cause. Same
		// argument D98 makes for an empty `credential:`.
		return config.Resolution{}, fault.New(fault.KindConfig, op,
			"the credential at "+path+" is empty")
	}
	return config.Resolution{Material: material}, nil
}

// openConfined opens path for reading, through os.Root at root when there is
// one (D344). An unrooted developer machine (root == "") opens the path
// directly: with no root declared there is nothing for a walk to escape.
func openConfined(root, path string) (*os.File, error) {
	if root == "" {
		return os.Open(path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	// Closing the Root does not close files opened through it.
	defer func() { _ = r.Close() }()
	return r.Open(rel)
}

// Posture reports what can happen to this credential without a redeploy (D104).
//
// ONE Lstat, AND THE PRESENCE OF THE LINK IS DEFINITIVE. Kubernetes maintains
// `..data` as a symlink into a timestamped directory and swaps it atomically,
// which is how a volume-mounted Secret updates at all. A `subPath` mount has
// none of that structure, and the documentation states plainly that it "will not
// receive updates".
func (p *Provider) Posture(ref string) (config.Posture, error) {
	path, err := PathOf(ref)
	if err != nil {
		return config.Posture{}, err
	}

	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), DataLink)); err == nil {
		return config.Posture{
			Rotation: config.RotationLive,
			Why: "a projected volume: the kubelet swaps " + DataLink + " atomically, so a " +
				"rotated Secret is picked up without a redeploy",
			AtRest: "k8s-secret",
			// VERSIONED BY CONTENT (§4.7.2's table), which is what keeps every
			// `file://` clear of a `versioned` requirement — including the
			// subPath case below, whose content is still an identity even though
			// it will never change. D104 rules that must WARN and not refuse,
			// and D153 is the record of getting that wrong first.
			Versioning: VersionedByContent,
			// FALSE, STATED RATHER THAN LEFT TO THE ZERO VALUE. A mounted file
			// records nothing about who read it: the process opens it and the
			// filesystem keeps no account, which is the property a secret
			// manager has and this does not. Written out because a zero value
			// cannot be told from a field nobody thought about.
			AuditedReads: false,
		}, nil
	}

	if p.inKubernetes {
		return config.Posture{
			Rotation: config.RotationNone,
			Why: "no " + DataLink + " link beside it, which in a pod means a subPath mount. " +
				"Kubernetes does not update those: rotating the Secret will change nothing " +
				"here until the pod restarts. Mount the volume WITHOUT subPath, or accept " +
				"that this credential is static and rotate it by redeploying",
			AtRest:       "k8s-secret",
			Versioning:   VersionedByContent,
			AuditedReads: false,
		}, nil
	}

	return config.Posture{
		Rotation: config.RotationOnChange,
		Why: "an ordinary file. Nothing rotates it on Sekizui's behalf, and an edit is " +
			"picked up at the next resolution because the version is the content",
		AtRest:       "static-file",
		Versioning:   VersionedByContent,
		AuditedReads: false,
	}, nil
}
