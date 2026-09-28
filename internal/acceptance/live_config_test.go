package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/fullstorydev/sekizui/pkg/config"
)

// liveCoordinates names the Fullstory org, user and session the live arms reach.
//
// **THEY ARE YOURS, AND THEY ARE NAMED, NEVER DISCOVERED.** The live arms append a
// server-side event and upsert a user, and `POST /v2/events` cannot be undone — so
// nothing here searches your org for a user or a session to write into. You point
// at them in `dev/fullstory-live.yaml` (gitignored; `make live-config` writes a
// commented template), and each field can be overridden by an environment
// variable for CI:
//
//	key          SEKIZUI_LIVE_KEY          path to a file holding the API key
//	uid          SEKIZUI_LIVE_UID          the user the writes upsert and the poll reads
//	session      SEKIZUI_LIVE_SESSION      that user's session, as the API names it
//	session_url  SEKIZUI_LIVE_SESSION_URL  the same session, as the browser shows it
//
// The org is read from the session URL, so it cannot disagree with the session.
type liveCoordinates struct {
	Key        string `json:"key"`
	UID        string `json:"uid"`
	Session    string `json:"session"`
	SessionURL string `json:"session_url"`

	org, device, uiSession string
}

// liveConfigPath is where the coordinates live, relative to the repository root.
const liveConfigPath = "dev/fullstory-live.yaml"

// A session URL as Fullstory's app shows it: the org, then the device and the
// session, separated by ":" (or its escaped form, as a copied link often has).
//
//nolint:gochecknoglobals // immutable, compiled once
var liveSessionURLShape = regexp.MustCompile(`^https://app\.(eu1\.)?fullstory\.com/ui/([A-Za-z0-9-]+)/session/([0-9]+)(?::|%3A)([0-9]+)`)

// loadLiveConfig reads the coordinates, applies the environment overrides, and
// FAILS naming whatever is missing — it is called only once a live run has been
// asked for, and an asked-for run that cannot reach Fullstory must not pass.
func loadLiveConfig(t *testing.T) liveCoordinates {
	t.Helper()

	var c liveCoordinates
	path := filepath.Join(mustRoot(t), liveConfigPath)
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.UnmarshalStrict(raw, &c); err != nil {
			t.Fatalf("%s does not parse: %v", liveConfigPath, err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("reading %s: %v", liveConfigPath, err)
	}
	for field, env := range map[*string]string{
		&c.Key: "SEKIZUI_LIVE_KEY", &c.UID: "SEKIZUI_LIVE_UID",
		&c.Session: "SEKIZUI_LIVE_SESSION", &c.SessionURL: "SEKIZUI_LIVE_SESSION_URL",
	} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			*field = v
		}
	}

	var missing []string
	for _, f := range []struct{ name, env, value string }{
		{"key", "SEKIZUI_LIVE_KEY", c.Key}, {"uid", "SEKIZUI_LIVE_UID", c.UID},
		{"session", "SEKIZUI_LIVE_SESSION", c.Session}, {"session_url", "SEKIZUI_LIVE_SESSION_URL", c.SessionURL},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, fmt.Sprintf("%s (or %s)", f.name, f.env))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("a live Fullstory run was asked for (%s is set) and it cannot reach an org: %s is "+
			"missing %s. `make live-config` writes a commented template; each field says where to "+
			"find its value. Unset %s to skip the live arms instead",
			liveWriteRequested, liveConfigPath, strings.Join(missing, ", "), liveWriteRequested)
	}

	m := liveSessionURLShape.FindStringSubmatch(c.SessionURL)
	switch {
	case m == nil:
		t.Fatalf("session_url %q is not a Fullstory session link — copy it from the browser: "+
			"https://app.fullstory.com/ui/<org>/session/<device>:<session>", c.SessionURL)
	case m[1] != "":
		t.Fatalf("session_url %q is an EU1 org. The acceptance deployment serves the `us` class, so the "+
			"live arms reach NA1 orgs only today", c.SessionURL)
	}
	c.org, c.device, c.uiSession = m[2], m[3], m[4]

	if !filepath.IsAbs(c.Key) {
		c.Key = filepath.Join(mustRoot(t), c.Key)
	}
	return c
}

// describe names the session for a human reading a failure, who can open it.
func (c liveCoordinates) describe() string {
	return fmt.Sprintf("uid %s, session %s (%s)", c.UID, c.Session, c.SessionURL)
}

// targetsFor points the session-reading targets at the configured user, for a
// live run's configuration patch. The committed file names the fixture's user,
// which is what the offline runs serve.
func (c liveCoordinates) targetsFor(d *config.Document) {
	for i := range d.Targets {
		switch d.Targets[i].Ref {
		case "fs:sessions", "fs:events":
			settings := map[string]string{}
			for k, v := range d.Targets[i].Settings {
				settings[k] = v
			}
			settings["sessions_uid"] = c.UID
			d.Targets[i].Settings = settings
		}
	}
}
