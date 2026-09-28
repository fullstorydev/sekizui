package fullstory

import (
	"net/http/httptest"
	"net/url"
)

// withServer admits a test server's host, which P3 step 24's host check would
// otherwise refuse — the only way a driver in this package's tests reaches one.
func withServer(s *httptest.Server) Option {
	u, _ := url.Parse(s.URL)
	return WithHosts(u.Host)
}
