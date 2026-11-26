package store

import (
	"net/url"
	"strings"
)

// NormalizeUpstreams validates a list of upstream addresses supplied by a configuration writer.
func NormalizeUpstreams(raw string) (string, error) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" || len(item) > 8192 {
			return "", ErrConfigInvalid
		}
		u, err := url.Parse(item)
		if err != nil || !validUpstreamURL(u) || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(item, "#") {
			return "", ErrConfigInvalid
		}
		out = append(out, u.String())
	}
	if len(out) > 32 {
		return "", ErrConfigInvalid
	}
	return strings.Join(out, ","), nil
}

func validUpstreamURL(u *url.URL) bool {
	return u != nil && u.Hostname() != "" && u.Opaque == "" && (u.Scheme == "http" || u.Scheme == "https")
}

// DisplayUpstreamURL omits URL fields that may contain credentials. It leaves the
// original URL intact for actual upstream requests.
func DisplayUpstreamURL(u *url.URL) string {
	if !validUpstreamURL(u) {
		return ""
	}
	clean := *u
	clean.User, clean.RawQuery, clean.ForceQuery = nil, "", false
	clean.Fragment, clean.RawFragment = "", ""
	return clean.String()
}

// DisplayUpstreams strips secrets and invalid addresses from an existing configuration.
// The second result reports whether anything was hidden, so the UI can preserve it on edit.
func DisplayUpstreams(raw string) (string, bool) {
	var addresses []string
	var redacted bool
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		u, err := url.Parse(item)
		if err != nil || !validUpstreamURL(u) {
			redacted = true
			continue
		}
		clean := DisplayUpstreamURL(u)
		redacted = redacted || clean != u.String()
		addresses = append(addresses, clean)
	}
	return strings.Join(addresses, ","), redacted
}
