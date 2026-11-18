package proxy

import "testing"

func TestSafeRedirect(t *testing.T) {
	allow := []string{"/", "/login", "/a/b?x=1", "https://example.com/x", "http://a.b/c"}
	deny := []string{"", "//evil.com", "/\\evil.com", "javascript:alert(1)", "ftp://x", "data:text/html,x", "https://", "example.com"}
	for _, s := range allow {
		if SafeRedirect(s) == "" {
			t.Errorf("应允许: %q", s)
		}
	}
	for _, s := range deny {
		if SafeRedirect(s) != "" {
			t.Errorf("应拒绝: %q", s)
		}
	}
}