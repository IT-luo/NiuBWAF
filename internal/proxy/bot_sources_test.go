package proxy

import (
	"strings"
	"testing"
	"time"
)

func TestCrawlerSourceVerification(t *testing.T) {
	ranges, err := parseCrawlerRanges(strings.NewReader(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	verifier := newCrawlerVerifier()
	verifier.sources["googlebot"] = crawlerRangeSnapshot{prefixes: ranges, loaded: time.Now()}
	for _, ip := range []string{"192.0.2.20", "2001:db8:123::1"} {
		if match, ready := verifier.verified("googlebot", ip); !match || !ready {
			t.Errorf("configured crawler source not recognized for %s", ip)
		}
	}
	if match, ready := verifier.verified("googlebot", "198.51.100.8"); match || !ready {
		t.Error("unexpected crawler source match")
	}
	if match, ready := verifier.verified("bingbot", "192.0.2.20"); match || ready {
		t.Error("a feed from another crawler must not verify the request")
	}
}

func TestNewPathLimitSeparatesClientsAndWindows(t *testing.T) {
	track := &botPathTracker{}
	for _, path := range []string{"/docs", "/help", "/docs"} {
		if over, _ := track.limitNewPath(1, "192.0.2.10", path, 2, 60); over {
			t.Fatal("still within the path quota")
		}
	}
	if over, first := track.limitNewPath(1, "192.0.2.10", "/settings", 2, 61); !over || !first {
		t.Fatal("expected the first excess path to be counted")
	}
	if over, _ := track.limitNewPath(1, "192.0.2.11", "/settings", 2, 61); over {
		t.Fatal("another client must have its own quota")
	}
	if over, _ := track.limitNewPath(1, "192.0.2.10", "/settings", 2, 70); over {
		t.Fatal("expected the next window to renew the quota")
	}
}
