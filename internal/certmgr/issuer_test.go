package certmgr

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type recordingDNSProvider struct {
	cleaned []string
}

func (*recordingDNSProvider) Present(_, _, _ string) error {
	// A provider can write the record before the client receives an error.
	return errors.New("lost provider response")
}

func (p *recordingDNSProvider) CleanUp(domain, _, _ string) error {
	p.cleaned = append(p.cleaned, domain)
	return nil
}

func TestDNSCancellationCleansOnlyAttemptedRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &recordingDNSProvider{}
	dns := &cancellableDNS{Provider: provider, ctx: ctx}
	if err := dns.Present("attempted.example", "token-a", "key-a"); err == nil {
		t.Fatal("expected the provider's response error")
	}
	cancel()
	if err := dns.Present("skipped.example", "token-b", "key-b"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled presentation returned %v", err)
	}
	if err := dns.CleanUp("attempted.example", "token-a", "key-a"); err != nil {
		t.Fatal(err)
	}
	if err := dns.CleanUp("skipped.example", "token-b", "key-b"); err != nil {
		t.Fatal(err)
	}
	if len(provider.cleaned) != 1 || provider.cleaned[0] != "attempted.example" {
		t.Errorf("cleanup ran for %v, want only attempted.example", provider.cleaned)
	}
}

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestTransportPreservesRequestDeadlineAndJobCancellation(t *testing.T) {
	job, cancelJob := context.WithCancel(context.Background())
	defer cancelJob()
	requestCtx, cancelRequest := context.WithTimeout(context.Background(), time.Minute)
	defer cancelRequest()
	expected, _ := requestCtx.Deadline()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	var sent context.Context
	transport := requestTransport{job, testTransport(func(r *http.Request) (*http.Response, error) {
		sent = r.Context()
		return &http.Response{Body: http.NoBody}, nil
	})}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if deadline, ok := sent.Deadline(); !ok || !deadline.Equal(expected) {
		t.Errorf("transport changed request deadline: got %v, want %v", deadline, expected)
	}
	if err := sent.Err(); err != nil {
		t.Fatalf("request canceled while the response body was still open: %v", err)
	}
	cancelJob()
	select {
	case <-sent.Done():
		if !errors.Is(sent.Err(), context.Canceled) {
			t.Errorf("job cancellation returned %v", sent.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("job cancellation did not reach the HTTP transport")
	}
	if _, err := response.Body.Read(nil); !errors.Is(err, io.EOF) {
		t.Errorf("unexpected body read error: %v", err)
	}
}
