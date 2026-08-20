package main

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSPIFFETrustDomainBinding(t *testing.T) {
	for _, invalid := range []string{"", "UPPER.example", "-bad.example", "bad-.example", "two..dots", "bad_name"} {
		if err := validateSPIFFETrustDomain(invalid); err == nil {
			t.Fatalf("invalid trust domain %q accepted", invalid)
		}
	}
	if err := validateSPIFFETrustDomain("prod.example.internal"); err != nil {
		t.Fatalf("valid trust domain rejected: %v", err)
	}

	otherDomain := &x509.Certificate{URIs: []*url.URL{testURI(t, "spiffe://other.example/agent/buildbot")}}
	if name, _ := certAgentName(otherDomain, "prod.example"); name != "" {
		t.Fatalf("cross-domain identity accepted as %q", name)
	}
	trusted := &x509.Certificate{URIs: []*url.URL{testURI(t, "spiffe://prod.example/agent/buildbot")}}
	if name, _ := certAgentName(trusted, ""); name != "" {
		t.Fatalf("certificate-only identity enabled without an explicit trust domain: %q", name)
	}
	if name, id := certAgentName(trusted, "prod.example"); name != "buildbot" || id == "" {
		t.Fatalf("trusted identity rejected: name=%q id=%q", name, id)
	}
	withQuery := &x509.Certificate{URIs: []*url.URL{testURI(t, "spiffe://prod.example/agent/buildbot?alias=admin")}}
	if name, _ := certAgentName(withQuery, "prod.example"); name != "" {
		t.Fatalf("non-canonical SPIFFE identity accepted as %q", name)
	}
}

func TestLimitRequestBody(t *testing.T) {
	const limit = 32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		_ = body
	})
	handler := limitRequestBody(next, limit)

	valid := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", limit)))
	validResult := httptest.NewRecorder()
	handler.ServeHTTP(validResult, valid)
	if validResult.Code != http.StatusNoContent {
		t.Fatalf("body at limit rejected: %d", validResult.Code)
	}

	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", limit+1)))
	oversized.ContentLength = -1 // exercise the streaming/chunked path
	oversizedResult := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResult, oversized)
	if oversizedResult.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized streaming body status=%d, want 413", oversizedResult.Code)
	}
}
