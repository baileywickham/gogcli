package googleapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteTokenSource_HappyPath(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %s", ct)
		}

		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", auth)
		}

		var req remoteTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if req.Email != "user@example.com" {
			t.Errorf("expected user@example.com, got %s", req.Email)
		}

		if len(req.Scopes) != 2 || req.Scopes[0] != "scope1" || req.Scopes[1] != "scope2" {
			t.Errorf("unexpected scopes: %v", req.Scopes)
		}

		resp := remoteTokenResponse{
			AccessToken: "access-123",
			Expiry:      expiry,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	ts := &remoteTokenSource{
		endpoint: srv.URL,
		auth:     "test-token",
		email:    "user@example.com",
		scopes:   []string{"scope1", "scope2"},
	}

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tok.AccessToken != "access-123" {
		t.Errorf("expected access-123, got %s", tok.AccessToken)
	}

	if !tok.Expiry.Equal(expiry) {
		t.Errorf("expected expiry %v, got %v", expiry, tok.Expiry)
	}
}

func TestRemoteTokenSource_NoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no auth header, got %s", auth)
		}

		json.NewEncoder(w).Encode(remoteTokenResponse{
			AccessToken: "access-no-auth",
			Expiry:      time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	ts := &remoteTokenSource{
		endpoint: srv.URL,
		email:    "user@example.com",
		scopes:   []string{"scope1"},
	}

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tok.AccessToken != "access-no-auth" {
		t.Errorf("expected access-no-auth, got %s", tok.AccessToken)
	}
}

func TestRemoteTokenSource_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ts := &remoteTokenSource{
		endpoint: srv.URL,
		email:    "user@example.com",
		scopes:   []string{"scope1"},
	}

	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected error")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 in error, got: %v", err)
	}
}

func TestRemoteTokenSource_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteTokenResponse{
			AccessToken: "",
			Expiry:      time.Now().Add(time.Hour),
		})
	}))
	defer srv.Close()

	ts := &remoteTokenSource{
		endpoint: srv.URL,
		email:    "user@example.com",
		scopes:   []string{"scope1"},
	}

	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected error for empty access token")
	}

	if !strings.Contains(err.Error(), "empty access token") {
		t.Errorf("expected empty access token error, got: %v", err)
	}
}

func TestRemoteTokenSource_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	ts := &remoteTokenSource{
		endpoint: srv.URL,
		email:    "user@example.com",
		scopes:   []string{"scope1"},
	}

	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "parse response") {
		t.Errorf("expected parse response error, got: %v", err)
	}
}

func TestRemoteTokenSource_ConnectionError(t *testing.T) {
	ts := &remoteTokenSource{
		endpoint: "http://127.0.0.1:1",
		email:    "user@example.com",
		scopes:   []string{"scope1"},
	}

	_, err := ts.Token()
	if err == nil {
		t.Fatal("expected error for connection failure")
	}

	if !strings.Contains(err.Error(), "request failed") {
		t.Errorf("expected request failed error, got: %v", err)
	}
}
