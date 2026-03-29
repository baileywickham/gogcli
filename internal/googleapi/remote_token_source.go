package googleapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type remoteTokenSource struct {
	endpoint   string
	auth       string
	email      string
	scopes     []string
	httpClient *http.Client
}

type remoteTokenRequest struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

type remoteTokenResponse struct {
	AccessToken string    `json:"access_token"`
	Expiry      time.Time `json:"expiry"`
}

func (r *remoteTokenSource) Token() (*oauth2.Token, error) {
	body, err := json.Marshal(remoteTokenRequest{
		Email:  r.email,
		Scopes: r.scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("remote token: marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("remote token: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if r.auth != "" {
		req.Header.Set("Authorization", "Bearer "+r.auth)
	}

	client := r.httpClient
	if client == nil {
		client = &http.Client{Timeout: tokenExchangeTimeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote token: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("remote token: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("remote token: endpoint returned %d: %s", resp.StatusCode, respBody)
	}

	var tokenResp remoteTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("remote token: parse response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("remote token: endpoint returned empty access token")
	}

	return &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		Expiry:      tokenResp.Expiry,
	}, nil
}

// CheckRemoteTokenEndpoint probes the remote token endpoint by requesting a
// token for the given email and scopes. It returns nil if the endpoint returns
// a valid access token.
func CheckRemoteTokenEndpoint(endpoint, auth, email string, scopes []string, timeout time.Duration) error {
	src := &remoteTokenSource{
		endpoint:   endpoint,
		auth:       auth,
		email:      email,
		scopes:     scopes,
		httpClient: &http.Client{Timeout: timeout},
	}
	_, err := src.Token()
	return err
}
