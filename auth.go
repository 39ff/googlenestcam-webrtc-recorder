package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthClient manages OAuth2 bearer tokens for the Google API.
type AuthClient struct {
	cfg        *Config
	httpClient *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func NewAuthClient(cfg *Config, httpClient *http.Client) *AuthClient {
	return &AuthClient{cfg: cfg, httpClient: httpClient}
}

func (a *AuthClient) refreshAccessToken(ctx context.Context) error {
	data := url.Values{
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"refresh_token": {a.cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token resp %d: %s", resp.StatusCode, body)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return err
	}

	a.mu.Lock()
	a.token = tok.AccessToken
	a.expires = time.Now().Add(time.Duration(tok.ExpiresIn-60) * time.Second)
	a.mu.Unlock()

	log.Printf("[AUTH] got token, valid %ds", tok.ExpiresIn)
	return nil
}

// Bearer returns a valid bearer token, refreshing if necessary.
func (a *AuthClient) Bearer(ctx context.Context) (string, error) {
	a.mu.Lock()
	expired := a.token == "" || time.Now().After(a.expires)
	a.mu.Unlock()

	if expired {
		if err := a.refreshAccessToken(ctx); err != nil {
			return "", err
		}
	}

	a.mu.Lock()
	t := a.token
	a.mu.Unlock()
	return t, nil
}
