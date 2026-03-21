package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SDMClient wraps Smart Device Management API calls.
type SDMClient struct {
	auth       *AuthClient
	httpClient *http.Client
	deviceID   string
}

func NewSDMClient(auth *AuthClient, httpClient *http.Client, deviceID string) *SDMClient {
	return &SDMClient{auth: auth, httpClient: httpClient, deviceID: deviceID}
}

func (s *SDMClient) executeCommand(ctx context.Context, command string, params any) (json.RawMessage, error) {
	u := fmt.Sprintf("https://smartdevicemanagement.googleapis.com/v1/%s:executeCommand", s.deviceID)
	body, err := json.Marshal(map[string]any{"command": command, "params": params})
	if err != nil {
		return nil, fmt.Errorf("marshal SDM request: %w", err)
	}

	bearer, err := s.auth.Bearer(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create SDM request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SDM %s -> %d: %s", command, resp.StatusCode, raw)
	}

	var res struct {
		Results json.RawMessage `json:"results"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Results, nil
}

func unmarshalCommand[T any](ctx context.Context, s *SDMClient, cmd string, params any) (T, error) {
	var v T
	raw, err := s.executeCommand(ctx, cmd, params)
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v)
	return v, err
}

// streamResponse is the common response type for GenerateWebRtcStream and ExtendWebRtcStream.
type streamResponse struct {
	AnswerSDP    string `json:"answerSdp"`
	MediaSession string `json:"mediaSessionId"`
	ExpiresAt    string `json:"expiresAt"`
}
