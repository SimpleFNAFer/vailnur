package mlclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const mlServerURL = "http://localhost:8000/predict/batch"

// PredictRequest is one item sent to the ML server.
type PredictRequest struct {
	Method string              `json:"method"`
	URL    string              `json:"url"`
	Params map[string][]string `json:"params"`
}

// MLResult is one item returned by the ML server.
type MLResult struct {
	Label       string             `json:"label"`
	Probability float64            `json:"probability"`
	BranchProbs map[string]float64 `json:"branch_probs"`
}

// Client is an HTTP client for the Python ML server.
type Client struct {
	http *http.Client
}

// New creates a Client with a 30 s timeout.
func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// PredictBatch sends a batch of requests to the ML server and returns results
// in the same order as the input slice.
func (c *Client) PredictBatch(reqs []PredictRequest) ([]MLResult, error) {
	body, err := json.Marshal(reqs)
	if err != nil {
		return nil, fmt.Errorf("mlclient: marshal: %w", err)
	}

	resp, err := c.http.Post(mlServerURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mlclient: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mlclient: unexpected status %d", resp.StatusCode)
	}

	var results []MLResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("mlclient: decode: %w", err)
	}

	if len(results) != len(reqs) {
		return nil, fmt.Errorf("mlclient: got %d results for %d requests", len(results), len(reqs))
	}

	return results, nil
}
