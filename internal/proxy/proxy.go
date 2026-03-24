package proxy

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

type Client struct {
	TargetURL string
	Timeout   time.Duration
	Token     string
}

func (c *Client) ForwardJSON(body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, c.TargetURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("X-Guard-Token", c.Token)
	}

	hc := &http.Client{Timeout: c.Timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}
