package proxy

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

type RawForwarder struct {
	UpstreamBase string
	Timeout      time.Duration
}

func (f *RawForwarder) Forward(method, pathQuery string, inHeaders http.Header, body []byte) ([]byte, int, http.Header, error) {
	url := f.UpstreamBase + pathQuery
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	for k, vals := range inHeaders {
		if k == "Host" || k == "Content-Length" {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	hc := &http.Client{Timeout: f.Timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, resp.Header, err
}
