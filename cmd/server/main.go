package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"clawguard-dlp-go/internal/audit"
	"clawguard-dlp-go/internal/dlp"
	"clawguard-dlp-go/internal/policy"
	"clawguard-dlp-go/internal/proxy"
)

type Req struct {
	UserID string `json:"userId"`
	Text   string `json:"text"`
}

type Resp struct {
	Action       string        `json:"action"`
	RedactedText string        `json:"redactedText,omitempty"`
	Findings     []dlp.Finding `json:"findings,omitempty"`
	Message      string        `json:"message,omitempty"`
}

type ModelProxyReq struct {
	UserID       string `json:"userId"`
	Prompt       string `json:"prompt"`
	ModelPayload any    `json:"modelPayload,omitempty"`
}

func main() {
	listen := env("CLAWGUARD_LISTEN", ":18080")
	auditPath := env("CLAWGUARD_AUDIT_PATH", "/tmp/clawguard_audit.log")
	proxyTarget := os.Getenv("CLAWGUARD_MODEL_TARGET")
	upstreamBase := env("CLAWGUARD_UPSTREAM_BASE", "https://chatgpt.com")
	guardToken := env("CLAWGUARD_TOKEN", "change-me")
	defaultAction := env("CLAWGUARD_DEFAULT_ACTION", "ALLOW_REDACTED")
	highAction := env("CLAWGUARD_HIGH_ACTION", "BLOCK")

	red := dlp.NewRedactor()
	pol := policy.NewEngine(parseAction(defaultAction), parseAction(highAction))
	aud := audit.New(auditPath)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/v1/sanitize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req Req
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res := red.Run(req.Text)
		act := pol.Decide(policy.Input{UserID: req.UserID, HitHigh: res.HitHigh})

		_ = aud.Write(audit.Record{Time: time.Now(), UserID: req.UserID, Action: string(act), Findings: res.Findings})

		if act == policy.Block {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(Resp{Action: string(act), Message: "sensitive content blocked by policy"})
			return
		}

		_ = json.NewEncoder(w).Encode(Resp{Action: string(act), RedactedText: res.RedactedText, Findings: res.Findings})
	})

	// 强制模式：只有带 X-Guard-Token 的请求才能走模型代理
	http.HandleFunc("/v1/model-proxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Guard-Token") != guardToken {
			http.Error(w, "missing or invalid guard token", http.StatusUnauthorized)
			return
		}
		if proxyTarget == "" {
			http.Error(w, "model proxy target not configured", http.StatusBadGateway)
			return
		}

		var req ModelProxyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res := red.Run(req.Prompt)
		act := pol.Decide(policy.Input{UserID: req.UserID, HitHigh: res.HitHigh})
		_ = aud.Write(audit.Record{Time: time.Now(), UserID: req.UserID, Action: "MODEL_PROXY_" + string(act), Findings: res.Findings})

		if act == policy.Block {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(Resp{Action: string(act), Message: "blocked by DLP policy"})
			return
		}

		payload := map[string]any{
			"userId":       req.UserID,
			"prompt":       res.RedactedText,
			"modelPayload": req.ModelPayload,
			"guard": map[string]any{
				"action":   act,
				"findings": res.Findings,
			},
		}
		b, _ := json.Marshal(payload)
		pc := &proxy.Client{TargetURL: proxyTarget, Timeout: 30 * time.Second, Token: guardToken}
		respBody, code, err := pc.ForwardJSON(b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(code)
		_, _ = w.Write(respBody)
	})

	// transparent upstream proxy for provider baseUrl switch (sanitizes JSON strings)
	rawf := &proxy.RawForwarder{UpstreamBase: strings.TrimRight(upstreamBase, "/"), Timeout: 60 * time.Second}
	http.HandleFunc("/backend-api/", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes := []byte{}
		if r.Body != nil {
			defer r.Body.Close()
			b, _ := io.ReadAll(r.Body)
			bodyBytes = b
		}
		if len(bodyBytes) > 0 && strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			if redBody, ok := sanitizeJSONBytes(bodyBytes, red); ok {
				bodyBytes = redBody
			}
		}
		respBody, code, respHeaders, err := rawf.Forward(r.Method, r.URL.RequestURI(), r.Header, bodyBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for k, vals := range respHeaders {
			if strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(code)
		_, _ = w.Write(respBody)
	})

	log.Printf("clawguard listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, nil))
}

func env(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func parseAction(v string) policy.Action {
	switch v {
	case string(policy.Block):
		return policy.Block
	case string(policy.LocalOnly):
		return policy.LocalOnly
	default:
		return policy.AllowRedacted
	}
}

func sanitizeJSONBytes(in []byte, red *dlp.Redactor) ([]byte, bool) {
	var obj any
	if err := json.Unmarshal(in, &obj); err != nil {
		return nil, false
	}
	sanitized := walkAndRedact(obj, red)
	out, err := json.Marshal(sanitized)
	if err != nil {
		return nil, false
	}
	return out, true
}

func walkAndRedact(v any, red *dlp.Redactor) any {
	switch t := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, vv := range t {
			m[k] = walkAndRedact(vv, red)
		}
		return m
	case []any:
		arr := make([]any, len(t))
		for i := range t {
			arr[i] = walkAndRedact(t[i], red)
		}
		return arr
	case string:
		return red.Run(t).RedactedText
	default:
		return v
	}
}
