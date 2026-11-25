package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/genai"
)

func TestGenAIProtocolRegistrationAndDefaults(t *testing.T) {
	if !validProtocol(protocolGenAI) {
		t.Fatalf("expected protocol %q to be valid", protocolGenAI)
	}
	if effectiveProtocol(protocolGenAI) != protocolGenAI {
		t.Fatalf("expected effectiveProtocol to return %q, got %q", protocolGenAI, effectiveProtocol(protocolGenAI))
	}
	if DefaultGenAIBaseURL != "https://generativelanguage.googleapis.com" {
		t.Fatalf("unexpected DefaultGenAIBaseURL: %s", DefaultGenAIBaseURL)
	}

	// Key store normalization defaults empty BaseURL to DefaultGenAIBaseURL
	record := persistedAPIKey{APIProtocol: protocolGenAI}
	normalizeKeyPolicy(&record)
	if record.BaseURL != DefaultGenAIBaseURL {
		t.Fatalf("expected default BaseURL %s, got %s", DefaultGenAIBaseURL, record.BaseURL)
	}

	// Custom BaseURL must be preserved
	customURL := "https://custom-gemini-proxy.internal"
	customRecord := persistedAPIKey{APIProtocol: protocolGenAI, BaseURL: customURL}
	normalizeKeyPolicy(&customRecord)
	if customRecord.BaseURL != customURL {
		t.Fatalf("expected custom BaseURL %s, got %s", customURL, customRecord.BaseURL)
	}

	// Upstream settings defaulting
	server := multiUpstreamProxy(t, "https://agentrouter.org")
	key := selectedAPIKey{
		APIProtocol: protocolGenAI,
		BaseURL:     "",
	}
	base, _, protocol, err := server.upstreamSettings(&key)
	if err != nil {
		t.Fatalf("upstreamSettings failed: %v", err)
	}
	if protocol != protocolGenAI {
		t.Fatalf("expected protocol %s, got %s", protocolGenAI, protocol)
	}
	if base.String() != DefaultGenAIBaseURL {
		t.Fatalf("expected base URL %s, got %s", DefaultGenAIBaseURL, base.String())
	}

	// prepareUpstream routing verification
	_, _, _, err = server.prepareUpstream("/v1/chat/completions", []byte(`{}`), protocolGenAI)
	if err != nil {
		t.Fatalf("expected /v1/chat/completions to be allowed for genai, got %v", err)
	}
	_, _, _, err = server.prepareUpstream("/v1/models", nil, protocolGenAI)
	if err != nil {
		t.Fatalf("expected /v1/models to be allowed for genai, got %v", err)
	}
	_, _, _, err = server.prepareUpstream("/v1/responses", []byte(`{}`), protocolGenAI)
	if err == nil {
		t.Fatalf("expected /v1/responses to be rejected for genai protocol")
	}
}

func TestGenAIMessageConversion(t *testing.T) {
	pngData := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	reqJSON := fmt.Sprintf(`{
		"model": "models/gemini-2.5-flash",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "developer", "content": "Follow safety rules."},
			{"role": "user", "content": "Hello step 1"},
			{"role": "user", "content": [
				{"type": "text", "text": "Hello step 2 with image"},
				{"type": "image_url", "image_url": {"url": "data:image/png;base64,%s"}}
			]},
			{"role": "assistant", "content": "Checking weather...", "tool_calls": [
				{
					"id": "call_123",
					"type": "function",
					"function": {"name": "get_weather", "arguments": "{\"location\":\"Paris\"}"}
				}
			]},
			{"role": "tool", "tool_call_id": "call_123", "content": "{\"temp\": 22}"}
		],
		"temperature": 0.7,
		"top_p": 0.9,
		"max_tokens": 150,
		"stop": ["END", "STOP"],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "get_weather",
					"description": "Get current weather",
					"parameters": {
						"type": "object",
						"properties": {
							"location": {"type": "string"}
						},
						"required": ["location"]
					}
				}
			}
		],
		"tool_choice": "auto"
	}`, pngData)

	cleanModel, contents, config, meta, err := buildGenAIRequest([]byte(reqJSON))
	if err != nil {
		t.Fatalf("buildGenAIRequest failed: %v", err)
	}

	if cleanModel != "gemini-2.5-flash" {
		t.Fatalf("expected cleanModel 'gemini-2.5-flash', got %q", cleanModel)
	}
	if meta.Model != "models/gemini-2.5-flash" {
		t.Fatalf("expected meta.Model to preserve client string, got %q", meta.Model)
	}

	// Verify SystemInstruction
	if config.SystemInstruction == nil || len(config.SystemInstruction.Parts) != 1 {
		t.Fatalf("expected 1 combined part in SystemInstruction, got %v", config.SystemInstruction)
	}
	sysText := config.SystemInstruction.Parts[0].Text
	if !strings.Contains(sysText, "You are a helpful assistant.") || !strings.Contains(sysText, "Follow safety rules.") {
		t.Fatalf("unexpected system instruction: %s", sysText)
	}

	// Verify Contents turns
	if len(contents) != 3 {
		t.Fatalf("expected 3 turns (user, model, user/tool), got %d turns", len(contents))
	}

	// Turn 0: User merged turn
	userTurn := contents[0]
	if userTurn.Role != "user" || len(userTurn.Parts) != 3 {
		t.Fatalf("expected merged user turn with 3 parts, got %d parts, role %s", len(userTurn.Parts), userTurn.Role)
	}
	if userTurn.Parts[0].Text != "Hello step 1" {
		t.Fatalf("expected first text part 'Hello step 1', got %q", userTurn.Parts[0].Text)
	}
	if userTurn.Parts[1].Text != "Hello step 2 with image" {
		t.Fatalf("expected second text part 'Hello step 2 with image', got %q", userTurn.Parts[1].Text)
	}
	blob := userTurn.Parts[2].InlineData
	if blob == nil || blob.MIMEType != "image/png" {
		t.Fatalf("expected image blob part with MIMEType image/png, got %v", userTurn.Parts[2])
	}
	expectedBytes, _ := base64.StdEncoding.DecodeString(pngData)
	if len(blob.Data) != len(expectedBytes) {
		t.Fatalf("expected %d bytes in blob, got %d", len(expectedBytes), len(blob.Data))
	}

	// Turn 1: Model with FunctionCall
	modelTurn := contents[1]
	if modelTurn.Role != "model" || len(modelTurn.Parts) != 2 {
		t.Fatalf("expected model turn with 2 parts (text + functionCall), got %d parts", len(modelTurn.Parts))
	}
	fc := modelTurn.Parts[1].FunctionCall
	if fc == nil || fc.Name != "get_weather" {
		t.Fatalf("expected FunctionCall for get_weather, got %v", modelTurn.Parts[1])
	}
	if loc, ok := fc.Args["location"].(string); !ok || loc != "Paris" {
		t.Fatalf("expected argument location=Paris, got %v", fc.Args)
	}

	// Turn 2: FunctionResponse
	toolTurn := contents[2]
	if toolTurn.Role != "user" || len(toolTurn.Parts) != 1 {
		t.Fatalf("expected tool response in user turn with 1 part, got %d", len(toolTurn.Parts))
	}
	fr := toolTurn.Parts[0].FunctionResponse
	if fr == nil || fr.Name != "get_weather" {
		t.Fatalf("expected FunctionResponse for get_weather, got %v", toolTurn.Parts[0])
	}
	if temp, ok := fr.Response["temp"].(float64); !ok || temp != 22 {
		t.Fatalf("expected response temp=22, got %v", fr.Response)
	}

	// Verify Config options
	if config.Temperature == nil || *config.Temperature != 0.7 {
		t.Fatalf("expected temperature 0.7, got %v", config.Temperature)
	}
	if config.TopP == nil || *config.TopP != 0.9 {
		t.Fatalf("expected topP 0.9, got %v", config.TopP)
	}
	if config.MaxOutputTokens != 150 {
		t.Fatalf("expected maxTokens 150, got %d", config.MaxOutputTokens)
	}
	if len(config.StopSequences) != 2 || config.StopSequences[0] != "END" || config.StopSequences[1] != "STOP" {
		t.Fatalf("unexpected stop sequences: %v", config.StopSequences)
	}
	if len(config.Tools) != 1 || len(config.Tools[0].FunctionDeclarations) != 1 {
		t.Fatalf("expected 1 function declaration in tools, got %v", config.Tools)
	}
}

func TestGenAINonStreamingGeneration(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/models/gemini-2.5-flash:generateContent") {
			t.Errorf("unexpected endpoint path: %s", r.URL.Path)
		}
		key := r.Header.Get("x-goog-api-key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}
		if key != "sk-gemini-test-key" {
			t.Errorf("unexpected api key: %s", key)
		}

		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"role": "model",
						"parts": []any{
							map[string]any{"text": "Hello from Google GenAI!"},
						},
					},
					"finishReason": "STOP",
				},
			},
			"usageMetadata": map[string]any{
				"promptTokenCount":     12,
				"candidatesTokenCount": 8,
				"totalTokenCount":      20,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	addUpstream(t, proxy, "gemini", mockServer.URL, protocolGenAI, "sk-gemini-test-key", 100, "gemini-2.5-flash")

	reqBody := `{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Hello"}]}`
	rec := requestGateway(proxy, "/v1/chat/completions", reqBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var chatResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &chatResp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if chatResp["object"] != "chat.completion" {
		t.Errorf("expected object 'chat.completion', got %v", chatResp["object"])
	}
	choices, _ := chatResp["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(choices))
	}
	firstChoice, _ := choices[0].(map[string]any)
	msg, _ := firstChoice["message"].(map[string]any)
	if msg["content"] != "Hello from Google GenAI!" {
		t.Errorf("expected content 'Hello from Google GenAI!', got %v", msg["content"])
	}
	if firstChoice["finish_reason"] != "stop" {
		t.Errorf("expected finish_reason 'stop', got %v", firstChoice["finish_reason"])
	}

	usage, _ := chatResp["usage"].(map[string]any)
	if usage["prompt_tokens"] != float64(12) || usage["completion_tokens"] != float64(8) || usage["total_tokens"] != float64(20) {
		t.Errorf("unexpected usage metrics: %v", usage)
	}
}

func TestGenAINonStreamingToolCall(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"role": "model",
						"parts": []any{
							map[string]any{
								"functionCall": map[string]any{
									"name": "lookup_stock",
									"args": map[string]any{"ticker": "GOOG"},
								},
							},
						},
					},
					"finishReason": "STOP",
				},
			},
			"usageMetadata": map[string]any{
				"promptTokenCount":     15,
				"candidatesTokenCount": 10,
				"totalTokenCount":      25,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	addUpstream(t, proxy, "gemini-tools", mockServer.URL, protocolGenAI, "sk-test-tool-key", 100, "gemini-2.5-flash")

	reqBody := `{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Stock price?"}],"tools":[{"type":"function","function":{"name":"lookup_stock"}}]}`
	rec := requestGateway(proxy, "/v1/chat/completions", reqBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var chatResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &chatResp)
	choices, _ := chatResp["choices"].([]any)
	firstChoice, _ := choices[0].(map[string]any)
	if firstChoice["finish_reason"] != "tool_calls" {
		t.Errorf("expected finish_reason 'tool_calls', got %v", firstChoice["finish_reason"])
	}
	msg, _ := firstChoice["message"].(map[string]any)
	toolCalls, _ := msg["tool_calls"].([]any)
	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(toolCalls))
	}
	tc, _ := toolCalls[0].(map[string]any)
	fn, _ := tc["function"].(map[string]any)
	if fn["name"] != "lookup_stock" {
		t.Errorf("expected function name lookup_stock, got %v", fn["name"])
	}
	if fn["arguments"] != `{"ticker":"GOOG"}` {
		t.Errorf("expected args '{\"ticker\":\"GOOG\"}', got %v", fn["arguments"])
	}
}

func TestGenAIStreamingGeneration(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, ":streamGenerateContent") {
			t.Errorf("expected streaming endpoint :streamGenerateContent, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)

		chunk1 := `data: {"candidates": [{"content": {"role": "model", "parts": [{"text": "Streamed "}]}}]}` + "\n\n"
		_, _ = io.WriteString(w, chunk1)
		flusher.Flush()

		chunk2 := `data: {"candidates": [{"content": {"role": "model", "parts": [{"text": "response."}]},"finishReason": "STOP"}],"usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15}}` + "\n\n"
		_, _ = io.WriteString(w, chunk2)
		flusher.Flush()
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	addUpstream(t, proxy, "gemini-stream", mockServer.URL, protocolGenAI, "sk-stream-key", 100, "gemini-2.5-flash")

	reqBody := `{"model":"gemini-2.5-flash","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello stream"}]}`
	rec := requestGateway(proxy, "/v1/chat/completions", reqBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %s", rec.Header().Get("Content-Type"))
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: [DONE]") {
		t.Fatalf("expected data: [DONE] token in stream, body was:\n%s", body)
	}

	// Parse SSE events
	lines := strings.Split(body, "\n")
	var textDeltas []string
	var gotUsage bool
	var gotFinishReason bool

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			continue
		}
		var chunk map[string]any
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			t.Fatalf("failed to parse SSE chunk JSON: %v, raw: %s", err, payload)
		}
		if chunk["object"] != "chat.completion.chunk" {
			t.Errorf("expected object 'chat.completion.chunk', got %v", chunk["object"])
		}
		if usage, ok := chunk["usage"].(map[string]any); ok && usage != nil {
			gotUsage = true
			if usage["total_tokens"] != float64(15) {
				t.Errorf("unexpected total_tokens: %v", usage["total_tokens"])
			}
		}
		if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
			first, _ := choices[0].(map[string]any)
			if delta, ok := first["delta"].(map[string]any); ok {
				if content, ok := delta["content"].(string); ok {
					textDeltas = append(textDeltas, content)
				}
			}
			if fr, ok := first["finish_reason"].(string); ok && fr != "" {
				gotFinishReason = true
				if fr != "stop" {
					t.Errorf("expected finish_reason 'stop', got %q", fr)
				}
			}
		}
	}

	fullText := strings.Join(textDeltas, "")
	if fullText != "Streamed response." {
		t.Errorf("expected full text 'Streamed response.', got %q", fullText)
	}
	if !gotUsage {
		t.Errorf("expected usage chunk in stream")
	}
	if !gotFinishReason {
		t.Errorf("expected finish_reason chunk in stream")
	}
}

func TestGenAIErrorHandlingAndFailover(t *testing.T) {
	attemptCount := 0
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		key := r.Header.Get("x-goog-api-key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}

		if key == "sk-failing-key" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    401,
					"message": "API key sk-failing-key is invalid",
					"status":  "UNAUTHENTICATED",
				},
			})
			return
		}

		// Second key succeeds
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"role":  "model",
						"parts": []any{map[string]any{"text": "Failover succeeded!"}},
					},
					"finishReason": "STOP",
				},
			},
		})
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	addUpstream(t, proxy, "key-fail", mockServer.URL, protocolGenAI, "sk-failing-key", 200, "gemini-2.5-flash")
	addUpstream(t, proxy, "key-ok", mockServer.URL, protocolGenAI, "sk-working-key", 100, "gemini-2.5-flash")

	reqBody := `{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"Test failover"}]}`
	rec := requestGateway(proxy, "/v1/chat/completions", reqBody)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 after failover, got %d: %s", rec.Code, rec.Body.String())
	}
	if attemptCount != 2 {
		t.Errorf("expected 2 attempts (1 failure + 1 failover), got %d", attemptCount)
	}

	var chatResp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &chatResp)
	choices, _ := chatResp["choices"].([]any)
	first, _ := choices[0].(map[string]any)
	msg, _ := first["message"].(map[string]any)
	if msg["content"] != "Failover succeeded!" {
		t.Errorf("expected 'Failover succeeded!', got %v", msg["content"])
	}
}

func TestGenAIKeyProbe(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-goog-api-key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}

		if key == "sk-invalid" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    403,
					"message": "Permission denied for sk-invalid",
					"status":  "PERMISSION_DENIED",
				},
			})
			return
		}

		// Valid probe response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []any{
				map[string]any{"name": "models/gemini-2.5-flash"},
			},
		})
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	parsed, _ := url.Parse(mockServer.URL)
	route := &outboundRoute{client: mockServer.Client()}

	// Probe valid key
	status, msg := proxy.probeGenAIKey(context.Background(), route, parsed, selectedAPIKey{
		Key: "sk-valid",
	})
	if status != http.StatusOK {
		t.Errorf("expected probe status 200, got %d: %s", status, msg)
	}

	// Probe invalid key
	status, msg = proxy.probeGenAIKey(context.Background(), route, parsed, selectedAPIKey{
		Key: "sk-invalid",
	})
	if status != http.StatusForbidden {
		t.Errorf("expected probe status 403, got %d: %s", status, msg)
	}
	if strings.Contains(msg, "sk-invalid") {
		t.Errorf("expected api key to be redacted from probe error message, got: %s", msg)
	}
}

func TestGenAIModelsEndpoint(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []any{
				map[string]any{"name": "models/gemini-2.5-flash"},
				map[string]any{"name": "models/gemini-2.5-pro"},
			},
		})
	}))
	defer mockServer.Close()

	proxy := multiUpstreamProxy(t, mockServer.URL)
	addUpstream(t, proxy, "gemini-models", mockServer.URL, protocolGenAI, "sk-models-key", 100)

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptest.NewRecorder()
	proxy.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var modelsResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &modelsResp); err != nil {
		t.Fatalf("failed to decode models JSON: %v", err)
	}
	if modelsResp["object"] != "list" {
		t.Errorf("expected object 'list', got %v", modelsResp["object"])
	}
	data, _ := modelsResp["data"].([]any)
	if len(data) != 2 {
		t.Fatalf("expected 2 models, got %d", len(data))
	}
	m0, _ := data[0].(map[string]any)
	if m0["id"] != "gemini-2.5-flash" {
		t.Errorf("expected model id 'gemini-2.5-flash', got %v", m0["id"])
	}
	m1, _ := data[1].(map[string]any)
	if m1["id"] != "gemini-2.5-pro" {
		t.Errorf("expected model id 'gemini-2.5-pro', got %v", m1["id"])
	}
}

func TestSSRFMetadataProtection(t *testing.T) {
	blockedURLs := []string{
		"http://169.254.169.254",
		"http://169.254.169.254:80",
		"http://169.254.1.1:8080/path",
		"http://[fe80::1]:8080",
		"http://metadata.google.internal",
		"http://instance-data",
		"http://metadata",
		"http://custom.metadata.internal",
		"http://2852039166:80", // decimal integer IP representation of 169.254.169.254
	}

	for _, raw := range blockedURLs {
		_, err := parseUpstreamURL(raw)
		if err == nil {
			t.Errorf("expected SSRF block for %s, but parsing succeeded", raw)
		}
	}

	// Verify valid external and local development URLs are not blocked
	validURLs := []string{
		"https://generativelanguage.googleapis.com",
		"https://api.openai.com/v1",
		"http://localhost:11434",
		"http://127.0.0.1:8000/v1",
	}
	for _, raw := range validURLs {
		_, err := parseUpstreamURL(raw)
		if err != nil {
			t.Errorf("expected URL %s to be valid, got error: %v", raw, err)
		}
	}
}

func TestGenAIThinkingAndReasoning(t *testing.T) {
	// 1. Test reasoning_effort mapping
	cases := []struct {
		effort         string
		expectedBudget int32
		includeThought bool
	}{
		{"low", 1024, true},
		{"medium", 4096, true},
		{"high", 16384, true},
		{"none", 0, false},
	}

	for _, tc := range cases {
		body := []byte(fmt.Sprintf(`{"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "hi"}], "reasoning_effort": %q}`, tc.effort))
		_, _, config, _, err := buildGenAIRequest(body)
		if err != nil {
			t.Fatalf("buildGenAIRequest failed for effort %s: %v", tc.effort, err)
		}
		if config.ThinkingConfig == nil {
			t.Fatalf("expected ThinkingConfig to be set for effort %s", tc.effort)
		}
		if config.ThinkingConfig.IncludeThoughts != tc.includeThought {
			t.Errorf("effort %s: expected IncludeThoughts=%v, got %v", tc.effort, tc.includeThought, config.ThinkingConfig.IncludeThoughts)
		}
		if config.ThinkingConfig.ThinkingBudget == nil || *config.ThinkingConfig.ThinkingBudget != tc.expectedBudget {
			t.Errorf("effort %s: expected budget %d, got %v", tc.effort, tc.expectedBudget, config.ThinkingConfig.ThinkingBudget)
		}
	}

	// 2. Test thinking.budget_tokens
	body := []byte(`{"model": "gemini-2.5-flash", "messages": [{"role": "user", "content": "hi"}], "thinking": {"budget_tokens": 2048}}`)
	_, _, config, _, err := buildGenAIRequest(body)
	if err != nil {
		t.Fatalf("buildGenAIRequest failed: %v", err)
	}
	if config.ThinkingConfig == nil || config.ThinkingConfig.ThinkingBudget == nil || *config.ThinkingConfig.ThinkingBudget != 2048 {
		t.Fatalf("expected budget 2048, got %v", config.ThinkingConfig)
	}

	// 3. Test convertGenAIResponse thought extraction into reasoning_content
	genResp := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "Thinking through the solution...", Thought: true},
						{Text: "The final answer is 42.", Thought: false},
					},
				},
				FinishReason: genai.FinishReasonStop,
			},
		},
		UsageMetadata: &genai.GenerateContentResponseUsageMetadata{
			PromptTokenCount:     10,
			CandidatesTokenCount: 20,
			TotalTokenCount:      30,
		},
	}

	raw, err := convertGenAIResponse(genResp, "gemini-2.5-flash")
	if err != nil {
		t.Fatalf("convertGenAIResponse failed: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("failed to unmarshal converted response: %v", err)
	}

	choices, _ := out["choices"].([]any)
	if len(choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(choices))
	}
	choice0, _ := choices[0].(map[string]any)
	msg, _ := choice0["message"].(map[string]any)

	if msg["reasoning_content"] != "Thinking through the solution..." {
		t.Errorf("expected reasoning_content 'Thinking through the solution...', got %v", msg["reasoning_content"])
	}
	if msg["content"] != "The final answer is 42." {
		t.Errorf("expected content 'The final answer is 42.', got %v", msg["content"])
	}
}

func TestGenAIMultimodalAudioAndDocument(t *testing.T) {
	audioB64 := base64.StdEncoding.EncodeToString([]byte("fake-mp3-audio-bytes"))
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 test pdf"))

	body := []byte(fmt.Sprintf(`{
		"model": "gemini-2.5-flash",
		"messages": [
			{
				"role": "user",
				"content": [
					{"type": "text", "text": "Analyze this:"},
					{"type": "input_audio", "input_audio": {"data": "%s", "format": "mp3"}},
					{"type": "file", "file": {"url": "data:application/pdf;base64,%s"}}
				]
			}
		]
	}`, audioB64, pdfB64))

	_, contents, _, _, err := buildGenAIRequest(body)
	if err != nil {
		t.Fatalf("buildGenAIRequest failed: %v", err)
	}

	if len(contents) != 1 || len(contents[0].Parts) != 3 {
		t.Fatalf("expected 1 turn with 3 parts, got %d turns, parts: %d", len(contents), len(contents[0].Parts))
	}

	pAudio := contents[0].Parts[1]
	if pAudio.InlineData == nil || pAudio.InlineData.MIMEType != "audio/mpeg" {
		t.Errorf("expected audio/mpeg inline data, got %v", pAudio.InlineData)
	}
	if string(pAudio.InlineData.Data) != "fake-mp3-audio-bytes" {
		t.Errorf("unexpected audio data: %s", string(pAudio.InlineData.Data))
	}

	pDoc := contents[0].Parts[2]
	if pDoc.InlineData == nil || pDoc.InlineData.MIMEType != "application/pdf" {
		t.Errorf("expected application/pdf inline data, got %v", pDoc.InlineData)
	}
	if string(pDoc.InlineData.Data) != "%PDF-1.4 test pdf" {
		t.Errorf("unexpected pdf data: %s", string(pDoc.InlineData.Data))
	}
}

func TestHealthAndCORSGenAI(t *testing.T) {
	// 1. Check health in genai mode returns "ok" even without WAF cookies
	server := multiUpstreamProxy(t, "https://generativelanguage.googleapis.com")
	server.cfg.UpstreamProtocol = protocolGenAI
	server.cfg.Profile = "claude-code" // normally requires WAF cookies, but genai protocol exempts it

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from health, got %d", rec.Code)
	}

	var health map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("expected status 'ok' for genai upstream, got %v", health["status"])
	}

	// 2. Check CORS headers and Max-Age
	optReq := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	optRec := httptest.NewRecorder()
	server.routes().ServeHTTP(optRec, optReq)

	if optRec.Code != http.StatusNoContent {
		t.Errorf("expected 204 No Content for OPTIONS, got %d", optRec.Code)
	}
	if maxAge := optRec.Header().Get("Access-Control-Max-Age"); maxAge != "86400" {
		t.Errorf("expected Access-Control-Max-Age: 86400, got %s", maxAge)
	}
	allowHeaders := optRec.Header().Get("Access-Control-Allow-Headers")
	if !strings.Contains(allowHeaders, "X-Admin-CSRF") || !strings.Contains(allowHeaders, "X-Admin-Session") {
		t.Errorf("expected CORS allow headers to include admin headers, got %s", allowHeaders)
	}
}
