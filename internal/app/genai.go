package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/genai"
)

func sanitizeErrorMessage(msg, apiKey string) string {
	if apiKey != "" {
		msg = strings.ReplaceAll(msg, apiKey, "[REDACTED_API_KEY]")
	}
	return msg
}

func formatGenAIErrorResponse(status int, err error, apiKey string) *http.Response {
	var apiErr genai.APIError
	var pApiErr *genai.APIError
	msg := ""
	if errors.As(err, &apiErr) {
		status = apiErr.Code
		msg = apiErr.Message
		if msg == "" {
			msg = apiErr.Status
		}
	} else if errors.As(err, &pApiErr) && pApiErr != nil {
		status = pApiErr.Code
		msg = pApiErr.Message
		if msg == "" {
			msg = pApiErr.Status
		}
	}
	if msg == "" && err != nil {
		msg = err.Error()
	}
	if status == 0 {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			status = http.StatusGatewayTimeout
		} else {
			status = http.StatusBadGateway
		}
	}
	msg = sanitizeErrorMessage(msg, apiKey)
	errPayload, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    "upstream_error",
			"code":    status,
		},
	})
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(errPayload)),
	}
}

func (server *proxyServer) probeGenAIKey(ctx context.Context, route *outboundRoute, baseURL *url.URL, key selectedAPIKey) (int, string) {
	baseURLStr := DefaultGenAIBaseURL
	if baseURL != nil && baseURL.String() != "" {
		baseURLStr = baseURL.String()
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		Backend:     genai.BackendGeminiAPI,
		APIKey:      key.Key,
		HTTPClient:  route.client,
		HTTPOptions: genai.HTTPOptions{BaseURL: baseURLStr},
	})
	if err != nil {
		return http.StatusBadRequest, "failed to initialize genai client"
	}
	page, err := client.Models.List(ctx, &genai.ListModelsConfig{PageSize: 1})
	if err != nil {
		var apiErr genai.APIError
		var pApiErr *genai.APIError
		var code int
		var msg string
		if errors.As(err, &apiErr) {
			code = apiErr.Code
			msg = apiErr.Message
			if msg == "" {
				msg = apiErr.Status
			}
		} else if errors.As(err, &pApiErr) && pApiErr != nil {
			code = pApiErr.Code
			msg = pApiErr.Message
			if msg == "" {
				msg = pApiErr.Status
			}
		}
		if code != 0 {
			if key.NetworkProxy != nil && code == http.StatusProxyAuthRequired {
				server.keys.recordProxyProbe(key.NetworkProxy.ID, false)
				return 0, "network proxy authentication failed"
			}
			if msg == "" {
				msg = http.StatusText(code)
			}
			return code, sanitizeErrorMessage(msg, key.Key)
		}
		if key.NetworkProxy != nil {
			server.keys.recordProxyProbe(key.NetworkProxy.ID, false)
			return 0, "network proxy connection failed"
		}
		return http.StatusBadGateway, "upstream connection failed"
	}
	_ = page
	return http.StatusOK, "Key accepted by Gemini models endpoint"
}

func (server *proxyServer) handleGenAIModels(ctx context.Context, route *outboundRoute, baseURL *url.URL, key *selectedAPIKey) (*http.Response, error) {
	apiKey := ""
	if key != nil {
		apiKey = key.Key
	}
	baseURLStr := DefaultGenAIBaseURL
	if baseURL != nil && baseURL.String() != "" {
		baseURLStr = baseURL.String()
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		Backend:     genai.BackendGeminiAPI,
		APIKey:      apiKey,
		HTTPClient:  route.client,
		HTTPOptions: genai.HTTPOptions{BaseURL: baseURLStr},
	})
	if err != nil {
		return formatGenAIErrorResponse(http.StatusBadRequest, err, apiKey), nil
	}
	page, err := client.Models.List(ctx, nil)
	if err != nil {
		return formatGenAIErrorResponse(0, err, apiKey), nil
	}
	type openAIModel struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	models := make([]openAIModel, 0)
	now := time.Now().Unix()
	for _, m := range page.Items {
		id := strings.TrimPrefix(m.Name, "models/")
		models = append(models, openAIModel{
			ID:      id,
			Object:  "model",
			Created: now,
			OwnedBy: "google",
		})
	}
	payload, err := json.Marshal(map[string]any{
		"object": "list",
		"data":   models,
	})
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(payload)),
	}, nil
}

func (server *proxyServer) executeGenAI(ctx context.Context, route *outboundRoute, baseURL *url.URL, key *selectedAPIKey, model string, body []byte, stream bool) (*http.Response, error) {
	apiKey := ""
	if key != nil {
		apiKey = key.Key
	}
	baseURLStr := DefaultGenAIBaseURL
	if baseURL != nil && baseURL.String() != "" {
		baseURLStr = baseURL.String()
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		Backend:     genai.BackendGeminiAPI,
		APIKey:      apiKey,
		HTTPClient:  route.client,
		HTTPOptions: genai.HTTPOptions{BaseURL: baseURLStr},
	})
	if err != nil {
		return formatGenAIErrorResponse(http.StatusBadRequest, err, apiKey), nil
	}

	reqModel, contents, config, meta, err := buildGenAIRequest(body)
	if err != nil {
		return formatGenAIErrorResponse(http.StatusBadRequest, err, apiKey), nil
	}
	if reqModel != "" {
		model = reqModel
	}

	if stream {
		return streamGenAIResponse(ctx, client, model, contents, config, meta, apiKey)
	}

	resp, err := client.Models.GenerateContent(ctx, model, contents, config)
	if err != nil {
		return formatGenAIErrorResponse(0, err, apiKey), nil
	}

	convertedJSON, err := convertGenAIResponse(resp, meta.Model)
	if err != nil {
		return formatGenAIErrorResponse(http.StatusBadGateway, fmt.Errorf("failed to convert genai response: %w", err), apiKey), nil
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(convertedJSON)),
	}, nil
}

func buildGenAIRequest(body []byte) (string, []*genai.Content, *genai.GenerateContentConfig, *requestMeta, error) {
	in, err := decodeObject(body)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}

	model, _ := in["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" {
		return "", nil, nil, nil, errors.New("model must be a non-empty string")
	}

	stream, _ := in["stream"].(bool)
	meta := &requestMeta{Model: model, Stream: stream, IncludeUsage: true}
	cleanModel := strings.TrimPrefix(model, "models/")
	if opts, ok := in["stream_options"].(map[string]any); ok {
		if include, ok := opts["include_usage"].(bool); ok {
			meta.IncludeUsage = include
		}
	}

	rawMessages, ok := in["messages"].([]any)
	if !ok {
		return "", nil, nil, nil, errors.New("messages must be an array")
	}

	contents, systemInstruction, err := convertMessagesToGenAI(rawMessages)
	if err != nil {
		return "", nil, nil, nil, err
	}

	config := &genai.GenerateContentConfig{}
	if systemInstruction != nil {
		config.SystemInstruction = systemInstruction
	}

	if temp, ok := toFloat32(in["temperature"]); ok {
		config.Temperature = &temp
	}
	if topP, ok := toFloat32(in["top_p"]); ok {
		config.TopP = &topP
	}
	if topK, ok := toFloat32(in["top_k"]); ok {
		config.TopK = &topK
	}
	if maxTokens, ok := toInt32(in["max_completion_tokens"]); ok {
		config.MaxOutputTokens = maxTokens
	} else if maxTokens, ok := toInt32(in["max_tokens"]); ok {
		config.MaxOutputTokens = maxTokens
	}

	if stop, ok := in["stop"]; ok {
		if str, ok := stop.(string); ok && str != "" {
			config.StopSequences = []string{str}
		} else if slice, ok := stop.([]any); ok {
			for _, item := range slice {
				if s, ok := item.(string); ok && s != "" {
					config.StopSequences = append(config.StopSequences, s)
				}
			}
		}
	}

	if presence, ok := toFloat32(in["presence_penalty"]); ok {
		config.PresencePenalty = &presence
	}
	if freq, ok := toFloat32(in["frequency_penalty"]); ok {
		config.FrequencyPenalty = &freq
	}
	if seed, ok := toInt32(in["seed"]); ok {
		config.Seed = &seed
	}

	if reasoningEffort, ok := in["reasoning_effort"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(reasoningEffort)) {
		case "low":
			budget := int32(1024)
			config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: true, ThinkingBudget: &budget}
		case "medium":
			budget := int32(4096)
			config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: true, ThinkingBudget: &budget}
		case "high":
			budget := int32(16384)
			config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: true, ThinkingBudget: &budget}
		case "none":
			budget := int32(0)
			config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: false, ThinkingBudget: &budget}
		}
	} else if thinkingObj, ok := in["thinking"].(map[string]any); ok {
		if budgetVal, ok := toInt32(thinkingObj["budget_tokens"]); ok {
			config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: budgetVal > 0, ThinkingBudget: &budgetVal}
		}
	} else if maxThinking, ok := toInt32(in["max_thinking_tokens"]); ok {
		config.ThinkingConfig = &genai.ThinkingConfig{IncludeThoughts: maxThinking > 0, ThinkingBudget: &maxThinking}
	}

	if format, ok := in["response_format"].(map[string]any); ok {
		typ, _ := format["type"].(string)
		if typ == "json_object" {
			config.ResponseMIMEType = "application/json"
		} else if typ == "json_schema" {
			config.ResponseMIMEType = "application/json"
			if schemaObj, ok := format["json_schema"].(map[string]any); ok {
				if schema, ok := schemaObj["schema"]; ok {
					config.ResponseJsonSchema = schema
				}
			}
		}
	}

	if rawTools, ok := in["tools"].([]any); ok {
		tools, err := convertOpenAIToolsToGenAI(rawTools)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if len(tools) > 0 {
			config.Tools = tools
		}
	} else if functions, ok := in["functions"].([]any); ok {
		legacy := make([]any, 0, len(functions))
		for _, fn := range functions {
			legacy = append(legacy, map[string]any{"type": "function", "function": fn})
		}
		tools, err := convertOpenAIToolsToGenAI(legacy)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if len(tools) > 0 {
			config.Tools = tools
		}
	}

	if choice, ok := in["tool_choice"]; ok {
		config.ToolConfig = convertOpenAIToolChoiceToGenAI(choice)
	} else if choice, ok := in["function_call"]; ok {
		config.ToolConfig = convertOpenAIToolChoiceToGenAI(choice)
	}

	return cleanModel, contents, config, meta, nil
}

func convertMessagesToGenAI(messages []any) ([]*genai.Content, *genai.Content, error) {
	var systemTexts []string
	contents := make([]*genai.Content, 0, len(messages))
	toolCallNames := make(map[string]string)

	for i, raw := range messages {
		msg, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("messages[%d] must be an object", i)
		}
		role, _ := msg["role"].(string)

		switch role {
		case "system", "developer":
			if text := contentText(msg["content"]); text != "" {
				systemTexts = append(systemTexts, text)
			}
		case "assistant":
			parts := make([]*genai.Part, 0)
			if content := msg["content"]; content != nil {
				if text := contentText(content); text != "" {
					parts = append(parts, &genai.Part{Text: text})
				}
			}
			if toolCalls, ok := msg["tool_calls"].([]any); ok {
				for _, rawCall := range toolCalls {
					call, ok := rawCall.(map[string]any)
					if !ok {
						continue
					}
					callID, _ := call["id"].(string)
					fn, _ := call["function"].(map[string]any)
					fnName, _ := fn["name"].(string)
					if callID != "" && fnName != "" {
						toolCallNames[callID] = fnName
					}
					rawArgs := stringValue(fn["arguments"], "{}")
					var args map[string]any
					if err := json.Unmarshal([]byte(rawArgs), &args); err != nil || args == nil {
						args = make(map[string]any)
					}
					parts = append(parts, &genai.Part{
						FunctionCall: &genai.FunctionCall{
							ID:   callID,
							Name: fnName,
							Args: args,
						},
					})
				}
			}
			if fn, ok := msg["function_call"].(map[string]any); ok {
				fnName, _ := fn["name"].(string)
				rawArgs := stringValue(fn["arguments"], "{}")
				var args map[string]any
				if err := json.Unmarshal([]byte(rawArgs), &args); err != nil || args == nil {
					args = make(map[string]any)
				}
				parts = append(parts, &genai.Part{
					FunctionCall: &genai.FunctionCall{
						ID:   fnName,
						Name: fnName,
						Args: args,
					},
				})
			}
			if len(parts) > 0 {
				contents = appendContentMergingRole(contents, &genai.Content{
					Role:  genai.RoleModel,
					Parts: parts,
				})
			}
		case "tool", "function":
			callID, _ := msg["tool_call_id"].(string)
			if callID == "" {
				callID, _ = msg["name"].(string)
			}
			fnName, _ := msg["name"].(string)
			if fnName == "" && callID != "" {
				fnName = toolCallNames[callID]
			}
			contentStr := contentText(msg["content"])
			var respMap map[string]any
			if err := json.Unmarshal([]byte(contentStr), &respMap); err != nil || respMap == nil {
				respMap = map[string]any{"response": contentStr}
			}
			part := &genai.Part{
				FunctionResponse: &genai.FunctionResponse{
					ID:       callID,
					Name:     fnName,
					Response: respMap,
				},
			}
			contents = appendContentMergingRole(contents, &genai.Content{
				Role:  genai.RoleUser,
				Parts: []*genai.Part{part},
			})
		default:
			// "user" or unknown roles treated as user
			parts := convertUserContentToParts(msg["content"])
			if len(parts) > 0 {
				contents = appendContentMergingRole(contents, &genai.Content{
					Role:  genai.RoleUser,
					Parts: parts,
				})
			}
		}
	}

	var systemInstruction *genai.Content
	if len(systemTexts) > 0 {
		systemInstruction = &genai.Content{
			Parts: []*genai.Part{{Text: strings.Join(systemTexts, "\n\n")}},
		}
	}

	if len(contents) == 0 {
		contents = append(contents, &genai.Content{
			Role:  genai.RoleUser,
			Parts: []*genai.Part{{Text: "Hello"}},
		})
	}

	return contents, systemInstruction, nil
}

func appendContentMergingRole(contents []*genai.Content, next *genai.Content) []*genai.Content {
	if len(contents) > 0 && contents[len(contents)-1].Role == next.Role {
		contents[len(contents)-1].Parts = append(contents[len(contents)-1].Parts, next.Parts...)
		return contents
	}
	return append(contents, next)
}

func convertUserContentToParts(content any) []*genai.Part {
	parts := make([]*genai.Part, 0)
	switch v := content.(type) {
	case string:
		if v != "" {
			parts = append(parts, &genai.Part{Text: v})
		}
	case []any:
		for _, raw := range v {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typ, _ := item["type"].(string)
			switch typ {
			case "text":
				if text, ok := item["text"].(string); ok && text != "" {
					parts = append(parts, &genai.Part{Text: text})
				}
			case "image_url":
				if imageObj, ok := item["image_url"].(map[string]any); ok {
					urlStr, _ := imageObj["url"].(string)
					if mime, data, ok := parseDataURI(urlStr); ok {
						parts = append(parts, &genai.Part{
							InlineData: &genai.Blob{
								MIMEType: mime,
								Data:     data,
							},
						})
					}
				}
			case "input_audio":
				if audioObj, ok := item["input_audio"].(map[string]any); ok {
					dataStr, _ := audioObj["data"].(string)
					format, _ := audioObj["format"].(string)
					if format == "" {
						format = "wav"
					}
					if dataBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataStr)); err == nil && len(dataBytes) > 0 {
						mime := "audio/" + format
						if format == "mp3" {
							mime = "audio/mpeg"
						}
						parts = append(parts, &genai.Part{
							InlineData: &genai.Blob{
								MIMEType: mime,
								Data:     dataBytes,
							},
						})
					}
				}
			case "file", "document":
				if fileObj, ok := item[typ].(map[string]any); ok {
					urlStr, _ := fileObj["url"].(string)
					if mime, data, ok := parseDataURI(urlStr); ok {
						parts = append(parts, &genai.Part{
							InlineData: &genai.Blob{
								MIMEType: mime,
								Data:     data,
							},
						})
					}
				}
			}
		}
	default:
		if text := contentText(content); text != "" {
			parts = append(parts, &genai.Part{Text: text})
		}
	}
	return parts
}

func parseDataURI(uri string) (string, []byte, bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", nil, false
	}
	trimmed := strings.TrimPrefix(uri, "data:")
	meta, b64Data, found := strings.Cut(trimmed, ",")
	if !found {
		return "", nil, false
	}
	if !strings.HasSuffix(meta, ";base64") {
		return "", nil, false
	}
	mime := strings.TrimSuffix(meta, ";base64")
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Data))
	if err != nil || len(decoded) == 0 {
		return "", nil, false
	}
	return mime, decoded, true
}

func convertOpenAIToolsToGenAI(rawTools []any) ([]*genai.Tool, error) {
	decls := make([]*genai.FunctionDeclaration, 0)
	for _, raw := range rawTools {
		tool, ok := raw.(map[string]any)
		if !ok || tool["type"] != "function" {
			continue
		}
		fn, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		decl := &genai.FunctionDeclaration{
			Name:        name,
			Description: desc,
		}
		if params, ok := fn["parameters"]; ok && params != nil {
			decl.ParametersJsonSchema = params
		}
		decls = append(decls, decl)
	}
	if len(decls) == 0 {
		return nil, nil
	}
	return []*genai.Tool{{FunctionDeclarations: decls}}, nil
}

func convertOpenAIToolChoiceToGenAI(value any) *genai.ToolConfig {
	switch tc := value.(type) {
	case string:
		switch tc {
		case "none":
			return &genai.ToolConfig{
				FunctionCallingConfig: &genai.FunctionCallingConfig{
					Mode: genai.FunctionCallingConfigModeNone,
				},
			}
		case "auto":
			return &genai.ToolConfig{
				FunctionCallingConfig: &genai.FunctionCallingConfig{
					Mode: genai.FunctionCallingConfigModeAuto,
				},
			}
		case "required":
			return &genai.ToolConfig{
				FunctionCallingConfig: &genai.FunctionCallingConfig{
					Mode: genai.FunctionCallingConfigModeAny,
				},
			}
		}
	case map[string]any:
		if fn, ok := tc["function"].(map[string]any); ok {
			if name, ok := fn["name"].(string); ok && name != "" {
				return &genai.ToolConfig{
					FunctionCallingConfig: &genai.FunctionCallingConfig{
						Mode:                 genai.FunctionCallingConfigModeAny,
						AllowedFunctionNames: []string{name},
					},
				}
			}
		}
	}
	return nil
}

func convertGenAIResponse(resp *genai.GenerateContentResponse, fallbackModel string) ([]byte, error) {
	id := convertResponseID(resp.ResponseID)
	created := time.Now().Unix()
	if !resp.CreateTime.IsZero() {
		created = resp.CreateTime.Unix()
	}

	model := fallbackModel
	if resp.ModelVersion != "" {
		model = resp.ModelVersion
	}

	var textBuilder strings.Builder
	var thoughtBuilder strings.Builder
	toolCalls := make([]any, 0)
	finishReason := "stop"

	if len(resp.Candidates) > 0 {
		candidate := resp.Candidates[0]
		if candidate.Content != nil {
			for _, part := range candidate.Content.Parts {
				if part.Thought {
					thoughtBuilder.WriteString(part.Text)
				} else if part.Text != "" {
					textBuilder.WriteString(part.Text)
				}
				if part.FunctionCall != nil {
					callID := part.FunctionCall.ID
					if callID == "" {
						callID = fmt.Sprintf("call_%d_%s", time.Now().UnixNano(), part.FunctionCall.Name)
					}
					argsBytes, _ := json.Marshal(part.FunctionCall.Args)
					toolCalls = append(toolCalls, map[string]any{
						"id":   callID,
						"type": "function",
						"function": map[string]any{
							"name":      part.FunctionCall.Name,
							"arguments": string(argsBytes),
						},
					})
				}
			}
		}
		finishReason = genaiFinishReason(candidate, len(toolCalls) > 0)
	}

	message := map[string]any{"role": "assistant"}
	if textBuilder.Len() > 0 {
		message["content"] = textBuilder.String()
	} else if len(toolCalls) > 0 {
		message["content"] = nil
	} else {
		message["content"] = ""
	}
	if thoughtBuilder.Len() > 0 {
		message["reasoning_content"] = thoughtBuilder.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}

	result := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": created,
		"model":   model,
		"choices": []any{choice},
	}

	if resp.UsageMetadata != nil {
		result["usage"] = convertGenAIUsage(resp.UsageMetadata)
	}

	return json.Marshal(result)
}

func genaiFinishReason(candidate *genai.Candidate, hasToolCalls bool) string {
	if hasToolCalls {
		return "tool_calls"
	}
	if candidate == nil {
		return "stop"
	}
	switch candidate.FinishReason {
	case genai.FinishReasonMaxTokens:
		return "length"
	case genai.FinishReasonSafety, genai.FinishReasonBlocklist, genai.FinishReasonProhibitedContent, genai.FinishReasonSPII:
		return "content_filter"
	case genai.FinishReasonStop:
		return "stop"
	default:
		return "stop"
	}
}

func convertGenAIUsage(usage *genai.GenerateContentResponseUsageMetadata) map[string]any {
	if usage == nil {
		return nil
	}
	res := map[string]any{
		"prompt_tokens":     usage.PromptTokenCount,
		"completion_tokens": usage.CandidatesTokenCount,
		"total_tokens":      usage.TotalTokenCount,
	}
	if usage.CachedContentTokenCount > 0 {
		res["prompt_tokens_details"] = map[string]any{
			"cached_tokens": usage.CachedContentTokenCount,
		}
	}
	return res
}

type firstStreamResult struct {
	firstResp *genai.GenerateContentResponse
	firstErr  error
}

func streamGenAIResponse(ctx context.Context, client *genai.Client, model string, contents []*genai.Content, config *genai.GenerateContentConfig, meta *requestMeta, apiKey string) (*http.Response, error) {
	iterator := client.Models.GenerateContentStream(ctx, model, contents, config)

	pr, pw := io.Pipe()
	firstCh := make(chan firstStreamResult, 1)

	go func() {
		streamID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		created := time.Now().Unix()
		roleSent := false
		isFirst := true
		toolIndex := 0
		var latestUsage *genai.GenerateContentResponseUsageMetadata
		var lastFinishReason string

		for resp, err := range iterator {
			if isFirst {
				isFirst = false
				firstCh <- firstStreamResult{firstResp: resp, firstErr: err}
				if err != nil {
					_ = pw.CloseWithError(err)
					return
				}
			} else if err != nil {
				_ = pw.CloseWithError(err)
				return
			}

			if resp.UsageMetadata != nil {
				latestUsage = resp.UsageMetadata
			}

			if !roleSent {
				roleChunk := map[string]any{
					"id":      streamID,
					"object":  "chat.completion.chunk",
					"created": created,
					"model":   meta.Model,
					"choices": []any{
						map[string]any{
							"index":         0,
							"delta":         map[string]any{"role": "assistant"},
							"finish_reason": nil,
						},
					},
				}
				_ = writeStreamSSE(pw, roleChunk)
				roleSent = true
			}

			if len(resp.Candidates) > 0 {
				candidate := resp.Candidates[0]
				if candidate.Content != nil {
					for _, part := range candidate.Content.Parts {
						if part.Thought && part.Text != "" {
							thoughtChunk := map[string]any{
								"id":      streamID,
								"object":  "chat.completion.chunk",
								"created": created,
								"model":   meta.Model,
								"choices": []any{
									map[string]any{
										"index":         0,
										"delta":         map[string]any{"reasoning_content": part.Text},
										"finish_reason": nil,
									},
								},
							}
							_ = writeStreamSSE(pw, thoughtChunk)
						} else if part.Text != "" {
							textChunk := map[string]any{
								"id":      streamID,
								"object":  "chat.completion.chunk",
								"created": created,
								"model":   meta.Model,
								"choices": []any{
									map[string]any{
										"index":         0,
										"delta":         map[string]any{"content": part.Text},
										"finish_reason": nil,
									},
								},
							}
							_ = writeStreamSSE(pw, textChunk)
						}
						if part.FunctionCall != nil {
							callID := part.FunctionCall.ID
							if callID == "" {
								callID = fmt.Sprintf("call_%d_%s", time.Now().UnixNano(), part.FunctionCall.Name)
							}
							argsBytes, _ := json.Marshal(part.FunctionCall.Args)
							toolChunk := map[string]any{
								"id":      streamID,
								"object":  "chat.completion.chunk",
								"created": created,
								"model":   meta.Model,
								"choices": []any{
									map[string]any{
										"index": 0,
										"delta": map[string]any{
											"tool_calls": []any{
												map[string]any{
													"index": toolIndex,
													"id":    callID,
													"type":  "function",
													"function": map[string]any{
														"name":      part.FunctionCall.Name,
														"arguments": string(argsBytes),
													},
												},
											},
										},
										"finish_reason": nil,
									},
								},
							}
							toolIndex++
							_ = writeStreamSSE(pw, toolChunk)
						}
					}
				}
				if candidate.FinishReason != "" && candidate.FinishReason != genai.FinishReasonUnspecified {
					lastFinishReason = genaiFinishReason(candidate, toolIndex > 0)
				}
			}
		}

		if isFirst {
			firstCh <- firstStreamResult{}
		}

		if lastFinishReason == "" {
			if toolIndex > 0 {
				lastFinishReason = "tool_calls"
			} else {
				lastFinishReason = "stop"
			}
		}

		finishChunk := map[string]any{
			"id":      streamID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   meta.Model,
			"choices": []any{
				map[string]any{
					"index":         0,
					"delta":         map[string]any{},
					"finish_reason": lastFinishReason,
				},
			},
		}
		_ = writeStreamSSE(pw, finishChunk)

		if meta.IncludeUsage && latestUsage != nil {
			usageChunk := map[string]any{
				"id":      streamID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   meta.Model,
				"choices": []any{},
				"usage":   convertGenAIUsage(latestUsage),
			}
			_ = writeStreamSSE(pw, usageChunk)
		}

		_, _ = io.WriteString(pw, "data: [DONE]\n\n")
		_ = pw.Close()
	}()

	select {
	case <-ctx.Done():
		_ = pr.Close()
		return nil, ctx.Err()
	case res := <-firstCh:
		if res.firstErr != nil {
			_ = pr.Close()
			return formatGenAIErrorResponse(0, res.firstErr, apiKey), nil
		}
	}

	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       pr,
	}, nil
}

func writeStreamSSE(w io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", encoded)
	return err
}

func toFloat32(val any) (float32, bool) {
	switch v := val.(type) {
	case float64:
		return float32(v), true
	case float32:
		return v, true
	case int:
		return float32(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return float32(f), true
		}
	}
	return 0, false
}

func toInt32(val any) (int32, bool) {
	switch v := val.(type) {
	case float64:
		return int32(v), true
	case int:
		return int32(v), true
	case int32:
		return v, true
	case int64:
		return int32(v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int32(i), true
		}
	}
	return 0, false
}
