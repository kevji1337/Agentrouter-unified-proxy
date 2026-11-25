package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (server *proxyServer) prepareAnthropicInbound(body []byte, protocol string) (string, []byte, *requestMeta, error) {
	p := effectiveProtocol(protocol)
	if p == protocolAnthropic {
		in, err := decodeObject(body)
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: %v", errInvalidUpstreamRequest, err)
		}
		model, _ := in["model"].(string)
		if strings.TrimSpace(model) == "" {
			return "", nil, nil, fmt.Errorf("%w: model must be a non-empty string", errInvalidUpstreamRequest)
		}
		if _, ok := in["messages"].([]any); !ok {
			return "", nil, nil, fmt.Errorf("%w: messages must be an array", errInvalidUpstreamRequest)
		}
		return "/v1/messages", body, nil, nil
	}

	chatBody, meta, err := convertAnthropicToChatRequest(body)
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: %v", errInvalidUpstreamRequest, err)
	}
	if p == protocolChatCompletions || p == protocolGenAI {
		meta.UpstreamFormat = "chat"
		return "/v1/chat/completions", chatBody, &meta, nil
	}
	if p == protocolResponses {
		responsesBody, respMeta, err := convertChatRequest(chatBody)
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: %v", errInvalidUpstreamRequest, err)
		}
		if server.cfg.ForceSequentialTools {
			responsesBody, err = enforceSequentialTools(responsesBody)
			if err != nil {
				return "", nil, nil, fmt.Errorf("%w: %v", errInvalidUpstreamRequest, err)
			}
			respMeta.ForceSequentialTools = true
		}
		respMeta.SourceFormat = "anthropic"
		respMeta.UpstreamFormat = "responses"
		return "/v1/responses", responsesBody, &respMeta, nil
	}
	return "", nil, nil, errNoCompatibleUpstream
}

func convertAnthropicToChatRequest(raw []byte) ([]byte, requestMeta, error) {
	in, err := decodeObject(raw)
	if err != nil {
		return nil, requestMeta{}, fmt.Errorf("invalid JSON: %w", err)
	}
	model, _ := in["model"].(string)
	if strings.TrimSpace(model) == "" {
		return nil, requestMeta{}, errors.New("model must be a non-empty string")
	}
	rawMessages, ok := in["messages"].([]any)
	if !ok {
		return nil, requestMeta{}, errors.New("messages must be an array")
	}
	stream, _ := in["stream"].(bool)
	meta := requestMeta{
		Model:        model,
		Stream:       stream,
		IncludeUsage: true,
		SourceFormat: "anthropic",
	}

	out := map[string]any{
		"model":  model,
		"stream": stream,
	}
	if stream {
		out["stream_options"] = map[string]any{"include_usage": true}
	}
	if v, ok := in["max_tokens"]; ok {
		out["max_completion_tokens"] = v
	}
	for _, key := range []string{"temperature", "top_p"} {
		if v, ok := in[key]; ok {
			out[key] = v
		}
	}
	if stopSeq, ok := in["stop_sequences"]; ok {
		out["stop"] = stopSeq
	}
	if md, ok := in["metadata"].(map[string]any); ok {
		if uid, ok := md["user_id"].(string); ok && uid != "" {
			out["user"] = uid
		}
	}
	if thinking, ok := in["thinking"].(map[string]any); ok {
		tType, _ := thinking["type"].(string)
		if tType == "enabled" || tType == "adaptive" {
			budget := uint64Value(thinking["budget_tokens"])
			switch {
			case budget > 0 && budget < 4000:
				out["reasoning_effort"] = "low"
			case budget >= 16000:
				out["reasoning_effort"] = "high"
			default:
				out["reasoning_effort"] = "medium"
			}
		}
	}

	if rawTools, ok := in["tools"].([]any); ok && len(rawTools) > 0 {
		chatTools := make([]any, 0, len(rawTools))
		for _, item := range rawTools {
			tm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := tm["name"].(string)
			if strings.TrimSpace(name) == "" {
				continue
			}
			fn := map[string]any{"name": name}
			if desc, ok := tm["description"].(string); ok && desc != "" {
				fn["description"] = desc
			}
			if schema, ok := tm["input_schema"].(map[string]any); ok {
				fn["parameters"] = schema
			} else {
				fn["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			chatTools = append(chatTools, map[string]any{
				"type":     "function",
				"function": fn,
			})
		}
		if len(chatTools) > 0 {
			out["tools"] = chatTools
		}
	}

	if tc, ok := in["tool_choice"].(map[string]any); ok {
		tcType, _ := tc["type"].(string)
		switch tcType {
		case "auto":
			out["tool_choice"] = "auto"
		case "any":
			out["tool_choice"] = "required"
		case "none":
			out["tool_choice"] = "none"
		case "tool":
			if name, _ := tc["name"].(string); name != "" {
				out["tool_choice"] = map[string]any{
					"type":     "function",
					"function": map[string]any{"name": name},
				}
			}
		}
		if disableParallel, ok := tc["disable_parallel_tool_use"].(bool); ok && disableParallel {
			out["parallel_tool_calls"] = false
		}
	}

	chatMessages := make([]any, 0, len(rawMessages)+1)
	if sysText := extractAnthropicSystemText(in["system"]); sysText != "" {
		chatMessages = append(chatMessages, map[string]any{
			"role":    "system",
			"content": sysText,
		})
	}

	for _, rawMsg := range rawMessages {
		msgMap, ok := rawMsg.(map[string]any)
		if !ok {
			return nil, requestMeta{}, errors.New("each message must be an object")
		}
		role, _ := msgMap["role"].(string)
		content := msgMap["content"]
		switch role {
		case "user":
			convertedMsgs, err := convertAnthropicUserMessage(content)
			if err != nil {
				return nil, requestMeta{}, err
			}
			chatMessages = append(chatMessages, convertedMsgs...)
		case "assistant":
			convertedMsg, err := convertAnthropicAssistantMessage(content)
			if err != nil {
				return nil, requestMeta{}, err
			}
			chatMessages = append(chatMessages, convertedMsg)
		default:
			return nil, requestMeta{}, fmt.Errorf("unsupported Anthropic message role %q", role)
		}
	}
	out["messages"] = chatMessages
	encoded, err := json.Marshal(out)
	return encoded, meta, err
}

func extractAnthropicSystemText(sys any) string {
	switch val := sys.(type) {
	case string:
		return val
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			if block, ok := item.(map[string]any); ok {
				if text, ok := block["text"].(string); ok && text != "" {
					parts = append(parts, text)
				}
			}
		}
		return strings.Join(parts, "\n\n")
	default:
		return ""
	}
}

func convertAnthropicUserMessage(content any) ([]any, error) {
	if text, ok := content.(string); ok {
		return []any{map[string]any{"role": "user", "content": text}}, nil
	}
	blocks, ok := content.([]any)
	if !ok {
		return nil, errors.New("message content must be a string or array of blocks")
	}
	var out []any
	var userParts []any
	allPlainText := true
	var textParts []string

	for _, rawBlock := range blocks {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			continue
		}
		bType, _ := block["type"].(string)
		switch bType {
		case "tool_result":
			callID, _ := block["tool_use_id"].(string)
			resultText := extractToolResultText(block["content"])
			if isErr, _ := block["is_error"].(bool); isErr && resultText != "" && !strings.HasPrefix(resultText, "Error:") {
				resultText = "Error: " + resultText
			}
			out = append(out, map[string]any{
				"role":         "tool",
				"tool_call_id": callID,
				"content":      resultText,
			})
		case "text":
			txt, _ := block["text"].(string)
			textParts = append(textParts, txt)
			userParts = append(userParts, map[string]any{"type": "text", "text": txt})
		case "image":
			allPlainText = false
			if src, ok := block["source"].(map[string]any); ok {
				srcType, _ := src["type"].(string)
				switch srcType {
				case "base64":
					mediaType, _ := src["media_type"].(string)
					if mediaType == "" {
						mediaType = "image/png"
					}
					data, _ := src["data"].(string)
					userParts = append(userParts, map[string]any{
						"type":      "image_url",
						"image_url": map[string]any{"url": "data:" + mediaType + ";base64," + data},
					})
				case "url":
					if u, _ := src["url"].(string); u != "" {
						userParts = append(userParts, map[string]any{
							"type":      "image_url",
							"image_url": map[string]any{"url": u},
						})
					}
				}
			}
		case "document":
			allPlainText = false
			if src, ok := block["source"].(map[string]any); ok {
				srcType, _ := src["type"].(string)
				if srcType == "base64" {
					mediaType, _ := src["media_type"].(string)
					if mediaType == "" {
						mediaType = "application/pdf"
					}
					data, _ := src["data"].(string)
					userParts = append(userParts, map[string]any{
						"type": "file",
						"file": map[string]any{"file_data": "data:" + mediaType + ";base64," + data},
					})
				}
			}
		}
	}

	if len(userParts) > 0 {
		if allPlainText {
			out = append(out, map[string]any{"role": "user", "content": strings.Join(textParts, "\n")})
		} else {
			out = append(out, map[string]any{"role": "user", "content": userParts})
		}
	} else if len(out) == 0 {
		out = append(out, map[string]any{"role": "user", "content": ""})
	}
	return out, nil
}

func extractToolResultText(content any) string {
	switch val := content.(type) {
	case string:
		return val
	case []any:
		var parts []string
		for _, item := range val {
			if m, ok := item.(map[string]any); ok {
				if m["type"] == "text" {
					if t, ok := m["text"].(string); ok {
						parts = append(parts, t)
						continue
					}
				}
				if raw, err := json.Marshal(m); err == nil {
					parts = append(parts, string(raw))
				}
			}
		}
		return strings.Join(parts, "\n")
	case nil:
		return ""
	default:
		raw, _ := json.Marshal(val)
		return string(raw)
	}
}

func convertAnthropicAssistantMessage(content any) (map[string]any, error) {
	if text, ok := content.(string); ok {
		return map[string]any{"role": "assistant", "content": text}, nil
	}
	blocks, ok := content.([]any)
	if !ok {
		return nil, errors.New("assistant content must be a string or array of blocks")
	}
	var textParts []string
	var thinkingParts []string
	var toolCalls []any

	for idx, rawBlock := range blocks {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			continue
		}
		bType, _ := block["type"].(string)
		switch bType {
		case "text":
			if t, ok := block["text"].(string); ok {
				textParts = append(textParts, t)
			}
		case "thinking":
			if t, ok := block["thinking"].(string); ok && t != "" {
				thinkingParts = append(thinkingParts, t)
			}
		case "tool_use":
			id, _ := block["id"].(string)
			if id == "" {
				id = fmt.Sprintf("toolu_%d", idx)
			}
			name, _ := block["name"].(string)
			argsJSON := "{}"
			if inputVal, hasInput := block["input"]; hasInput && inputVal != nil {
				if rawArgs, err := json.Marshal(inputVal); err == nil {
					argsJSON = string(rawArgs)
				}
			}
			toolCalls = append(toolCalls, map[string]any{
				"id":   id,
				"type": "function",
				"function": map[string]any{
					"name":      name,
					"arguments": argsJSON,
				},
			})
		}
	}

	msg := map[string]any{"role": "assistant"}
	if len(textParts) > 0 || len(toolCalls) == 0 {
		msg["content"] = strings.Join(textParts, "")
	} else {
		msg["content"] = nil
	}
	if len(thinkingParts) > 0 {
		msg["reasoning_content"] = strings.Join(thinkingParts, "\n")
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
	}
	return msg, nil
}

func convertChatToAnthropicRequest(raw []byte) ([]byte, requestMeta, error) {
	in, err := decodeObject(raw)
	if err != nil {
		return nil, requestMeta{}, fmt.Errorf("invalid JSON: %w", err)
	}
	model, _ := in["model"].(string)
	if strings.TrimSpace(model) == "" {
		return nil, requestMeta{}, errors.New("model must be a non-empty string")
	}
	rawMessages, ok := in["messages"].([]any)
	if !ok {
		return nil, requestMeta{}, errors.New("messages must be an array")
	}
	stream, _ := in["stream"].(bool)
	meta := requestMeta{
		Model:          model,
		Stream:         stream,
		IncludeUsage:   true,
		UpstreamFormat: "anthropic",
	}
	if opts, ok := in["stream_options"].(map[string]any); ok {
		if include, ok := opts["include_usage"].(bool); ok {
			meta.IncludeUsage = include
		}
	}

	maxTokens := uint64Value(in["max_completion_tokens"])
	if maxTokens == 0 {
		maxTokens = uint64Value(in["max_tokens"])
	}
	if maxTokens == 0 {
		maxTokens = 8192
	}

	out := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"stream":     stream,
	}
	for _, key := range []string{"temperature", "top_p"} {
		if v, ok := in[key]; ok {
			out[key] = v
		}
	}
	if stopVal, ok := in["stop"]; ok && stopVal != nil {
		switch s := stopVal.(type) {
		case string:
			if s != "" {
				out["stop_sequences"] = []string{s}
			}
		case []any:
			if len(s) > 0 {
				out["stop_sequences"] = s
			}
		}
	}
	if effort, _ := in["reasoning_effort"].(string); effort != "" && effort != "none" {
		var budget uint64 = 4096
		switch effort {
		case "low", "minimal":
			budget = 2048
		case "medium":
			budget = 8192
		case "high":
			budget = 16384
		}
		if maxTokens <= budget {
			maxTokens = budget + 4096
			out["max_tokens"] = maxTokens
		}
		out["thinking"] = map[string]any{
			"type":          "enabled",
			"budget_tokens": budget,
		}
	}

	if rawTools, ok := in["tools"].([]any); ok && len(rawTools) > 0 {
		anthTools := make([]any, 0, len(rawTools))
		for _, item := range rawTools {
			tm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := tm["function"].(map[string]any)
			if fn == nil {
				fn = tm
			}
			name, _ := fn["name"].(string)
			if name == "" {
				continue
			}
			t := map[string]any{"name": name}
			if desc, ok := fn["description"].(string); ok && desc != "" {
				t["description"] = desc
			}
			if params, ok := fn["parameters"].(map[string]any); ok {
				t["input_schema"] = params
			} else {
				t["input_schema"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			anthTools = append(anthTools, t)
		}
		if len(anthTools) > 0 {
			out["tools"] = anthTools
		}
	}

	if tc, ok := in["tool_choice"]; ok && tc != nil {
		switch choice := tc.(type) {
		case string:
			switch choice {
			case "auto":
				out["tool_choice"] = map[string]any{"type": "auto"}
			case "required":
				out["tool_choice"] = map[string]any{"type": "any"}
			case "none":
				out["tool_choice"] = map[string]any{"type": "none"}
			}
		case map[string]any:
			if fn, ok := choice["function"].(map[string]any); ok {
				if name, _ := fn["name"].(string); name != "" {
					out["tool_choice"] = map[string]any{"type": "tool", "name": name}
				}
			}
		}
	}

	var sysParts []string
	var anthMessages []map[string]any
	appendRoleBlocks := func(role string, blocks []any) {
		if len(blocks) == 0 {
			return
		}
		if len(anthMessages) > 0 && anthMessages[len(anthMessages)-1]["role"] == role {
			existing, _ := anthMessages[len(anthMessages)-1]["content"].([]any)
			anthMessages[len(anthMessages)-1]["content"] = append(existing, blocks...)
			return
		}
		anthMessages = append(anthMessages, map[string]any{
			"role":    role,
			"content": blocks,
		})
	}

	for _, rawMsg := range rawMessages {
		m, ok := rawMsg.(map[string]any)
		if !ok {
			return nil, requestMeta{}, errors.New("each message must be an object")
		}
		role, _ := m["role"].(string)
		switch role {
		case "system", "developer":
			if txt := extractPlainMessageContent(m["content"]); txt != "" {
				sysParts = append(sysParts, txt)
			}
		case "user":
			blocks := convertChatUserContentToAnthropicBlocks(m["content"])
			appendRoleBlocks("user", blocks)
		case "assistant":
			var blocks []any
			if txt := extractPlainMessageContent(m["content"]); txt != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": txt})
			}
			if calls, ok := m["tool_calls"].([]any); ok {
				for idx, rawCall := range calls {
					cm, ok := rawCall.(map[string]any)
					if !ok {
						continue
					}
					fn, _ := cm["function"].(map[string]any)
					id, _ := cm["id"].(string)
					if id == "" {
						id = fmt.Sprintf("toolu_%d", idx)
					}
					name, _ := fn["name"].(string)
					argsStr, _ := fn["arguments"].(string)
					inputObj := map[string]any{}
					if strings.TrimSpace(argsStr) != "" {
						_ = json.Unmarshal([]byte(argsStr), &inputObj)
					}
					blocks = append(blocks, map[string]any{
						"type":  "tool_use",
						"id":    id,
						"name":  name,
						"input": inputObj,
					})
				}
			}
			if len(blocks) == 0 {
				blocks = []any{map[string]any{"type": "text", "text": ""}}
			}
			appendRoleBlocks("assistant", blocks)
		case "tool":
			callID, _ := m["tool_call_id"].(string)
			txt := extractPlainMessageContent(m["content"])
			appendRoleBlocks("user", []any{
				map[string]any{
					"type":        "tool_result",
					"tool_use_id": callID,
					"content":     txt,
				},
			})
		}
	}

	if len(sysParts) > 0 {
		out["system"] = strings.Join(sysParts, "\n\n")
	}
	if len(anthMessages) == 0 {
		return nil, requestMeta{}, errors.New("at least one non-system message is required")
	}
	out["messages"] = anthMessages
	encoded, err := json.Marshal(out)
	return encoded, meta, err
}

func extractPlainMessageContent(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func convertChatUserContentToAnthropicBlocks(content any) []any {
	switch v := content.(type) {
	case string:
		return []any{map[string]any{"type": "text", "text": v}}
	case []any:
		var blocks []any
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			pType, _ := m["type"].(string)
			switch pType {
			case "text", "input_text":
				txt, _ := m["text"].(string)
				blocks = append(blocks, map[string]any{"type": "text", "text": txt})
			case "image_url":
				if img, ok := m["image_url"].(map[string]any); ok {
					u, _ := img["url"].(string)
					if strings.HasPrefix(u, "data:") {
						metaPart, b64, ok := strings.Cut(strings.TrimPrefix(u, "data:"), ";base64,")
						if ok {
							if metaPart == "" {
								metaPart = "image/png"
							}
							blocks = append(blocks, map[string]any{
								"type": "image",
								"source": map[string]any{
									"type":       "base64",
									"media_type": metaPart,
									"data":       b64,
								},
							})
						}
					} else if u != "" {
						blocks = append(blocks, map[string]any{
							"type": "image",
							"source": map[string]any{
								"type": "url",
								"url":  u,
							},
						})
					}
				}
			}
		}
		if len(blocks) == 0 {
			blocks = []any{map[string]any{"type": "text", "text": ""}}
		}
		return blocks
	default:
		return []any{map[string]any{"type": "text", "text": ""}}
	}
}

func mapChatFinishToAnthropicStop(finish string) string {
	switch finish {
	case "tool_calls", "function_call":
		return "tool_use"
	case "length":
		return "max_tokens"
	default:
		return "end_turn"
	}
}

func mapAnthropicStopToChatFinish(stop string) string {
	switch stop {
	case "tool_use":
		return "tool_calls"
	case "max_tokens":
		return "length"
	default:
		return "stop"
	}
}

func convertChatResponseToAnthropic(chatRaw []byte, fallbackModel string) ([]byte, error) {
	chat, err := decodeObject(chatRaw)
	if err != nil {
		return nil, err
	}
	id, _ := chat["id"].(string)
	if id == "" {
		id = fmt.Sprintf("msg_%d", time.Now().UnixNano())
	} else if strings.HasPrefix(id, "chatcmpl-") {
		id = "msg_" + strings.TrimPrefix(id, "chatcmpl-")
	}
	model, _ := chat["model"].(string)
	if model == "" {
		model = fallbackModel
	}

	contentBlocks := make([]any, 0, 2)
	stopReason := "end_turn"
	if choices, ok := chat["choices"].([]any); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]any); ok {
			if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
				stopReason = mapChatFinishToAnthropicStop(fr)
			}
			if msg, ok := choice["message"].(map[string]any); ok {
				if reasoning, ok := msg["reasoning_content"].(string); ok && reasoning != "" {
					contentBlocks = append(contentBlocks, map[string]any{
						"type":     "thinking",
						"thinking": reasoning,
					})
				}
				if text, ok := msg["content"].(string); ok && text != "" {
					contentBlocks = append(contentBlocks, map[string]any{
						"type": "text",
						"text": text,
					})
				}
				if calls, ok := msg["tool_calls"].([]any); ok && len(calls) > 0 {
					stopReason = "tool_use"
					for idx, rawCall := range calls {
						cm, ok := rawCall.(map[string]any)
						if !ok {
							continue
						}
						fn, _ := cm["function"].(map[string]any)
						callID, _ := cm["id"].(string)
						if callID == "" {
							callID = fmt.Sprintf("toolu_%d", idx)
						}
						name, _ := fn["name"].(string)
						argsStr, _ := fn["arguments"].(string)
						inputObj := map[string]any{}
						if strings.TrimSpace(argsStr) != "" {
							_ = json.Unmarshal([]byte(argsStr), &inputObj)
						}
						contentBlocks = append(contentBlocks, map[string]any{
							"type":  "tool_use",
							"id":    callID,
							"name":  name,
							"input": inputObj,
						})
					}
				}
			}
		}
	}
	if len(contentBlocks) == 0 {
		contentBlocks = append(contentBlocks, map[string]any{"type": "text", "text": ""})
	}

	inTok, outTok := parseUsage(chatRaw)
	resp := map[string]any{
		"id":            id,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"content":       contentBlocks,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  inTok,
			"output_tokens": outTok,
		},
	}
	return json.Marshal(resp)
}

func convertAnthropicResponseToChat(anthRaw []byte, fallbackModel string) ([]byte, error) {
	anth, err := decodeObject(anthRaw)
	if err != nil {
		return nil, err
	}
	id, _ := anth["id"].(string)
	if id == "" {
		id = fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	}
	model, _ := anth["model"].(string)
	if model == "" {
		model = fallbackModel
	}
	stopReason, _ := anth["stop_reason"].(string)
	finishReason := mapAnthropicStopToChatFinish(stopReason)

	var textParts []string
	var thinkingParts []string
	var toolCalls []any

	if blocks, ok := anth["content"].([]any); ok {
		for idx, rawBlock := range blocks {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			bType, _ := block["type"].(string)
			switch bType {
			case "thinking":
				if t, ok := block["thinking"].(string); ok && t != "" {
					thinkingParts = append(thinkingParts, t)
				}
			case "text":
				if t, ok := block["text"].(string); ok {
					textParts = append(textParts, t)
				}
			case "tool_use":
				callID, _ := block["id"].(string)
				if callID == "" {
					callID = fmt.Sprintf("call_%d", idx)
				}
				name, _ := block["name"].(string)
				argsBytes, _ := json.Marshal(block["input"])
				if len(argsBytes) == 0 || string(argsBytes) == "null" {
					argsBytes = []byte("{}")
				}
				toolCalls = append(toolCalls, map[string]any{
					"id":   callID,
					"type": "function",
					"function": map[string]any{
						"name":      name,
						"arguments": string(argsBytes),
					},
				})
			}
		}
	}
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}

	msg := map[string]any{"role": "assistant"}
	if len(textParts) > 0 || len(toolCalls) == 0 {
		msg["content"] = strings.Join(textParts, "")
	} else {
		msg["content"] = nil
	}
	if len(thinkingParts) > 0 {
		msg["reasoning_content"] = strings.Join(thinkingParts, "\n")
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
	}

	inTok, outTok := parseUsage(anthRaw)
	out := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       msg,
				"finish_reason": finishReason,
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     inTok,
			"completion_tokens": outTok,
			"total_tokens":      inTok + outTok,
		},
	}
	return json.Marshal(out)
}

func writeAnthropicSSEEvent(w io.Writer, eventName string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, raw); err != nil {
		return err
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		flush(rw)
	}
	return nil
}

func convertChatSSEToAnthropicSSE(w http.ResponseWriter, body io.Reader, fallbackModel string) error {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)

	msgID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	model := fallbackModel
	started := false
	activeKind := "" // "", "thinking", "text", "tool"
	activeBlockIdx := -1
	nextBlockIdx := 0
	toolBlockByChatIdx := make(map[int]int)
	stopReason := "end_turn"
	var inputTokens, outputTokens uint64

	ensureMessageStart := func() error {
		if started {
			return nil
		}
		started = true
		return writeAnthropicSSEEvent(w, "message_start", map[string]any{
			"type": "message_start",
			"message": map[string]any{
				"id":            msgID,
				"type":          "message",
				"role":          "assistant",
				"model":         model,
				"content":       []any{},
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]any{
					"input_tokens":  inputTokens,
					"output_tokens": 0,
				},
			},
		})
	}

	closeActiveBlock := func() error {
		if activeBlockIdx < 0 {
			return nil
		}
		idx := activeBlockIdx
		activeBlockIdx = -1
		activeKind = ""
		return writeAnthropicSSEEvent(w, "content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": idx,
		})
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			break
		}
		chunk, err := decodeObject([]byte(data))
		if err != nil {
			continue
		}
		if cid, ok := chunk["id"].(string); ok && cid != "" && !started {
			msgID = "msg_" + strings.TrimPrefix(cid, "chatcmpl-")
		}
		if cm, ok := chunk["model"].(string); ok && cm != "" {
			model = cm
		}
		if inTok, outTok, ok := usageFromJSON([]byte(data)); ok {
			if inTok > 0 {
				inputTokens = inTok
			}
			if outTok > 0 {
				outputTokens = outTok
			}
		}

		choices, _ := chunk["choices"].([]any)
		if len(choices) == 0 {
			continue
		}
		choice, _ := choices[0].(map[string]any)
		if choice == nil {
			continue
		}
		if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
			stopReason = mapChatFinishToAnthropicStop(fr)
		}
		delta, _ := choice["delta"].(map[string]any)
		if delta == nil {
			continue
		}

		if reasoning, ok := delta["reasoning_content"].(string); ok && reasoning != "" {
			if err := ensureMessageStart(); err != nil {
				return err
			}
			if activeKind != "thinking" {
				if err := closeActiveBlock(); err != nil {
					return err
				}
				activeBlockIdx = nextBlockIdx
				nextBlockIdx++
				activeKind = "thinking"
				if err := writeAnthropicSSEEvent(w, "content_block_start", map[string]any{
					"type":          "content_block_start",
					"index":         activeBlockIdx,
					"content_block": map[string]any{"type": "thinking", "thinking": ""},
				}); err != nil {
					return err
				}
			}
			if err := writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": activeBlockIdx,
				"delta": map[string]any{"type": "thinking_delta", "thinking": reasoning},
			}); err != nil {
				return err
			}
		}

		if text, ok := delta["content"].(string); ok && text != "" {
			if err := ensureMessageStart(); err != nil {
				return err
			}
			if activeKind != "text" {
				if err := closeActiveBlock(); err != nil {
					return err
				}
				activeBlockIdx = nextBlockIdx
				nextBlockIdx++
				activeKind = "text"
				if err := writeAnthropicSSEEvent(w, "content_block_start", map[string]any{
					"type":          "content_block_start",
					"index":         activeBlockIdx,
					"content_block": map[string]any{"type": "text", "text": ""},
				}); err != nil {
					return err
				}
			}
			if err := writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": activeBlockIdx,
				"delta": map[string]any{"type": "text_delta", "text": text},
			}); err != nil {
				return err
			}
		}

		if calls, ok := delta["tool_calls"].([]any); ok && len(calls) > 0 {
			stopReason = "tool_use"
			if err := ensureMessageStart(); err != nil {
				return err
			}
			for pos, rawCall := range calls {
				cm, ok := rawCall.(map[string]any)
				if !ok {
					continue
				}
				chatIdx := pos
				if rawIdx, hasIdx := cm["index"]; hasIdx {
					chatIdx = int(uint64Value(rawIdx))
				}
				blockIdx, exists := toolBlockByChatIdx[chatIdx]
				fn, _ := cm["function"].(map[string]any)
				if !exists {
					if err := closeActiveBlock(); err != nil {
						return err
					}
					blockIdx = nextBlockIdx
					nextBlockIdx++
					toolBlockByChatIdx[chatIdx] = blockIdx
					activeBlockIdx = blockIdx
					activeKind = "tool"
					callID, _ := cm["id"].(string)
					if callID == "" {
						callID = fmt.Sprintf("toolu_%d", blockIdx)
					}
					name, _ := fn["name"].(string)
					if err := writeAnthropicSSEEvent(w, "content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIdx,
						"content_block": map[string]any{
							"type":  "tool_use",
							"id":    callID,
							"name":  name,
							"input": map[string]any{},
						},
					}); err != nil {
						return err
					}
				}
				if argsDelta, _ := fn["arguments"].(string); argsDelta != "" {
					if err := writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{
						"type":  "content_block_delta",
						"index": blockIdx,
						"delta": map[string]any{
							"type":         "input_json_delta",
							"partial_json": argsDelta,
						},
					}); err != nil {
						return err
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		_ = writeAnthropicSSEEvent(w, "error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "upstream stream interrupted",
			},
		})
		return err
	}

	if err := ensureMessageStart(); err != nil {
		return err
	}
	if err := closeActiveBlock(); err != nil {
		return err
	}
	if err := writeAnthropicSSEEvent(w, "message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   stopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	}); err != nil {
		return err
	}
	return writeAnthropicSSEEvent(w, "message_stop", map[string]any{"type": "message_stop"})
}

func writeSyntheticAnthropicStream(w http.ResponseWriter, anthJSON []byte) error {
	msg, err := decodeObject(anthJSON)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	inTok, outTok := parseUsage(anthJSON)
	startMsg := cloneMap(msg)
	startMsg["content"] = []any{}
	startMsg["stop_reason"] = nil
	startMsg["usage"] = map[string]any{"input_tokens": inTok, "output_tokens": 0}
	if err := writeAnthropicSSEEvent(w, "message_start", map[string]any{"type": "message_start", "message": startMsg}); err != nil {
		return err
	}

	if blocks, ok := msg["content"].([]any); ok {
		for idx, rawBlock := range blocks {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			bType, _ := block["type"].(string)
			switch bType {
			case "thinking":
				txt, _ := block["thinking"].(string)
				_ = writeAnthropicSSEEvent(w, "content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "thinking", "thinking": ""}})
				if txt != "" {
					_ = writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "thinking_delta", "thinking": txt}})
				}
				_ = writeAnthropicSSEEvent(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": idx})
			case "text":
				txt, _ := block["text"].(string)
				_ = writeAnthropicSSEEvent(w, "content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "text", "text": ""}})
				if txt != "" {
					_ = writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": txt}})
				}
				_ = writeAnthropicSSEEvent(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": idx})
			case "tool_use":
				rawInput, _ := json.Marshal(block["input"])
				_ = writeAnthropicSSEEvent(w, "content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "tool_use", "id": block["id"], "name": block["name"], "input": map[string]any{}}})
				_ = writeAnthropicSSEEvent(w, "content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(rawInput)}})
				_ = writeAnthropicSSEEvent(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": idx})
			}
		}
	}

	stopReason, _ := msg["stop_reason"].(string)
	if stopReason == "" {
		stopReason = "end_turn"
	}
	_ = writeAnthropicSSEEvent(w, "message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stopReason, "stop_sequence": nil},
		"usage": map[string]any{"input_tokens": inTok, "output_tokens": outTok},
	})
	return writeAnthropicSSEEvent(w, "message_stop", map[string]any{"type": "message_stop"})
}

func convertAnthropicSSEToChatSSE(w http.ResponseWriter, body io.Reader, meta requestMeta) error {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)

	streamID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	model := meta.Model
	roleSent := false
	finishReason := "stop"
	toolIdxByBlock := make(map[int]int)
	nextToolIdx := 0
	var inputTokens, outputTokens uint64

	sendChunk := func(delta map[string]any, finish any) error {
		payload := map[string]any{
			"id":      streamID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []any{
				map[string]any{
					"index":         0,
					"delta":         delta,
					"finish_reason": finish,
				},
			},
		}
		if err := writeStreamSSE(w, payload); err != nil {
			return err
		}
		flush(w)
		return nil
	}

	ensureRole := func() error {
		if roleSent {
			return nil
		}
		roleSent = true
		return sendChunk(map[string]any{"role": "assistant"}, nil)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		ev, err := decodeObject([]byte(data))
		if err != nil {
			continue
		}
		evType, _ := ev["type"].(string)
		switch evType {
		case "error":
			return errors.New("upstream anthropic stream reported error")
		case "message_start":
			if msg, ok := ev["message"].(map[string]any); ok {
				if id, ok := msg["id"].(string); ok && id != "" {
					streamID = id
				}
				if m, ok := msg["model"].(string); ok && m != "" {
					model = m
				}
				if u, ok := msg["usage"].(map[string]any); ok {
					inputTokens = uint64Value(u["input_tokens"]) + uint64Value(u["cache_creation_input_tokens"]) + uint64Value(u["cache_read_input_tokens"])
				}
			}
			if err := ensureRole(); err != nil {
				return err
			}
		case "content_block_start":
			blockIdx := int(uint64Value(ev["index"]))
			if cb, ok := ev["content_block"].(map[string]any); ok {
				if cb["type"] == "tool_use" {
					if err := ensureRole(); err != nil {
						return err
					}
					tIdx := nextToolIdx
					nextToolIdx++
					toolIdxByBlock[blockIdx] = tIdx
					finishReason = "tool_calls"
					callID, _ := cb["id"].(string)
					name, _ := cb["name"].(string)
					if err := sendChunk(map[string]any{
						"tool_calls": []any{
							map[string]any{
								"index": tIdx,
								"id":    callID,
								"type":  "function",
								"function": map[string]any{
									"name":      name,
									"arguments": "",
								},
							},
						},
					}, nil); err != nil {
						return err
					}
				}
			}
		case "content_block_delta":
			blockIdx := int(uint64Value(ev["index"]))
			delta, _ := ev["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			dType, _ := delta["type"].(string)
			switch dType {
			case "thinking_delta":
				if txt, _ := delta["thinking"].(string); txt != "" {
					if err := ensureRole(); err != nil {
						return err
					}
					if err := sendChunk(map[string]any{"reasoning_content": txt}, nil); err != nil {
						return err
					}
				}
			case "text_delta":
				if txt, _ := delta["text"].(string); txt != "" {
					if err := ensureRole(); err != nil {
						return err
					}
					if err := sendChunk(map[string]any{"content": txt}, nil); err != nil {
						return err
					}
				}
			case "input_json_delta":
				if part, _ := delta["partial_json"].(string); part != "" {
					tIdx := toolIdxByBlock[blockIdx]
					if err := sendChunk(map[string]any{
						"tool_calls": []any{
							map[string]any{
								"index": tIdx,
								"function": map[string]any{
									"arguments": part,
								},
							},
						},
					}, nil); err != nil {
						return err
					}
				}
			}
		case "message_delta":
			if d, ok := ev["delta"].(map[string]any); ok {
				if sr, ok := d["stop_reason"].(string); ok && sr != "" {
					finishReason = mapAnthropicStopToChatFinish(sr)
				}
			}
			if u, ok := ev["usage"].(map[string]any); ok {
				if out := uint64Value(u["output_tokens"]); out > 0 {
					outputTokens = out
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	if err := ensureRole(); err != nil {
		return err
	}
	if err := sendChunk(map[string]any{}, finishReason); err != nil {
		return err
	}
	if meta.IncludeUsage && (inputTokens > 0 || outputTokens > 0) {
		usageChunk := map[string]any{
			"id":      streamID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []any{},
			"usage": map[string]any{
				"prompt_tokens":     inputTokens,
				"completion_tokens": outputTokens,
				"total_tokens":      inputTokens + outputTokens,
			},
		}
		if err := writeStreamSSE(w, usageChunk); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	flush(w)
	return nil
}

func writeAnthropicError(w http.ResponseWriter, status int, errType, message string) {
	writeJSON(w, status, map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errType,
			"message": message,
		},
	})
}

func writeAnthropicUpstreamError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errInvalidUpstreamRequest):
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
	case errors.Is(err, errNoEnabledAPIKeys), errors.Is(err, errNoCompatibleUpstream), errors.Is(err, errNetworkProxyUnavailable):
		writeAnthropicError(w, http.StatusServiceUnavailable, "api_error", err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeAnthropicError(w, http.StatusGatewayTimeout, "timeout_error", "upstream request timed out")
	default:
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "upstream request failed")
	}
}

func ensureAnthropicErrorShape(status int, raw []byte) []byte {
	var parsed map[string]any
	if json.Unmarshal(raw, &parsed) == nil {
		if parsed["type"] == "error" {
			if _, ok := parsed["error"].(map[string]any); ok {
				return raw
			}
		}
		if errObj, ok := parsed["error"].(map[string]any); ok {
			msg, _ := errObj["message"].(string)
			if msg != "" {
				errType := "api_error"
				switch status {
				case http.StatusBadRequest:
					errType = "invalid_request_error"
				case http.StatusUnauthorized:
					errType = "authentication_error"
				case http.StatusForbidden:
					errType = "permission_error"
				case http.StatusNotFound:
					errType = "not_found_error"
				case http.StatusTooManyRequests:
					errType = "rate_limit_error"
				}
				converted, _ := json.Marshal(map[string]any{
					"type":  "error",
					"error": map[string]any{"type": errType, "message": msg},
				})
				return converted
			}
		}
	}
	msg := http.StatusText(status)
	if msg == "" {
		msg = "upstream error"
	}
	fallback, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": map[string]any{"type": "api_error", "message": msg},
	})
	return fallback
}

func estimateAnthropicInputTokens(obj map[string]any) int {
	var totalRunes int
	countVal := func(v any) {
		raw, err := json.Marshal(v)
		if err == nil {
			totalRunes += utf8.RuneCount(raw)
		}
	}
	if sys, ok := obj["system"]; ok && sys != nil {
		countVal(sys)
	}
	if msgs, ok := obj["messages"]; ok && msgs != nil {
		countVal(msgs)
	}
	if tools, ok := obj["tools"]; ok && tools != nil {
		countVal(tools)
	}
	estimated := (totalRunes + 3) / 4
	if estimated < 1 {
		estimated = 1
	}
	return estimated
}

func (server *proxyServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAnthropicError(w, http.StatusMethodNotAllowed, "invalid_request_error", "use POST")
		return
	}
	body, err := readRequestBody(w, r, server.cfg.MaxBodyBytes)
	if err != nil {
		return
	}
	obj, err := decodeObject(body)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "invalid JSON object")
		return
	}
	model, _ := obj["model"].(string)
	if strings.TrimSpace(model) == "" {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "model must be a non-empty string")
		return
	}
	if _, ok := obj["messages"].([]any); !ok {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "messages must be an array")
		return
	}
	stream, _ := obj["stream"].(bool)

	cacheScope, authAvailable := server.resolveCacheAuthScope(r, model, "/v1/messages")
	cacheKey, cacheTTL, cacheable := "", time.Duration(0), false
	if authAvailable {
		cacheKey, cacheTTL, cacheable = server.cache.isCacheableScoped(r, body, obj, "anthropic|"+cacheScope)
	}
	if cacheable {
		if cachedBody, hit := server.cache.get(r.Context(), cacheKey); hit {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("X-Cache-Key", cacheKey[:16])
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(cachedBody)
			requestLogFromContext(r.Context()).set(map[string]any{"cached": true, "cache_hit": true, "model": model})
			logRequestEvent(r.Context(), "info", "cache_hit", map[string]any{
				"request_id": requestIDFromContext(r.Context()),
				"cache_key":  cacheKey[:16],
				"model":      model,
			})
			return
		}
	}

	resp, convertedMeta, err := server.doUpstreamWithMeta(r.Context(), r.Header, http.MethodPost, "/v1/messages", body, stream)
	if err != nil {
		writeAnthropicUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()

	if convertedMeta == nil {
		if !isEventStream(resp.Header) && cacheable && resp.StatusCode == http.StatusOK {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, server.cfg.MaxBodyBytes+1))
			if readErr == nil && int64(len(raw)) <= server.cfg.MaxBodyBytes {
				server.cache.set(r.Context(), cacheKey, raw, cacheTTL)
				copyResponseHeaders(w.Header(), resp.Header)
				w.Header().Set("X-Cache", "MISS")
				w.Header().Set("X-Cache-Key", cacheKey[:16])
				w.WriteHeader(resp.StatusCode)
				_, _ = w.Write(raw)
				return
			}
		}
		copyResponseHeaders(w.Header(), resp.Header)
		if cacheable {
			w.Header().Set("X-Cache", "MISS")
		}
		w.WriteHeader(resp.StatusCode)
		if isEventStream(resp.Header) {
			server.metrics.activeSSE.Add(1)
			defer server.metrics.activeSSE.Add(-1)
			streamCopy(w, resp.Body)
		} else {
			_, _ = io.Copy(w, resp.Body)
		}
		return
	}

	meta := *convertedMeta
	meta.RequestID = requestIDFromContext(r.Context())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		shaped := ensureAnthropicErrorShape(resp.StatusCode, raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(shaped)
		return
	}

	if meta.Stream {
		server.metrics.activeSSE.Add(1)
		defer server.metrics.activeSSE.Add(-1)
		if isEventStream(resp.Header) {
			var streamErr error
			if meta.UpstreamFormat == "responses" {
				pr, pw := io.Pipe()
				pipeRecorder := &pipeResponseWriter{header: make(http.Header), writer: pw}
				go func() {
					convErr := convertResponsesSSE(pipeRecorder, resp.Body, meta)
					_ = pw.CloseWithError(convErr)
				}()
				streamErr = convertChatSSEToAnthropicSSE(w, pr, meta.Model)
				_ = pr.Close()
			} else {
				streamErr = convertChatSSEToAnthropicSSE(w, resp.Body, meta.Model)
			}
			if streamErr != nil {
				requestLogFromContext(r.Context()).responseError("conversion_error")
				requestLogFromContext(r.Context()).set(map[string]any{"response_interrupted": true})
				logRequestEvent(r.Context(), "error", "sse_conversion_failed", map[string]any{
					"request_id": requestIDFromContext(r.Context()),
					"error_code": "conversion_error",
				})
			}
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, server.cfg.MaxBodyBytes+1))
		if readErr != nil || int64(len(raw)) > server.cfg.MaxBodyBytes {
			writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to read upstream response")
			return
		}
		chatJSON := raw
		if meta.UpstreamFormat == "responses" {
			chatJSON, err = convertResponsesResponse(raw, meta.Model)
			if err != nil {
				writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to convert upstream response")
				return
			}
		}
		anthJSON, err := convertChatResponseToAnthropic(chatJSON, meta.Model)
		if err != nil {
			writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to convert upstream response")
			return
		}
		_ = writeSyntheticAnthropicStream(w, anthJSON)
		return
	}

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, server.cfg.MaxBodyBytes+1))
	if readErr != nil || int64(len(raw)) > server.cfg.MaxBodyBytes {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to read upstream response")
		return
	}
	chatJSON := raw
	if meta.UpstreamFormat == "responses" {
		chatJSON, err = convertResponsesResponse(raw, meta.Model)
		if err != nil {
			writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to convert upstream response")
			return
		}
	}
	anthJSON, err := convertChatResponseToAnthropic(chatJSON, meta.Model)
	if err != nil {
		writeAnthropicError(w, http.StatusBadGateway, "api_error", "failed to convert upstream response")
		return
	}
	if cacheable {
		server.cache.set(r.Context(), cacheKey, anthJSON, cacheTTL)
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("X-Cache-Key", cacheKey[:16])
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(anthJSON)
}

func (server *proxyServer) handleMessagesCountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAnthropicError(w, http.StatusMethodNotAllowed, "invalid_request_error", "use POST")
		return
	}
	body, err := readRequestBody(w, r, server.cfg.MaxBodyBytes)
	if err != nil {
		return
	}
	obj, err := decodeObject(body)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "invalid JSON object")
		return
	}
	if _, ok := obj["messages"].([]any); !ok {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "messages must be an array")
		return
	}
	model, _ := obj["model"].(string)

	// Use native upstream /v1/messages/count_tokens when an Anthropic provider/key is available;
	// otherwise fall back to deterministic local estimation for OpenAI/Gemini-backed pools.
	if _, nativeAvailable := server.resolveCacheAuthScope(r, model, "/v1/messages/count_tokens"); nativeAvailable {
		resp, upErr := server.doUpstream(r.Context(), r.Header, http.MethodPost, "/v1/messages/count_tokens", body, false)
		if upErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				copyResponseHeaders(w.Header(), resp.Header)
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
				return
			}
		}
	}

	if _, anyAvailable := server.resolveCacheAuthScope(r, model, "/v1/messages"); !anyAvailable {
		writeAnthropicError(w, http.StatusServiceUnavailable, "api_error", errNoEnabledAPIKeys.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"input_tokens": estimateAnthropicInputTokens(obj),
	})
}

type pipeResponseWriter struct {
	header http.Header
	writer io.Writer
	status int
}

func (p *pipeResponseWriter) Header() http.Header         { return p.header }
func (p *pipeResponseWriter) WriteHeader(statusCode int)  { p.status = statusCode }
func (p *pipeResponseWriter) Write(b []byte) (int, error) { return p.writer.Write(b) }
func (p *pipeResponseWriter) Flush()                      {}
