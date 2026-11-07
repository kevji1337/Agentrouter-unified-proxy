package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// requestMeta contains the small amount of original Chat Completions state
// needed while converting the upstream response.
type requestMeta struct {
	Model                string
	Stream               bool
	IncludeUsage         bool
	RequestID            string
	ForceSequentialTools bool
}

func enforceSequentialTools(raw []byte) ([]byte, error) {
	request, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	tools, _ := request["tools"].([]any)
	if len(tools) == 0 {
		return raw, nil
	}
	request["parallel_tool_calls"] = false
	request["max_tool_calls"] = 1
	return json.Marshal(request)
}

func decodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("JSON body must be an object")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("request contains more than one JSON value")
		}
		return nil, err
	}
	return v, nil
}

// convertChatRequest translates a Chat Completions request to Responses API.
// It deliberately copies only fields that have a defined Responses equivalent;
// arbitrary client headers and Chat-only fields never leak upstream.
func convertChatRequest(raw []byte) ([]byte, requestMeta, error) {
	in, err := decodeObject(raw)
	if err != nil {
		return nil, requestMeta{}, fmt.Errorf("invalid JSON: %w", err)
	}

	model, _ := in["model"].(string)
	if strings.TrimSpace(model) == "" {
		return nil, requestMeta{}, errors.New("model must be a non-empty string")
	}
	stream, _ := in["stream"].(bool)
	meta := requestMeta{Model: model, Stream: stream, IncludeUsage: true}
	if opts, ok := in["stream_options"].(map[string]any); ok {
		if include, ok := opts["include_usage"].(bool); ok {
			meta.IncludeUsage = include
		}
	}

	out := map[string]any{"model": model, "stream": stream}
	for _, key := range []string{
		"temperature", "top_p", "frequency_penalty", "presence_penalty",
		"parallel_tool_calls", "user", "store", "metadata", "service_tier",
		"top_logprobs", "stop", "seed",
	} {
		if value, ok := in[key]; ok {
			out[key] = value
		}
	}

	if v, ok := in["max_completion_tokens"]; ok {
		out["max_output_tokens"] = v
	} else if v, ok := in["max_tokens"]; ok {
		out["max_output_tokens"] = v
	}
	if effort, ok := in["reasoning_effort"].(string); ok && effort != "" {
		out["reasoning"] = map[string]any{"effort": effort}
	}
	if format, ok := in["response_format"].(map[string]any); ok {
		if converted := convertResponseFormat(format); converted != nil {
			out["text"] = map[string]any{"format": converted}
		}
	}

	if tools, ok := in["tools"].([]any); ok {
		out["tools"] = convertTools(tools)
	} else if functions, ok := in["functions"].([]any); ok {
		legacy := make([]any, 0, len(functions))
		for _, fn := range functions {
			legacy = append(legacy, map[string]any{"type": "function", "function": fn})
		}
		out["tools"] = convertTools(legacy)
	}
	if choice, ok := in["tool_choice"]; ok {
		out["tool_choice"] = convertToolChoice(choice)
	} else if choice, ok := in["function_call"]; ok {
		out["tool_choice"] = convertLegacyFunctionChoice(choice)
	}

	messages, ok := in["messages"].([]any)
	if !ok {
		return nil, requestMeta{}, errors.New("messages must be an array")
	}
	input, instructions, err := convertMessages(messages)
	if err != nil {
		return nil, requestMeta{}, err
	}
	out["input"] = input
	if instructions != "" {
		out["instructions"] = instructions
	}
	if stream {
		out["include"] = []string{"reasoning.encrypted_content"}
	}

	converted, err := json.Marshal(out)
	if err != nil {
		return nil, requestMeta{}, fmt.Errorf("encode converted request: %w", err)
	}
	return converted, meta, nil
}

func convertMessages(messages []any) ([]any, string, error) {
	input := make([]any, 0, len(messages))
	var instructions []string
	for i, value := range messages {
		msg, ok := value.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("messages[%d] must be an object", i)
		}
		role, _ := msg["role"].(string)
		switch role {
		case "system", "developer":
			if text := contentText(msg["content"]); text != "" {
				instructions = append(instructions, text)
			}
		case "assistant":
			if content, exists := msg["content"]; exists && content != nil {
				if converted := convertAssistantContent(content); converted != nil {
					input = append(input, map[string]any{
						"role": "assistant", "content": converted,
					})
				}
			}
			if calls, ok := msg["tool_calls"].([]any); ok {
				for _, rawCall := range calls {
					call, ok := rawCall.(map[string]any)
					if !ok {
						continue
					}
					fn, _ := call["function"].(map[string]any)
					id, _ := call["id"].(string)
					name, _ := fn["name"].(string)
					args := stringValue(fn["arguments"], "{}")
					item := map[string]any{
						"type": "function_call", "call_id": id, "name": name,
						"arguments": args, "status": "completed",
					}
					if id != "" {
						item["id"] = id
					}
					input = append(input, item)
				}
			}
			// Legacy assistant function_call.
			if fn, ok := msg["function_call"].(map[string]any); ok {
				name, _ := fn["name"].(string)
				input = append(input, map[string]any{
					"type": "function_call", "call_id": name, "name": name,
					"arguments": stringValue(fn["arguments"], "{}"), "status": "completed",
				})
			}
		case "tool":
			callID, _ := msg["tool_call_id"].(string)
			input = append(input, map[string]any{
				"type": "function_call_output", "call_id": callID,
				"output": nonEmptyOutput(msg["content"]),
			})
		case "function":
			name, _ := msg["name"].(string)
			input = append(input, map[string]any{
				"type": "function_call_output", "call_id": name,
				"output": nonEmptyOutput(msg["content"]),
			})
		default:
			if role == "" {
				role = "user"
			}
			input = append(input, map[string]any{
				"role": role, "content": convertUserContent(msg["content"]),
			})
		}
	}
	return input, strings.Join(instructions, "\n\n"), nil
}

func convertUserContent(content any) any {
	parts, ok := content.([]any)
	if !ok {
		return content
	}
	out := make([]any, 0, len(parts))
	for _, raw := range parts {
		part, ok := raw.(map[string]any)
		if !ok {
			out = append(out, raw)
			continue
		}
		switch part["type"] {
		case "text":
			out = append(out, map[string]any{"type": "input_text", "text": part["text"]})
		case "image_url":
			image, ok := part["image_url"].(map[string]any)
			if !ok {
				continue
			}
			url, _ := image["url"].(string)
			if url == "" || isEmptyDataURI(url) {
				continue
			}
			converted := map[string]any{"type": "input_image", "image_url": url}
			if detail, ok := image["detail"].(string); ok && detail != "" {
				converted["detail"] = detail
			}
			out = append(out, converted)
		default:
			out = append(out, part)
		}
	}
	return out
}

func convertAssistantContent(content any) any {
	text := contentText(content)
	if text == "" {
		return nil
	}
	return []any{map[string]any{
		"type": "output_text", "text": text, "annotations": []any{},
	}}
}

func contentText(content any) string {
	switch value := content.(type) {
	case string:
		return value
	case []any:
		var b strings.Builder
		for _, raw := range value {
			part, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := part["text"].(string); ok {
				b.WriteString(text)
			} else if text, ok := part["thinking"].(string); ok {
				b.WriteString("<thinking>")
				b.WriteString(text)
				b.WriteString("</thinking>")
			}
		}
		return b.String()
	case nil:
		return ""
	default:
		b, _ := json.Marshal(value)
		return string(b)
	}
}

func nonEmptyOutput(content any) string {
	if text := contentText(content); text != "" {
		return text
	}
	return "(empty)"
}

func stringValue(value any, fallback string) string {
	if text, ok := value.(string); ok && text != "" {
		return text
	}
	if value != nil {
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
	}
	return fallback
}

func convertTools(tools []any) []any {
	out := make([]any, 0, len(tools))
	for _, value := range tools {
		tool, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if tool["type"] != "function" {
			out = append(out, tool)
			continue
		}
		fn, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		converted := map[string]any{"type": "function"}
		for _, key := range []string{"name", "description", "parameters", "strict"} {
			if v, exists := fn[key]; exists {
				converted[key] = v
			}
		}
		out = append(out, converted)
	}
	return out
}

func convertToolChoice(value any) any {
	choice, ok := value.(map[string]any)
	if !ok || choice["type"] != "function" {
		return value
	}
	if fn, ok := choice["function"].(map[string]any); ok {
		return map[string]any{"type": "function", "name": fn["name"]}
	}
	return value
}

func convertLegacyFunctionChoice(value any) any {
	if text, ok := value.(string); ok {
		if text == "none" || text == "auto" {
			return text
		}
	}
	if choice, ok := value.(map[string]any); ok {
		return map[string]any{"type": "function", "name": choice["name"]}
	}
	return value
}

func convertResponseFormat(format map[string]any) any {
	typ, _ := format["type"].(string)
	switch typ {
	case "text", "json_object":
		return map[string]any{"type": typ}
	case "json_schema":
		schema, ok := format["json_schema"].(map[string]any)
		if !ok {
			return nil
		}
		converted := map[string]any{"type": "json_schema"}
		for _, key := range []string{"name", "description", "schema", "strict"} {
			if v, exists := schema[key]; exists {
				converted[key] = v
			}
		}
		return converted
	default:
		if typ != "" {
			return format
		}
	}
	return nil
}

func isEmptyDataURI(value string) bool {
	if !strings.HasPrefix(value, "data:") {
		return false
	}
	marker := ";base64,"
	index := strings.Index(value, marker)
	return index >= 0 && strings.TrimSpace(value[index+len(marker):]) == ""
}

// convertResponsesResponse translates one non-stream Responses API response to
// the Chat Completions response shape.
func convertResponsesResponse(raw []byte, fallbackModel string) ([]byte, error) {
	response, err := decodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream Responses JSON: %w", err)
	}
	id, _ := response["id"].(string)
	model, _ := response["model"].(string)
	if model == "" {
		model = fallbackModel
	}
	created := response["created_at"]
	if created == nil {
		created = time.Now().Unix()
	}

	var text strings.Builder
	var refusal strings.Builder
	toolCalls := make([]any, 0)
	if output, ok := response["output"].([]any); ok {
		for _, rawItem := range output {
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			switch item["type"] {
			case "message":
				if parts, ok := item["content"].([]any); ok {
					for _, rawPart := range parts {
						part, ok := rawPart.(map[string]any)
						if !ok {
							continue
						}
						switch part["type"] {
						case "output_text", "text":
							if value, ok := part["text"].(string); ok {
								text.WriteString(value)
							}
						case "refusal":
							value, _ := part["refusal"].(string)
							if value == "" {
								value, _ = part["text"].(string)
							}
							refusal.WriteString(value)
						}
					}
				}
			case "function_call":
				callID, _ := item["call_id"].(string)
				if callID == "" {
					callID, _ = item["id"].(string)
				}
				toolCalls = append(toolCalls, map[string]any{
					"id": callID, "type": "function",
					"function": map[string]any{
						"name": item["name"], "arguments": stringValue(item["arguments"], "{}"),
					},
				})
			}
		}
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	if status, _ := response["status"].(string); status == "incomplete" {
		finishReason = "length"
		if details, ok := response["incomplete_details"].(map[string]any); ok {
			if reason, _ := details["reason"].(string); reason == "content_filter" {
				finishReason = "content_filter"
			}
		}
	}
	message := map[string]any{"role": "assistant", "content": nil}
	if text.Len() > 0 {
		message["content"] = text.String()
	}
	if refusal.Len() > 0 {
		message["refusal"] = refusal.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	result := map[string]any{
		"id": convertResponseID(id), "object": "chat.completion", "created": created,
		"model": model,
		"choices": []any{map[string]any{
			"index": 0, "message": message, "finish_reason": finishReason,
		}},
	}
	if usage, ok := response["usage"].(map[string]any); ok {
		result["usage"] = convertUsage(usage)
	}
	if tier, ok := response["service_tier"]; ok {
		result["service_tier"] = tier
	}
	return json.Marshal(result)
}

func convertUsage(usage map[string]any) map[string]any {
	input := usage["input_tokens"]
	output := usage["output_tokens"]
	total := usage["total_tokens"]
	if total == nil {
		total = addJSONNumbers(input, output)
	}
	result := map[string]any{
		"prompt_tokens": input, "completion_tokens": output, "total_tokens": total,
	}
	if details, ok := usage["input_tokens_details"].(map[string]any); ok {
		if cached, exists := details["cached_tokens"]; exists {
			result["prompt_tokens_details"] = map[string]any{"cached_tokens": cached}
		}
	}
	if details, ok := usage["output_tokens_details"].(map[string]any); ok {
		if reasoning, exists := details["reasoning_tokens"]; exists {
			result["completion_tokens_details"] = map[string]any{"reasoning_tokens": reasoning}
		}
	}
	return result
}

func addJSONNumbers(a, b any) any {
	toInt := func(value any) int64 {
		switch n := value.(type) {
		case json.Number:
			v, _ := n.Int64()
			return v
		case float64:
			return int64(n)
		case int:
			return int64(n)
		case int64:
			return n
		default:
			return 0
		}
	}
	return toInt(a) + toInt(b)
}

func convertResponseID(id string) string {
	if strings.HasPrefix(id, "chatcmpl-") {
		return id
	}
	if strings.HasPrefix(id, "resp_") {
		return "chatcmpl-" + strings.TrimPrefix(id, "resp_")
	}
	if id == "" {
		return fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	}
	return "chatcmpl-" + id
}
