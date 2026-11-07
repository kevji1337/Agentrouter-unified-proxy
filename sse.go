package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type streamTool struct {
	Index            int
	CallID           string
	Name             string
	Arguments        string
	ArgumentsEmitted bool
	MismatchLogged   bool
	Announced        bool
}

type chatStreamState struct {
	ID           string
	Model        string
	Created      int64
	RoleSent     bool
	Finalized    bool
	SawTool      bool
	IncludeUsage bool
	NextTool     int
	Tools        []*streamTool
	ByOutput     map[int]*streamTool
	ByItemID     map[string]*streamTool
	ByCallID     map[string]*streamTool
}

func newChatStreamState(meta requestMeta) *chatStreamState {
	return &chatStreamState{
		ID: fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano()), Model: meta.Model,
		Created: time.Now().Unix(), IncludeUsage: meta.IncludeUsage,
		ByOutput: make(map[int]*streamTool), ByItemID: make(map[string]*streamTool),
		ByCallID: make(map[string]*streamTool),
	}
}

// convertResponsesSSE incrementally maps Responses events to Chat Completions
// chunks. A frame is flushed immediately after conversion, preserving upstream
// backpressure and avoiding buffering the model output.
func convertResponsesSSE(w http.ResponseWriter, body io.Reader, meta requestMeta) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	state := newChatStreamState(meta)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	dataLines := make([]string, 0, 1)

	process := func() error {
		if len(dataLines) == 0 {
			return nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		if strings.TrimSpace(data) == "" || strings.TrimSpace(data) == "[DONE]" {
			return nil
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return nil // Ignore malformed/unknown upstream keepalive frames.
		}
		return handleResponsesEvent(w, event, state)
	}

	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			if err := process(); err != nil {
				return err
			}
			if state.Finalized {
				break
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			value := strings.TrimPrefix(line, "data:")
			value = strings.TrimPrefix(value, " ")
			dataLines = append(dataLines, value)
		}
	}
	if !state.Finalized {
		if err := process(); err != nil {
			return err
		}
	}
	if !state.Finalized {
		if err := finalizeChatStream(w, state, "stop", nil); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	flush(w)
	return scanner.Err()
}

func handleResponsesEvent(w http.ResponseWriter, event map[string]any, state *chatStreamState) error {
	typ, _ := event["type"].(string)
	switch typ {
	case "response.created", "response.in_progress":
		updateStreamIdentity(state, event)
		return ensureRole(w, state)

	case "response.output_text.delta", "response.content_part.delta":
		delta, _ := event["delta"].(string)
		if delta == "" {
			return nil
		}
		if err := ensureRole(w, state); err != nil {
			return err
		}
		return writeChatChunk(w, state, map[string]any{"content": delta}, nil, nil)

	case "response.refusal.delta":
		delta, _ := event["delta"].(string)
		if delta == "" {
			return nil
		}
		if err := ensureRole(w, state); err != nil {
			return err
		}
		return writeChatChunk(w, state, map[string]any{"refusal": delta}, nil, nil)

	case "response.reasoning_summary_text.delta":
		delta, _ := event["delta"].(string)
		if delta == "" {
			return nil
		}
		if err := ensureRole(w, state); err != nil {
			return err
		}
		return writeChatChunk(w, state, map[string]any{"reasoning_content": delta}, nil, nil)

	case "response.output_item.added":
		item, _ := event["item"].(map[string]any)
		if item == nil || item["type"] != "function_call" {
			return nil
		}
		return announceTool(w, state, event, item)

	case "response.function_call_arguments.delta":
		delta, _ := event["delta"].(string)
		if delta == "" {
			return nil
		}
		tool := findTool(state, event)
		if tool == nil {
			// A few compatible APIs omit output_item.added. Create a stable slot.
			item := map[string]any{"type": "function_call", "id": event["item_id"]}
			if err := announceTool(w, state, event, item); err != nil {
				return err
			}
			tool = findTool(state, event)
		}
		if tool == nil {
			return nil
		}
		accumulateToolArgumentDelta(tool, delta)
		return nil

	case "response.function_call_arguments.done":
		tool := findTool(state, event)
		if tool == nil {
			item := map[string]any{
				"type": "function_call", "id": event["item_id"],
				"call_id": event["call_id"], "name": event["name"],
			}
			if err := announceTool(w, state, event, item); err != nil {
				return err
			}
			tool = findTool(state, event)
		}
		return emitCompletedToolArguments(w, state, tool, stringValue(event["arguments"], ""))

	case "response.output_item.done":
		item, _ := event["item"].(map[string]any)
		if item == nil || item["type"] != "function_call" {
			return nil
		}
		tool := findTool(state, event)
		if tool == nil {
			if err := announceTool(w, state, event, item); err != nil {
				return err
			}
			tool = findTool(state, event)
		}
		return emitCompletedToolArguments(w, state, tool, stringValue(item["arguments"], ""))

	case "response.completed", "response.done", "response.incomplete", "response.failed":
		updateStreamIdentity(state, event)
		response, _ := event["response"].(map[string]any)
		if response != nil {
			if err := reconcileTerminalTools(w, state, response); err != nil {
				return err
			}
			finishReason := "stop"
			if state.SawTool {
				finishReason = "tool_calls"
			}
			status, _ := response["status"].(string)
			if status == "incomplete" {
				finishReason = "length"
				if details, ok := response["incomplete_details"].(map[string]any); ok {
					if reason, _ := details["reason"].(string); reason == "content_filter" {
						finishReason = "content_filter"
					}
				}
			}
			usage, _ := response["usage"].(map[string]any)
			return finalizeChatStream(w, state, finishReason, usage)
		}
		finishReason := "stop"
		if state.SawTool {
			finishReason = "tool_calls"
		}
		return finalizeChatStream(w, state, finishReason, nil)
	}
	return nil
}

func updateStreamIdentity(state *chatStreamState, event map[string]any) {
	response, _ := event["response"].(map[string]any)
	if response == nil {
		return
	}
	if id, ok := response["id"].(string); ok && id != "" {
		state.ID = convertResponseID(id)
	}
	if model, ok := response["model"].(string); ok && model != "" {
		state.Model = model
	}
	if created, ok := response["created_at"].(float64); ok && created > 0 {
		state.Created = int64(created)
	}
}

func ensureRole(w http.ResponseWriter, state *chatStreamState) error {
	if state.RoleSent {
		return nil
	}
	state.RoleSent = true
	return writeChatChunk(w, state, map[string]any{"role": "assistant"}, nil, nil)
}

func announceTool(w http.ResponseWriter, state *chatStreamState, event, item map[string]any) error {
	if err := ensureRole(w, state); err != nil {
		return err
	}
	outputIndex := intValue(event["output_index"])
	itemID, _ := item["id"].(string)
	callID, _ := item["call_id"].(string)
	if callID == "" {
		callID = itemID
	}
	if callID == "" {
		callID = fmt.Sprintf("call_%d", time.Now().UnixNano())
	}
	name, _ := item["name"].(string)
	if existing := findToolByIdentity(state, outputIndex, itemID, callID); existing != nil {
		if existing.Name == "" && name != "" {
			existing.Name = name
			return writeChatChunk(w, state, map[string]any{"tool_calls": []any{map[string]any{
				"index": existing.Index, "function": map[string]any{"name": name},
			}}}, nil, nil)
		}
		return nil
	}
	tool := &streamTool{
		Index: state.NextTool, CallID: callID, Name: name, Announced: true,
	}
	state.NextTool++
	state.SawTool = true
	state.Tools = append(state.Tools, tool)
	state.ByOutput[outputIndex] = tool
	if itemID != "" {
		state.ByItemID[itemID] = tool
	}
	state.ByCallID[callID] = tool
	return writeChatChunk(w, state, map[string]any{"tool_calls": []any{map[string]any{
		"index": tool.Index, "id": callID, "type": "function",
		"function": map[string]any{"name": name, "arguments": ""},
	}}}, nil, nil)
}

func findTool(state *chatStreamState, event map[string]any) *streamTool {
	if itemID, ok := event["item_id"].(string); ok && itemID != "" {
		if tool := state.ByItemID[itemID]; tool != nil {
			return tool
		}
	}
	if callID, ok := event["call_id"].(string); ok && callID != "" {
		if tool := state.ByCallID[callID]; tool != nil {
			return tool
		}
	}
	return state.ByOutput[intValue(event["output_index"])]
}

func findToolByIdentity(state *chatStreamState, outputIndex int, itemID, callID string) *streamTool {
	if itemID != "" && state.ByItemID[itemID] != nil {
		return state.ByItemID[itemID]
	}
	if callID != "" && state.ByCallID[callID] != nil {
		return state.ByCallID[callID]
	}
	return state.ByOutput[outputIndex]
}

func emitCompletedToolArguments(w http.ResponseWriter, state *chatStreamState, tool *streamTool, full string) error {
	if tool == nil || full == "" {
		return nil
	}
	if tool.ArgumentsEmitted {
		if !jsonStringsEquivalent(tool.Arguments, full) && !tool.MismatchLogged {
			tool.MismatchLogged = true
			logEvent("warn", "tool_arguments_mismatch", map[string]any{
				"tool": tool.Name, "call_id": tool.CallID,
				"streamed_length": len(tool.Arguments), "final_length": len(full),
			})
		}
		return nil
	}
	// The terminal value is authoritative. Keeping argument deltas buffered
	// until this point avoids forwarding cumulative snapshots or placeholders
	// as if they were incremental Chat Completions deltas.
	tool.Arguments = full
	if !json.Valid([]byte(tool.Arguments)) {
		logEvent("warn", "invalid_streamed_tool_arguments", map[string]any{
			"tool": tool.Name, "call_id": tool.CallID,
		})
		tool.Arguments = "{}"
	}
	tool.ArgumentsEmitted = true
	return writeChatChunk(w, state, map[string]any{"tool_calls": []any{map[string]any{
		"index": tool.Index, "function": map[string]any{"arguments": tool.Arguments},
	}}}, nil, nil)
}

func accumulateToolArgumentDelta(tool *streamTool, delta string) {
	if tool == nil || delta == "" || tool.ArgumentsEmitted {
		return
	}
	if tool.Arguments == "" {
		tool.Arguments = delta
		return
	}
	// Some Responses-compatible gateways send cumulative snapshots in `delta`
	// instead of true incremental fragments. Support both forms.
	if strings.HasPrefix(delta, tool.Arguments) {
		tool.Arguments = delta
		return
	}
	if strings.HasPrefix(tool.Arguments, delta) {
		return // duplicate or stale cumulative snapshot
	}
	tool.Arguments += delta
}

func jsonStringsEquivalent(left, right string) bool {
	if left == right {
		return true
	}
	var leftValue, rightValue any
	if json.Unmarshal([]byte(left), &leftValue) != nil || json.Unmarshal([]byte(right), &rightValue) != nil {
		return false
	}
	leftJSON, _ := json.Marshal(leftValue)
	rightJSON, _ := json.Marshal(rightValue)
	return string(leftJSON) == string(rightJSON)
}

func reconcileTerminalTools(w http.ResponseWriter, state *chatStreamState, response map[string]any) error {
	output, _ := response["output"].([]any)
	for outputIndex, rawItem := range output {
		item, _ := rawItem.(map[string]any)
		if item == nil || item["type"] != "function_call" {
			continue
		}
		event := map[string]any{
			"output_index": outputIndex, "item_id": item["id"], "call_id": item["call_id"],
		}
		tool := findTool(state, event)
		if tool == nil {
			if err := announceTool(w, state, event, item); err != nil {
				return err
			}
			tool = findTool(state, event)
		}
		if tool != nil && tool.Name == "" {
			if name, _ := item["name"].(string); name != "" {
				tool.Name = name
				if err := writeChatChunk(w, state, map[string]any{"tool_calls": []any{map[string]any{
					"index": tool.Index, "function": map[string]any{"name": name},
				}}}, nil, nil); err != nil {
					return err
				}
			}
		}
		if err := emitCompletedToolArguments(w, state, tool, stringValue(item["arguments"], "")); err != nil {
			return err
		}
	}
	return nil
}

func intValue(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case json.Number:
		v, _ := number.Int64()
		return int(v)
	case int:
		return number
	default:
		return 0
	}
}

func finalizeChatStream(w http.ResponseWriter, state *chatStreamState, reason string, usage map[string]any) error {
	if state.Finalized {
		return nil
	}
	if err := ensureRole(w, state); err != nil {
		return err
	}
	for _, tool := range state.Tools {
		arguments := tool.Arguments
		if arguments == "" || !json.Valid([]byte(arguments)) {
			if arguments != "" {
				logEvent("warn", "invalid_streamed_tool_arguments", map[string]any{
					"tool": tool.Name, "call_id": tool.CallID,
				})
			}
			arguments = "{}"
		}
		if !tool.ArgumentsEmitted {
			if err := emitCompletedToolArguments(w, state, tool, arguments); err != nil {
				return err
			}
		}
	}
	state.Finalized = true
	if err := writeChatChunk(w, state, map[string]any{}, &reason, nil); err != nil {
		return err
	}
	if state.IncludeUsage && usage != nil {
		chunk := map[string]any{
			"id": state.ID, "object": "chat.completion.chunk", "created": state.Created,
			"model": state.Model, "choices": []any{}, "usage": convertUsage(usage),
		}
		return writeSSEJSON(w, chunk)
	}
	return nil
}

func writeChatChunk(w http.ResponseWriter, state *chatStreamState, delta map[string]any, finish *string, usage map[string]any) error {
	choice := map[string]any{"index": 0, "delta": delta, "finish_reason": finish}
	chunk := map[string]any{
		"id": state.ID, "object": "chat.completion.chunk", "created": state.Created,
		"model": state.Model, "choices": []any{choice},
	}
	if usage != nil {
		chunk["usage"] = convertUsage(usage)
	}
	return writeSSEJSON(w, chunk)
}

func writeSSEJSON(w http.ResponseWriter, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", encoded); err != nil {
		return err
	}
	flush(w)
	return nil
}

func flush(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// writeSyntheticChatStream handles an upstream that ignored stream=true and
// returned one JSON Responses object. It emits valid Chat SSE framing rather
// than returning JSON to a streaming client.
func writeSyntheticChatStream(w http.ResponseWriter, chatJSON []byte, includeUsage bool) {
	var response map[string]any
	if json.Unmarshal(chatJSON, &response) != nil {
		writeError(w, http.StatusBadGateway, "conversion_error", "failed to synthesize stream")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	base := map[string]any{
		"id": response["id"], "object": "chat.completion.chunk",
		"created": response["created"], "model": response["model"],
	}
	choices, _ := response["choices"].([]any)
	if len(choices) > 0 {
		choice, _ := choices[0].(map[string]any)
		message, _ := choice["message"].(map[string]any)
		delta := map[string]any{"role": "assistant"}
		for _, key := range []string{"content", "refusal", "tool_calls"} {
			if value, ok := message[key]; ok && value != nil {
				delta[key] = value
			}
		}
		chunk := cloneMap(base)
		chunk["choices"] = []any{map[string]any{
			"index": 0, "delta": delta, "finish_reason": nil,
		}}
		_ = writeSSEJSON(w, chunk)

		finish := cloneMap(base)
		finish["choices"] = []any{map[string]any{
			"index": 0, "delta": map[string]any{}, "finish_reason": choice["finish_reason"],
		}}
		_ = writeSSEJSON(w, finish)
	}
	if usage, ok := response["usage"]; ok && includeUsage {
		chunk := cloneMap(base)
		chunk["choices"] = []any{}
		chunk["usage"] = usage
		_ = writeSSEJSON(w, chunk)
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flush(w)
}

func cloneMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
