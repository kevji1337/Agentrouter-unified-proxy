package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConvertChatRequest(t *testing.T) {
	raw := []byte(`{
  "model":"test-model",
  "messages":[
    {"role":"system","content":"Be concise."},
    {"role":"user","content":[
      {"type":"text","text":"describe"},
      {"type":"image_url","image_url":{"url":"https://example.test/a.png","detail":"high"}}
    ]},
    {"role":"assistant","content":null,"tool_calls":[
      {"id":"call_1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Riga\"}"}}
    ]},
    {"role":"tool","tool_call_id":"call_1","content":"sunny"}
  ],
  "tools":[{"type":"function","function":{"name":"weather","description":"Get weather","parameters":{"type":"object"}}}],
  "tool_choice":{"type":"function","function":{"name":"weather"}},
  "response_format":{"type":"json_schema","json_schema":{"name":"answer","schema":{"type":"object"},"strict":true}},
  "max_completion_tokens":512,
  "reasoning_effort":"medium",
  "stream":true,
  "stream_options":{"include_usage":false}
}`)

	converted, meta, err := convertChatRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.Stream || meta.IncludeUsage || meta.Model != "test-model" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	var body map[string]any
	if err := json.Unmarshal(converted, &body); err != nil {
		t.Fatal(err)
	}
	if body["instructions"] != "Be concise." {
		t.Fatalf("instructions = %#v", body["instructions"])
	}
	if body["max_output_tokens"].(float64) != 512 {
		t.Fatalf("max_output_tokens = %#v", body["max_output_tokens"])
	}
	input := body["input"].([]any)
	if len(input) != 3 {
		t.Fatalf("input has %d items, want 3: %#v", len(input), input)
	}
	user := input[0].(map[string]any)
	parts := user["content"].([]any)
	if parts[0].(map[string]any)["type"] != "input_text" || parts[1].(map[string]any)["type"] != "input_image" {
		t.Fatalf("vision conversion failed: %#v", parts)
	}
	call := input[1].(map[string]any)
	if call["type"] != "function_call" || call["call_id"] != "call_1" {
		t.Fatalf("tool call conversion failed: %#v", call)
	}
	tool := body["tools"].([]any)[0].(map[string]any)
	if _, nested := tool["function"]; nested || tool["name"] != "weather" {
		t.Fatalf("tool was not flattened: %#v", tool)
	}
	choice := body["tool_choice"].(map[string]any)
	if choice["name"] != "weather" {
		t.Fatalf("tool choice = %#v", choice)
	}
}

func TestConvertResponsesResponse(t *testing.T) {
	raw := []byte(`{
  "id":"resp_abc","object":"response","created_at":1700000000,"status":"completed","model":"m",
  "output":[
    {"type":"message","content":[{"type":"output_text","text":"Hello "},{"type":"output_text","text":"world"}]},
    {"type":"function_call","call_id":"call_7","name":"lookup","arguments":"{\"q\":1}"}
  ],
  "usage":{"input_tokens":10,"output_tokens":4,"total_tokens":14,"input_tokens_details":{"cached_tokens":3}}
}`)
	converted, err := convertResponsesResponse(raw, "fallback")
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(converted, &body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != "chatcmpl-abc" || body["object"] != "chat.completion" {
		t.Fatalf("bad envelope: %#v", body)
	}
	choice := body["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Fatalf("finish_reason = %#v", choice["finish_reason"])
	}
	message := choice["message"].(map[string]any)
	if message["content"] != "Hello world" {
		t.Fatalf("content = %#v", message["content"])
	}
	if len(message["tool_calls"].([]any)) != 1 {
		t.Fatalf("tool calls = %#v", message["tool_calls"])
	}
	usage := body["usage"].(map[string]any)
	if usage["prompt_tokens"].(float64) != 10 {
		t.Fatalf("usage = %#v", usage)
	}
}

func TestConvertResponsesSSE(t *testing.T) {
	upstream := strings.Join([]string{
		`event: response.created`,
		`data: {"type":"response.created","response":{"id":"resp_stream","model":"m"}}`,
		``,
		`event: response.output_text.delta`,
		`data: {"type":"response.output_text.delta","delta":"Hi"}`,
		``,
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"lookup"}}`,
		``,
		`event: response.function_call_arguments.delta`,
		`data: {"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":"{\"q\":1}"}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"id":"resp_stream","model":"m","status":"completed","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}}`,
		``,
	}, "\n")

	recorder := newFlushRecorder()
	err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true, IncludeUsage: true})
	if err != nil {
		t.Fatal(err)
	}
	result := recorder.Body.String()
	for _, want := range []string{
		`"object":"chat.completion.chunk"`, `"role":"assistant"`, `"content":"Hi"`,
		`"tool_calls"`, `"arguments":"{\"q\":1}"`, `"finish_reason":"tool_calls"`,
		`"prompt_tokens":2`, `data: [DONE]`,
	} {
		if !strings.Contains(result, want) {
			t.Fatalf("stream missing %q:\n%s", want, result)
		}
	}
	if recorder.flushes < 5 {
		t.Fatalf("stream flushed only %d times", recorder.flushes)
	}
}

func TestToolArgumentsRecoveredFromDoneEvent(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read_file"}}`,
		``,
		`data: {"type":"response.function_call_arguments.done","output_index":0,"item_id":"fc_1","arguments":"{\"target\":\"C:\\\\Temp\\\\session.md\"}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed"}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	if err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true}); err != nil {
		t.Fatal(err)
	}
	result := recorder.Body.String()
	if !strings.Contains(result, `"arguments":"{\"target\":\"C:\\\\Temp\\\\session.md\"}"`) {
		t.Fatalf("done-event arguments were lost:\n%s", result)
	}
	if strings.Contains(result, `"arguments":"{}"`) {
		t.Fatalf("valid arguments were replaced with empty object:\n%s", result)
	}
	if count := strings.Count(result, `"tool_calls":[`); count != 1 {
		t.Fatalf("tool call must be emitted as one self-contained chunk, got %d:\n%s", count, result)
	}
	if !strings.Contains(result, `"id":"call_1"`) || !strings.Contains(result, `"name":"read_file"`) {
		t.Fatalf("self-contained tool chunk is missing id/name:\n%s", result)
	}
}

func TestToolArgumentsRecoveredFromCompletedResponse(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.created","response":{"id":"resp_tools","model":"m"}}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed","output":[{"id":"fc_2","type":"function_call","call_id":"call_2","name":"read_file","arguments":"{\"target\":\"note.md\"}"}]}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	if err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true}); err != nil {
		t.Fatal(err)
	}
	result := recorder.Body.String()
	for _, expected := range []string{`"name":"read_file"`, `"arguments":"{\"target\":\"note.md\"}"`, `"finish_reason":"tool_calls"`} {
		if !strings.Contains(result, expected) {
			t.Fatalf("terminal tool recovery missing %s:\n%s", expected, result)
		}
	}
}

func TestEmptyToolArgumentsBecomeJSONObject(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_3","type":"function_call","call_id":"call_3","name":"no_args"}}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed"}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	if err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorder.Body.String(), `"arguments":"{}"`) {
		t.Fatalf("empty arguments did not receive JSON fallback:\n%s", recorder.Body.String())
	}
}

func TestCumulativeToolArgumentDeltas(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_4","type":"function_call","call_id":"call_4","name":"read_file","arguments":"{}"}}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_4","delta":"{\"tar"}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_4","delta":"{\"target\":\"note.md\"}"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed"}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	if err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true}); err != nil {
		t.Fatal(err)
	}
	result := recorder.Body.String()
	if !strings.Contains(result, `"arguments":"{\"target\":\"note.md\"}"`) {
		t.Fatalf("cumulative arguments were not normalized:\n%s", result)
	}
	if strings.Contains(result, `{\"tar{\"target`) {
		t.Fatalf("cumulative snapshots were concatenated:\n%s", result)
	}
}

func TestTerminalToolArgumentsOverrideBufferedDeltas(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_5","type":"function_call","call_id":"call_5","name":"read_file"}}`,
		``,
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_5","delta":"broken"}`,
		``,
		`data: {"type":"response.completed","response":{"status":"completed","output":[{"id":"fc_5","type":"function_call","call_id":"call_5","name":"read_file","arguments":"{\"target\":\"correct.md\"}"}]}}`,
		``,
	}, "\n")
	recorder := newFlushRecorder()
	if err := convertResponsesSSE(recorder, strings.NewReader(upstream), requestMeta{Model: "m", Stream: true}); err != nil {
		t.Fatal(err)
	}
	result := recorder.Body.String()
	if !strings.Contains(result, `"arguments":"{\"target\":\"correct.md\"}"`) || strings.Contains(result, `"arguments":"broken"`) {
		t.Fatalf("terminal arguments did not override buffered deltas:\n%s", result)
	}
}
