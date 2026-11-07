package app

import "testing"

func TestParseUsageJSONAndSSE(t *testing.T) {
	input, output := parseUsage([]byte(`{"usage":{"input_tokens":12,"output_tokens":7}}`))
	if input != 12 || output != 7 {
		t.Fatalf("JSON usage = %d/%d", input, output)
	}
	sse := []byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":20,\"output_tokens\":5}}}\n\n")
	input, output = parseUsage(sse)
	if input != 20 || output != 5 {
		t.Fatalf("SSE usage = %d/%d", input, output)
	}
}
