package app

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

const maxUsageCaptureBytes = 2 << 20

type usageTrackingBody struct {
	body    io.ReadCloser
	buffer  []byte
	onUsage func(input, output uint64)
	once    sync.Once
}

type releaseBody struct {
	body    io.ReadCloser
	release func()
	once    sync.Once
}

func newReleaseBody(body io.ReadCloser, release func()) io.ReadCloser {
	return &releaseBody{body: body, release: release}
}

func (body *releaseBody) Read(target []byte) (int, error) {
	n, err := body.body.Read(target)
	if err != nil {
		body.once.Do(body.release)
	}
	return n, err
}

func (body *releaseBody) Close() error {
	body.once.Do(body.release)
	return body.body.Close()
}

func newUsageTrackingBody(body io.ReadCloser, onUsage func(input, output uint64)) io.ReadCloser {
	return &usageTrackingBody{body: body, onUsage: onUsage}
}

func (body *usageTrackingBody) Read(target []byte) (int, error) {
	n, err := body.body.Read(target)
	if n > 0 {
		body.capture(target[:n])
	}
	if err != nil {
		body.finalize()
	}
	return n, err
}

func (body *usageTrackingBody) Close() error {
	body.finalize()
	return body.body.Close()
}

func (body *usageTrackingBody) capture(chunk []byte) {
	if len(chunk) >= maxUsageCaptureBytes {
		body.buffer = append(body.buffer[:0], chunk[len(chunk)-maxUsageCaptureBytes:]...)
		return
	}
	if len(body.buffer)+len(chunk) > maxUsageCaptureBytes {
		drop := len(body.buffer) + len(chunk) - maxUsageCaptureBytes
		body.buffer = append(body.buffer[:0], body.buffer[drop:]...)
	}
	body.buffer = append(body.buffer, chunk...)
}

func (body *usageTrackingBody) finalize() {
	body.once.Do(func() {
		input, output := parseUsage(body.buffer)
		if input > 0 || output > 0 {
			body.onUsage(input, output)
		}
	})
}

func parseUsage(raw []byte) (uint64, uint64) {
	if input, output, ok := usageFromJSON(raw); ok {
		return input, output
	}
	lines := bytes.Split(raw, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if input, output, ok := usageFromJSON(data); ok {
			return input, output
		}
	}
	return 0, 0
}

func usageFromJSON(raw []byte) (uint64, uint64, bool) {
	var event map[string]any
	if json.Unmarshal(raw, &event) != nil {
		return 0, 0, false
	}
	if response, ok := event["response"].(map[string]any); ok {
		event = response
	}
	usage, ok := event["usage"].(map[string]any)
	if !ok {
		return 0, 0, false
	}
	return uint64Value(usage["input_tokens"]), uint64Value(usage["output_tokens"]), true
}

func uint64Value(value any) uint64 {
	switch number := value.(type) {
	case float64:
		return uint64(number)
	case json.Number:
		parsed, _ := number.Int64()
		return uint64(max(parsed, 0))
	case int:
		return uint64(max(number, 0))
	case uint64:
		return number
	default:
		return 0
	}
}
