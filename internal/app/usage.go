package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"sync"
)

const maxUsageCaptureBytes = 2 << 20

type outOfBandUsageContextKey struct{}

type outOfBandUsage struct {
	mu     sync.Mutex
	input  uint64
	output uint64
	set    bool
}

func withOutOfBandUsage(ctx context.Context) (context.Context, *outOfBandUsage) {
	holder := &outOfBandUsage{}
	return context.WithValue(ctx, outOfBandUsageContextKey{}, holder), holder
}

func recordOutOfBandUsage(ctx context.Context, input, output uint64) {
	holder, _ := ctx.Value(outOfBandUsageContextKey{}).(*outOfBandUsage)
	if holder == nil || (input == 0 && output == 0) {
		return
	}
	holder.mu.Lock()
	holder.input = input
	holder.output = output
	holder.set = true
	holder.mu.Unlock()
}

func (holder *outOfBandUsage) load() (uint64, uint64, bool) {
	if holder == nil {
		return 0, 0, false
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	return holder.input, holder.output, holder.set
}

type usageTrackingBody struct {
	body     io.ReadCloser
	buffer   []byte
	fallback *outOfBandUsage
	onUsage  func(input, output uint64)
	once     sync.Once
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
	return newUsageTrackingBodyWithFallback(body, nil, onUsage)
}

func newUsageTrackingBodyWithFallback(body io.ReadCloser, fallback *outOfBandUsage, onUsage func(input, output uint64)) io.ReadCloser {
	return &usageTrackingBody{body: body, fallback: fallback, onUsage: onUsage}
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
		if input == 0 && output == 0 {
			if fbIn, fbOut, ok := body.fallback.load(); ok {
				input, output = fbIn, fbOut
			}
		}
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
	var found bool
	var lastInput, lastOutput uint64
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if input, output, ok := usageFromJSON(data); ok {
			if !found {
				lastInput, lastOutput = input, output
				found = true
				if lastInput > 0 {
					return lastInput, lastOutput
				}
			} else if lastInput == 0 && input > 0 {
				lastInput = input
				return lastInput, lastOutput
			}
		}
	}
	return lastInput, lastOutput
}

func usageFromJSON(raw []byte) (uint64, uint64, bool) {
	var event map[string]any
	if json.Unmarshal(raw, &event) != nil {
		return 0, 0, false
	}
	if response, ok := event["response"].(map[string]any); ok {
		event = response
	} else if message, ok := event["message"].(map[string]any); ok {
		if _, hasUsage := event["usage"].(map[string]any); !hasUsage {
			event = message
		}
	}
	usage, ok := event["usage"].(map[string]any)
	if !ok {
		return 0, 0, false
	}
	input, output := usage["input_tokens"], usage["output_tokens"]
	if input == nil {
		input = usage["prompt_tokens"]
	}
	if output == nil {
		output = usage["completion_tokens"]
	}
	inTokens := uint64Value(input) + uint64Value(usage["cache_creation_input_tokens"]) + uint64Value(usage["cache_read_input_tokens"])
	return inTokens, uint64Value(output), true
}

func uint64Value(value any) uint64 {
	switch number := value.(type) {
	case float64:
		if number <= 0 || math.IsNaN(number) || math.IsInf(number, 0) {
			return 0
		}
		if number >= float64(math.MaxUint64) {
			return math.MaxUint64
		}
		return uint64(number)
	case json.Number:
		if parsed, err := number.Int64(); err == nil {
			return uint64(max(parsed, 0))
		}
		if parsedU, err := strconv.ParseUint(number.String(), 10, 64); err == nil {
			return parsedU
		}
		if parsedF, err := number.Float64(); err == nil {
			return uint64Value(parsedF)
		}
		return 0
	case int:
		return uint64(max(number, 0))
	case int64:
		return uint64(max(number, 0))
	case uint64:
		return number
	default:
		return 0
	}
}
