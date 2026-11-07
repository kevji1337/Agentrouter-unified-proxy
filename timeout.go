package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

var errUpstreamIdleTimeout = errors.New("upstream response idle timeout")

// idleTimeoutBody cancels the upstream request when no body bytes arrive for
// the configured interval. Canceling the request interrupts a blocked HTTP/2
// or HTTP/1 body read, unlike a timer that only returns an error later.
type idleTimeoutBody struct {
	body     io.ReadCloser
	cancel   context.CancelFunc
	timeout  time.Duration
	mu       sync.Mutex
	timer    *time.Timer
	timedOut bool
	closed   bool
}

func newIdleTimeoutBody(body io.ReadCloser, cancel context.CancelFunc, timeout time.Duration) io.ReadCloser {
	wrapped := &idleTimeoutBody{body: body, cancel: cancel, timeout: timeout}
	if timeout > 0 {
		wrapped.timer = time.AfterFunc(timeout, wrapped.expire)
	}
	return wrapped
}

func (body *idleTimeoutBody) expire() {
	body.mu.Lock()
	if body.closed {
		body.mu.Unlock()
		return
	}
	body.timedOut = true
	body.mu.Unlock()
	body.cancel()
}

func (body *idleTimeoutBody) Read(buffer []byte) (int, error) {
	n, err := body.body.Read(buffer)
	body.mu.Lock()
	if n > 0 && body.timer != nil && !body.closed {
		body.timer.Reset(body.timeout)
	}
	timedOut := body.timedOut
	body.mu.Unlock()
	if err != nil && timedOut {
		return n, errUpstreamIdleTimeout
	}
	return n, err
}

func (body *idleTimeoutBody) Close() error {
	body.mu.Lock()
	if body.closed {
		body.mu.Unlock()
		return nil
	}
	body.closed = true
	if body.timer != nil {
		body.timer.Stop()
	}
	body.mu.Unlock()
	body.cancel()
	return body.body.Close()
}
