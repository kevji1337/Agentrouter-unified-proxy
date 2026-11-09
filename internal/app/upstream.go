package app

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const (
	protocolResponses       = "responses"
	protocolChatCompletions = "chat-completions"
)

var errNoCompatibleUpstream = errors.New("no available upstream supports the requested API protocol and model")
var errInvalidUpstreamRequest = errors.New("request cannot be converted to Responses API")

// An absent protocol preserves the behavior of existing v1/v2 stores.
func effectiveProtocol(protocol string) string {
	if protocol == "" {
		return protocolResponses
	}
	return protocol
}

func validProtocol(protocol string) bool {
	return effectiveProtocol(protocol) == protocolResponses || protocol == protocolChatCompletions
}

func parseUpstreamURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("base_url must be an absolute http(s) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") || parsed.Opaque != "" {
		return nil, errors.New("base_url must not contain credentials, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("base_url port must be between 1 and 65535")
		}
	}
	// Do not clean or discard provider-specific path segments.
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return parsed, nil
}

func upstreamOrigin(base *url.URL) string {
	return strings.ToLower(base.Scheme + "://" + base.Host)
}

// A process-owned origin allowlist also applies to loaded/imported credentials.
// Private/local origins work only when explicitly listed in restricted mode.
func (server *proxyServer) validateUpstreamURL(raw string) (*url.URL, error) {
	base, err := parseUpstreamURL(raw)
	if err != nil {
		return nil, err
	}
	if len(server.cfg.AllowedUpstreamOrigins) > 0 {
		allowed := false
		for _, origin := range server.cfg.AllowedUpstreamOrigins {
			if upstreamOrigin(base) == origin {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("upstream origin is not allowed by UPSTREAM_ALLOWED_ORIGINS")
		}
	}
	return base, nil
}

func (server *proxyServer) upstreamSettings(key *selectedAPIKey) (*url.URL, string, string, error) {
	raw := server.cfg.UpstreamURL.String()
	protocol := effectiveProtocol(server.cfg.UpstreamProtocol)
	profile := server.cfg.Profile
	if key != nil {
		protocol = effectiveProtocol(key.APIProtocol)
		if key.BaseURL != "" {
			raw = key.BaseURL
		}
	}
	if !validProtocol(protocol) {
		return nil, "", "", errors.New("invalid configured upstream protocol")
	}
	base, err := server.validateUpstreamURL(raw)
	if err != nil {
		return nil, "", "", err
	}
	if upstreamOrigin(base) != upstreamOrigin(server.cfg.UpstreamURL) {
		profile = "generic"
	}
	if key != nil && key.SpoofProfile != "" {
		profile = key.SpoofProfile
	}
	return base, profile, protocol, nil
}

func (server *proxyServer) usesWAFCookies(base *url.URL, profile string) bool {
	return profile != "generic" && upstreamOrigin(base) == upstreamOrigin(server.cfg.UpstreamURL)
}

// Prepare from the original client payload on EVERY attempt, so failover may
// change protocols without reusing a payload converted for another upstream.
func (server *proxyServer) prepareUpstream(path string, body []byte, protocol string) (string, []byte, *requestMeta, error) {
	if path == "/v1/responses" && protocol != protocolResponses {
		return "", nil, nil, errNoCompatibleUpstream
	}
	if path != "/v1/chat/completions" || protocol == protocolChatCompletions {
		return path, body, nil, nil
	}
	converted, meta, err := convertChatRequest(body)
	if err != nil {
		return "", nil, nil, errInvalidUpstreamRequest
	}
	if server.cfg.ForceSequentialTools {
		converted, err = enforceSequentialTools(converted)
		if err != nil {
			return "", nil, nil, errInvalidUpstreamRequest
		}
		meta.ForceSequentialTools = true
	}
	return "/v1/responses", converted, &meta, nil
}
