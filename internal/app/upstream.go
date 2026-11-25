package app

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	protocolResponses       = "responses"
	protocolChatCompletions = "chat-completions"
	protocolGenAI           = "genai"

	DefaultGenAIBaseURL = "https://generativelanguage.googleapis.com"
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
	p := effectiveProtocol(protocol)
	return p == protocolResponses || p == protocolChatCompletions || p == protocolGenAI
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
	rawHost := strings.ToLower(parsed.Hostname())
	cleanHost := strings.TrimRight(rawHost, ".")
	if cleanHost == "" {
		return nil, errors.New("base_url must be an absolute http(s) URL")
	}
	if cleanHost == "metadata.google.internal" || cleanHost == "instance-data" || cleanHost == "metadata" || (strings.HasSuffix(cleanHost, ".internal") && strings.Contains(cleanHost, "metadata")) {
		return nil, errors.New("base_url must not target cloud metadata endpoints")
	}
	baseHost, zone, hasZone := strings.Cut(cleanHost, "%")
	if hasZone && (baseHost == "" || zone == "") {
		return nil, errors.New("base_url contains invalid IPv6 zone")
	}
	if addr, addrErr := netip.ParseAddr(baseHost); addrErr == nil {
		unmapped := addr.Unmap()
		if hasZone || unmapped.IsUnspecified() || unmapped.IsMulticast() || unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() || isCloudMetadataAddr(unmapped) {
			return nil, errors.New("base_url must not target link-local, unspecified, multicast, or metadata addresses")
		}
	} else if hasNonStandardNumericIP(cleanHost) {
		return nil, errors.New("base_url must not use non-standard numeric IP representations")
	}
	// Do not clean or discard provider-specific path segments.
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return parsed, nil
}

func isCloudMetadataAddr(addr netip.Addr) bool {
	// Alibaba Cloud ECS metadata (100.100.100.200) and AWS EC2 IPv6 IMDS (fd00:ec2::254).
	return addr == netip.MustParseAddr("100.100.100.200") || addr == netip.MustParseAddr("fd00:ec2::254")
}

func hasNonStandardNumericIP(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		if _, err := strconv.ParseUint(label, 0, 64); err == nil {
			continue
		}
		allDigits := true
		for i := 0; i < len(label); i++ {
			if label[i] < '0' || label[i] > '9' {
				allDigits = false
				break
			}
		}
		if !allDigits {
			return false
		}
	}
	return true
}

func protocolSupportsPath(protocol, path string) bool {
	pathOnly, _, _ := strings.Cut(path, "?")
	p := effectiveProtocol(protocol)
	if pathOnly == "/v1/responses" {
		return p == protocolResponses
	}
	if p == protocolGenAI {
		return pathOnly == "/v1/chat/completions" || pathOnly == "/v1/models" || pathOnly == "/models"
	}
	return true
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
	protocol := effectiveProtocol(server.cfg.UpstreamProtocol)
	if key != nil {
		protocol = effectiveProtocol(key.APIProtocol)
	}
	raw := server.cfg.UpstreamURL.String()
	if protocol == protocolGenAI && (server.cfg.UpstreamURL == nil || server.cfg.UpstreamProtocol != protocolGenAI) {
		raw = DefaultGenAIBaseURL
	}
	profile := server.cfg.Profile
	if key != nil {
		if key.BaseURL != "" {
			raw = key.BaseURL
		} else if protocol == protocolGenAI {
			raw = DefaultGenAIBaseURL
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
	if protocol == protocolGenAI {
		if !protocolSupportsPath(protocolGenAI, path) {
			return "", nil, nil, errNoCompatibleUpstream
		}
		return path, body, nil, nil
	}
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
