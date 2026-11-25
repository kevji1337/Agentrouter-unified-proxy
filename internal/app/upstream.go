package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	protocolResponses       = "responses"
	protocolChatCompletions = "chat-completions"
	protocolGenAI           = "genai"
	protocolAnthropic       = "anthropic"

	DefaultGenAIBaseURL     = "https://generativelanguage.googleapis.com"
	DefaultAnthropicBaseURL = "https://api.anthropic.com"
	DefaultAnthropicVersion = "2023-06-01"
)

var errNoCompatibleUpstream = errors.New("no available upstream supports the requested API protocol and model")
var errInvalidUpstreamRequest = errors.New("request cannot be converted to upstream API format")
var errDNSRebindingBlocked = errors.New("upstream resolved to disallowed IP address")

type ipLookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// An absent protocol preserves the behavior of existing v1/v2 stores.
func effectiveProtocol(protocol string) string {
	if protocol == "" {
		return protocolResponses
	}
	return protocol
}

func validProtocol(protocol string) bool {
	p := effectiveProtocol(protocol)
	return p == protocolResponses || p == protocolChatCompletions || p == protocolGenAI || p == protocolAnthropic
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

func isAlwaysBlockedDialAddr(addr netip.Addr) bool {
	unmapped := addr.Unmap()
	return !unmapped.IsValid() ||
		addr.Zone() != "" ||
		unmapped.IsUnspecified() ||
		unmapped.IsMulticast() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() ||
		isCloudMetadataAddr(unmapped)
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func isPrivateOrCarrierAddr(addr netip.Addr) bool {
	unmapped := addr.Unmap()
	return unmapped.IsPrivate() || cgnatPrefix.Contains(unmapped)
}

func isMetadataHostname(cleanHost string) bool {
	return cleanHost == "metadata.google.internal" ||
		cleanHost == "instance-data" ||
		cleanHost == "metadata" ||
		(strings.HasSuffix(cleanHost, ".internal") && strings.Contains(cleanHost, "metadata"))
}

func (server *proxyServer) isAllowlistedHost(cleanHost string) bool {
	if server == nil || len(server.cfg.AllowedUpstreamOrigins) == 0 {
		return false
	}
	for _, origin := range server.cfg.AllowedUpstreamOrigins {
		parsed, err := url.Parse(origin)
		if err != nil {
			continue
		}
		if strings.TrimRight(strings.ToLower(parsed.Hostname()), ".") == cleanHost {
			return true
		}
	}
	return false
}

// newSafeDialContext resolves hostnames once per connection attempt, rejects
// metadata/link-local/unspecified/multicast targets and DNS-rebinding to
// loopback (or private ranges when BlockPrivateUpstreamIPs is enabled), and
// dials the validated IP literal directly so the OS cannot perform a second
// unvalidated DNS lookup (TOCTOU).
func (server *proxyServer) newSafeDialContext(baseDialer *net.Dialer, lookup ipLookupFunc) func(ctx context.Context, network, address string) (net.Conn, error) {
	if baseDialer == nil {
		baseDialer = &net.Dialer{}
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		cleanHost := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
		if cleanHost == "" || strings.Contains(cleanHost, "%") || isMetadataHostname(cleanHost) {
			return nil, errDNSRebindingBlocked
		}
		allowlisted := server.isAllowlistedHost(cleanHost)
		blockPrivate := server != nil && server.cfg.BlockPrivateUpstreamIPs && !allowlisted

		if literal, parseErr := netip.ParseAddr(cleanHost); parseErr == nil {
			unmapped := literal.Unmap()
			if isAlwaysBlockedDialAddr(literal) {
				return nil, errDNSRebindingBlocked
			}
			if blockPrivate && (unmapped.IsLoopback() || isPrivateOrCarrierAddr(unmapped)) {
				return nil, errDNSRebindingBlocked
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(unmapped.String(), port))
		}
		if hasNonStandardNumericIP(cleanHost) {
			return nil, errDNSRebindingBlocked
		}

		ipNetwork := "ip"
		switch network {
		case "tcp4":
			ipNetwork = "ip4"
		case "tcp6":
			ipNetwork = "ip6"
		}
		resolved, err := lookup(ctx, ipNetwork, cleanHost)
		if err != nil {
			return nil, err
		}
		if len(resolved) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host}
		}

		allowLoopback := cleanHost == "localhost" || strings.HasSuffix(cleanHost, ".localhost") || allowlisted
		validAddrs := make([]netip.Addr, 0, len(resolved))
		for _, candidate := range resolved {
			unmapped := candidate.Unmap()
			if isAlwaysBlockedDialAddr(candidate) {
				return nil, errDNSRebindingBlocked
			}
			if unmapped.IsLoopback() && !allowLoopback {
				return nil, errDNSRebindingBlocked
			}
			if blockPrivate && (unmapped.IsLoopback() || isPrivateOrCarrierAddr(unmapped)) {
				return nil, errDNSRebindingBlocked
			}
			validAddrs = append(validAddrs, unmapped)
		}

		var lastErr error
		for _, addr := range validAddrs {
			conn, dialErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, lastErr
	}
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
	if pathOnly == "/v1/messages" {
		return true
	}
	if pathOnly == "/v1/messages/count_tokens" {
		return p == protocolAnthropic
	}
	if p == protocolGenAI || p == protocolAnthropic {
		return pathOnly == "/v1/chat/completions" || pathOnly == "/v1/models" || pathOnly == "/models"
	}
	return true
}

func defaultBaseURLForProtocol(protocol string) string {
	switch effectiveProtocol(protocol) {
	case protocolGenAI:
		return DefaultGenAIBaseURL
	case protocolAnthropic:
		return DefaultAnthropicBaseURL
	default:
		return ""
	}
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
	if defURL := defaultBaseURLForProtocol(protocol); defURL != "" && (server.cfg.UpstreamURL == nil || server.cfg.UpstreamProtocol != protocol) {
		raw = defURL
	}
	profile := server.cfg.Profile
	if key != nil {
		if key.BaseURL != "" {
			raw = key.BaseURL
		} else if defURL := defaultBaseURLForProtocol(protocol); defURL != "" {
			raw = defURL
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
	pathOnly, _, _ := strings.Cut(path, "?")
	if pathOnly == "/v1/messages" {
		return server.prepareAnthropicInbound(body, protocol)
	}
	if protocol == protocolGenAI {
		if !protocolSupportsPath(protocolGenAI, path) {
			return "", nil, nil, errNoCompatibleUpstream
		}
		return path, body, nil, nil
	}
	if protocol == protocolAnthropic {
		if !protocolSupportsPath(protocolAnthropic, path) {
			return "", nil, nil, errNoCompatibleUpstream
		}
		if pathOnly == "/v1/chat/completions" {
			converted, meta, err := convertChatToAnthropicRequest(body)
			if err != nil {
				return "", nil, nil, fmt.Errorf("%w: %v", errInvalidUpstreamRequest, err)
			}
			return "/v1/messages", converted, &meta, nil
		}
		return path, body, nil, nil
	}
	if pathOnly == "/v1/responses" && protocol != protocolResponses {
		return "", nil, nil, errNoCompatibleUpstream
	}
	if pathOnly != "/v1/chat/completions" || protocol == protocolChatCompletions {
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
	meta.UpstreamFormat = "responses"
	return "/v1/responses", converted, &meta, nil
}
