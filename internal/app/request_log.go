package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
)

type requestLogContextKey struct{}

// One request-owned, secret-free snapshot. A response body/usage callback may
// update it concurrently with cancellation; never store keys, headers or bodies.
type requestLog struct {
	mu     sync.Mutex
	fields map[string]any
}

func requestLogFromContext(ctx context.Context) *requestLog {
	value, _ := ctx.Value(requestLogContextKey{}).(*requestLog)
	return value
}

func (record *requestLog) set(fields map[string]any) {
	if record == nil {
		return
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	for key, value := range fields {
		record.fields[key] = value
	}
}

// Generic response errors must not erase a more precise transport diagnosis.
func (record *requestLog) responseError(code string) {
	if record == nil {
		return
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if old, _ := record.fields["error_code"].(string); old != "" && (code == "upstream_error" || code == "conversion_error") {
		return
	}
	record.fields["error_code"] = code
}

func (record *requestLog) snapshot() map[string]any {
	result := make(map[string]any)
	if record == nil {
		return result
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	for key, value := range record.fields {
		result[key] = value
	}
	return result
}

func (record *requestLog) attempt(route map[string]any) {
	if record == nil {
		return
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	count, _ := record.fields["attempts"].(int)
	record.fields["attempts"] = count + 1
	for key, value := range route {
		record.fields[key] = value
	}
}

func logRequestEvent(ctx context.Context, level, event string, fields map[string]any) {
	record := requestLogFromContext(ctx).snapshot()
	record["request_id"] = requestIDFromContext(ctx)
	for key, value := range fields {
		record[key] = value
	}
	logEvent(level, event, record)
}

func providerLogName(key *selectedAPIKey) string {
	if key == nil {
		return "Default upstream"
	}
	if key.ProviderName != "" {
		return key.ProviderName
	}
	return "Legacy endpoint"
}
func networkRouteLogName(key *selectedAPIKey) string {
	if key != nil && key.NetworkProxy != nil {
		if key.NetworkProxy.Name != "" {
			return key.NetworkProxy.Name
		}
		return key.NetworkProxy.ID
	}
	if key != nil && key.ProxyMode == "direct" {
		return "Direct"
	}
	return "Environment / default transport"
}

func safeRouteFields(key *selectedAPIKey, base *url.URL, protocol string) map[string]any {
	fields := map[string]any{"provider": providerLogName(key), "provider_id": "", "key_name": "Inbound / anonymous", "key_id": "", "key_mask": "", "network_route": networkRouteLogName(key), "proxy_id": "", "upstream_host": base.Host, "upstream_protocol": protocol}
	if key != nil {
		fields["key_id"], fields["key_name"], fields["key_mask"], fields["provider_id"] = key.ID, key.Name, key.Mask, key.ProviderID
		if key.NetworkProxy != nil {
			fields["proxy_id"] = key.NetworkProxy.ID
		}
	}
	return fields
}

// Classify without err.Error(): transport errors can include proxy userinfo,
// URL queries or credentials. Codes are deliberately bounded and non-sensitive.
func requestFailureCode(err error) string {
	switch {
	case errors.Is(err, errNoEnabledAPIKeys):
		return "no_enabled_api_keys"
	case errors.Is(err, errNoCompatibleUpstream):
		return "no_compatible_upstream"
	case errors.Is(err, errNetworkProxyUnavailable):
		return "network_proxy_unavailable"
	case errors.Is(err, errInvalidUpstreamRequest):
		return "invalid_request"
	case errors.Is(err, errUpstreamIdleTimeout):
		return "upstream_idle_timeout"
	case errors.Is(err, context.Canceled):
		return "request_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "upstream_timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns_error"
	}
	var certificate *url.Error
	if errors.As(err, &certificate) {
		err = certificate.Err
	}
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &unknownAuthority) || errors.As(err, &invalidCertificate) || errors.As(err, &hostname) {
		return "tls_error"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "upstream_timeout"
	}
	var network *net.OpError
	if errors.As(err, &network) {
		return "connection_error"
	}
	return "upstream_error"
}

type loggedResponseBody struct {
	io.ReadCloser
	ctx  context.Context
	once sync.Once
}

func (body *loggedResponseBody) Read(buffer []byte) (int, error) {
	n, err := body.ReadCloser.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		body.once.Do(func() {
			code := requestFailureCode(err)
			requestLogFromContext(body.ctx).set(map[string]any{"error_code": code, "response_interrupted": true})
			logRequestEvent(body.ctx, "error", "upstream_response_interrupted", map[string]any{"error_code": code})
		})
	}
	return n, err
}

func requestLogLevel(status int, fields map[string]any) string {
	if fields["error_code"] != "" && fields["error_code"] != nil && status < 400 {
		return "warn"
	}
	if status >= 500 {
		return "error"
	}
	if status >= 400 {
		return "warn"
	}
	return "info"
}

func logCategory(event string) string {
	switch event {
	case "request_completed":
		return "requests"
	case "api_key_failover", "upstream_transport_retry", "upstream_status_retry", "waf_block_retry", "azure_resource_state_retry", "no_available_api_keys":
		return "routing"
	case "tool_call_emitted", "parallel_tools_suppressed", "invalid_streamed_tool_arguments":
		return "tools"
	case "sse_conversion_failed", "upstream_response_interrupted":
		return "requests"
	}
	if len(event) >= 6 && event[:6] == "admin_" {
		return "admin"
	}
	return "system"
}

func logIsBackground(event string, fields map[string]any) bool {
	if level := logValue(fields, "level"); level == "warn" || level == "error" {
		return false
	}
	switch event {
	case "tool_call_emitted", "key_health_completed", "waf_warmup_succeeded":
		return true
	case "request_completed":
		path, _ := fields["path"].(string)
		return (fields["method"] == http.MethodGet && len(path) >= 11 && path[:11] == "/api/admin/") || path == "/v1/models" || path == "/models" || path == "/admin" || path == "/docs" || path == "/openapi.json"
	}
	return false
}

func logValue(fields map[string]any, key string) string {
	if value, ok := fields[key]; ok && value != nil {
		return fmt.Sprint(value)
	}
	return ""
}

func failureExplanation(code string) string {
	switch code {
	case "no_enabled_api_keys":
		return "Нет доступного ключа: проверьте Enabled, модели, cooldown и лимиты"
	case "no_compatible_upstream":
		return "Нет доступного провайдера с нужной моделью и API-протоколом"
	case "network_proxy_unavailable":
		return "Назначенный сетевой прокси отключён или отсутствует; прямой выход запрещён"
	case "proxy_auth_required":
		return "Клиентский ключ доступа к gateway отсутствует или невалиден"
	case "network_proxy_auth":
		return "Сетевой прокси отклонил логин/пароль; API-ключ провайдера не признан невалидным"
	case "upstream_idle_timeout":
		return "Upstream перестал передавать данные: истёк idle timeout"
	case "upstream_timeout":
		return "Истекло время ожидания upstream или сетевого прокси"
	case "request_canceled":
		return "Запрос отменён клиентом или при остановке сервера"
	case "dns_error":
		return "Не удалось разрешить адрес сервера или прокси через DNS"
	case "tls_error":
		return "Не прошла проверка TLS-сертификата сервера или прокси"
	case "connection_error":
		return "Ошибка сетевого соединения с upstream или прокси"
	case "client_write_failed":
		return "Не удалось отправить ответ клиенту: соединение закрыто"
	case "invalid_request":
		return "Запрос невалиден или несовместим с выбранным API-протоколом"
	case "conversion_error":
		return "Ошибка преобразования ответа Responses в Chat Completions"
	case "upstream_error":
		return "Запрос к upstream не выполнен; проверьте выбранный endpoint и сетевой маршрут"
	}
	return code
}

// Machine event names stay unchanged for JSON consumers and Telegram alerts.
// Human summaries are additive and contain only already-approved log fields.
func logSummary(event string, fields map[string]any) string {
	value := func(key string) string { return logValue(fields, key) }
	switch event {
	case "request_completed":
		result := fmt.Sprintf("%s %s → HTTP %s · %s мс", value("method"), value("path"), value("status"), value("duration_ms"))
		if code := value("error_code"); code != "" {
			result += " — " + failureExplanation(code)
		} else {
			reasons := map[string]string{"401": "upstream отклонил API-ключ", "402": "upstream требует оплату или исчерпан баланс", "403": "upstream запретил доступ", "404": "endpoint или ресурс не найден", "429": "upstream ограничил частоту запросов", "500": "ошибка upstream", "502": "ошибка upstream", "503": "upstream недоступен", "504": "upstream не ответил вовремя"}
			if reason := reasons[value("status")]; reason != "" {
				result += " — " + reason
			}
		}
		if value("response_interrupted") == "true" {
			result += " (статус уже отправлен, ответ прерван)"
		}
		return result
	case "api_key_failover":
		return fmt.Sprintf("HTTP %s: переключение %s / %s → %s / %s", value("status"), value("failed_provider"), value("failed_key_name"), value("next_provider"), value("next_key_name"))
	case "upstream_transport_retry":
		return fmt.Sprintf("Сетевой повтор %s/%s: %s", value("attempt"), value("max_retries"), failureExplanation(value("error_code")))
	case "upstream_status_retry":
		return fmt.Sprintf("Upstream HTTP %s: повтор %s/%s по retry-политике", value("status"), value("attempt"), value("max_retries"))
	case "parallel_tools_suppressed":
		return fmt.Sprintf("Upstream прислал %s инструментов, передан %s: включён последовательный режим", value("returned"), value("forwarded"))
	case "tool_call_emitted":
		return fmt.Sprintf("Передан инструмент %s · аргументы: %s байт", value("tool"), value("arguments_length"))
	case "invalid_streamed_tool_arguments":
		return "Инструмент " + value("tool") + ": некорректный JSON аргументов заменён на {}"
	case "upstream_response_interrupted":
		return "Ответ upstream прерван: " + failureExplanation(value("error_code"))
	case "key_health_completed":
		return fmt.Sprintf("Проверка ключей: %s проверено · %s принято · %s ошибок · %s не подтверждено", value("checked"), value("accepted"), value("failed"), value("inconclusive"))
	case "key_health_failed":
		return fmt.Sprintf("Проверка %s / %s: HTTP %s — %s", value("provider"), value("key_name"), value("status"), value("reason"))
	case "admin_password_changed":
		return "Пароль администратора изменён; предыдущие сессии отозваны"
	case "admin_key_updated":
		summary := "API-ключ обновлён: " + value("name")
		if value("credential_replaced") == "true" {
			summary += " · credential заменён"
		}
		return summary
	}
	labels := map[string]string{
		"waf_block_retry":            "WAF заблокировал запрос; обновляем cookie через тот же маршрут и повторяем один раз",
		"azure_resource_state_retry": "Azure отклонил чужой resource state; повторяем stateless-запрос",
		"no_available_api_keys":      failureExplanation("no_enabled_api_keys"),
		"sse_conversion_failed":      "Ошибка преобразования Responses SSE в Chat Completions",
		"waf_warmup_succeeded":       "WAF-cookie обновлены", "waf_warmup_no_cookie": "Проверка WAF завершена без cookie",
		"admin_login": "Вход администратора", "admin_routing_mode_changed": "Режим выбора ключей изменён",
		"admin_key_added": "Добавлен API-ключ", "admin_key_policy_updated": "Изменена политика API-ключа", "admin_key_deleted": "Удалён API-ключ",
		"admin_provider_saved": "Сохранён провайдер и модели", "admin_provider_deleted": "Удалён провайдер",
		"admin_network_proxy_created": "Добавлен сетевой прокси; привязки перераспределены",
		"admin_network_proxy_updated": "Изменён сетевой прокси", "admin_network_proxy_deleted": "Удалён сетевой прокси",
		"admin_backup_imported": "Импортирована резервная копия", "admin_client_key_created": "Создан клиентский ключ доступа",
		"admin_client_key_revealed": "Администратор раскрыл клиентский ключ", "admin_client_key_updated": "Изменён клиентский ключ доступа",
		"admin_client_key_deleted": "Удалён клиентский ключ доступа", "proxy_listening": "Gateway запущен",
		"postgres_unavailable": "PostgreSQL недоступен", "redis_unavailable": "Redis недоступен",
	}
	if label := labels[event]; label != "" {
		return label
	}
	return event
}
