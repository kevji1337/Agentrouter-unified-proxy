package app

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFaviconPublicWithGatewayAuthentication(t *testing.T) {
	gateway := multiUpstreamProxy(t, "http://127.0.0.1:1")
	gateway.cfg.ProxyAuthToken = "fixture-proxy-token"
	gateway.cfg.AdminAccounts = []adminAccount{{Name: "owner", Role: "admin", Token: "favicon-admin-fixture-token"}}
	if _, _, err := gateway.keys.createClientKey("Browser test"); err != nil {
		t.Fatal(err)
	}
	handler := gateway.routes()
	for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+path, func(t *testing.T) {
				req := httptest.NewRequest(method, path, nil)
				id := "favicon-fixture-" + method + path
				req.Header.Set("X-Request-ID", id)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
				}
				want, mime := faviconICO, "image/vnd.microsoft.icon"
				if path == "/favicon.svg" {
					want, mime = faviconSVG, "image/svg+xml"
				}
				if rec.Header().Get("Content-Type") != mime || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "public, max-age=86400" {
					t.Fatal("incorrect asset headers")
				}
				if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), want) {
					t.Fatal("incorrect embedded asset")
				}
				if method == http.MethodHead && (rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "") {
					t.Fatal("HEAD must return metadata without body")
				}
				for _, entry := range adminLogRing.recent(0, 200) {
					if entry["request_id"] == id {
						t.Fatal("successful favicon generated log noise")
					}
				}
			})
		}
	}
	for _, path := range []string{"/v1/models", "/v1/chat/completions", "/api/admin/keys", "/favicon.ico/private", "/favicon.svg/private"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s bypassed authentication: %d", path, rec.Code)
		}
	}
}

func TestFaviconUnsupportedMethods(t *testing.T) {
	gateway := multiUpstreamProxy(t, "http://127.0.0.1:1")
	for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
		rec := httptest.NewRecorder()
		gateway.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("unsupported method accepted")
		}
	}
}

func TestFaviconAssetsAndHTMLLinks(t *testing.T) {
	// The legacy ICO is a real PNG-backed icon, not SVG served with an ICO MIME.
	if len(faviconICO) < 22 || binary.LittleEndian.Uint16(faviconICO[2:4]) != 1 || binary.LittleEndian.Uint16(faviconICO[4:6]) != 1 {
		t.Fatal("invalid ICO directory")
	}
	offset := int(binary.LittleEndian.Uint32(faviconICO[18:22]))
	size := int(binary.LittleEndian.Uint32(faviconICO[14:18]))
	if offset != 22 || offset+size != len(faviconICO) {
		t.Fatal("invalid ICO entry bounds")
	}
	img, err := png.Decode(bytes.NewReader(faviconICO[offset:]))
	if err != nil || img.Bounds().Dx() != 32 || img.Bounds().Dy() != 32 {
		t.Fatalf("invalid favicon image: %v", err)
	}
	var svg struct {
		XMLName xml.Name
		ViewBox string `xml:"viewBox,attr"`
	}
	if err := xml.Unmarshal(faviconSVG, &svg); err != nil || svg.XMLName.Local != "svg" || svg.ViewBox != "0 0 32 32" {
		t.Fatal("invalid SVG asset")
	}
	for _, html := range []string{adminDashboardHTML, apiDocsHTML} {
		if !strings.Contains(html, `rel="icon" type="image/svg+xml" href="/favicon.svg"`) || !strings.Contains(html, `href="/favicon.ico"`) {
			t.Fatal("page does not declare local favicon")
		}
	}
}
