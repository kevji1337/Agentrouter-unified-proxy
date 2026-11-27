package assets

import _ "embed"

//go:embed admin.html
var adminDashboardHTML string

//go:embed openapi.json
var openAPISpec []byte

//go:embed docs.html
var apiDocsHTML string

//go:embed favicon.svg
var faviconSVG []byte

//go:embed favicon.ico
var faviconICO []byte

//go:noinline
func AdminDashboardHTML() string { return adminDashboardHTML }

//go:noinline
func OpenAPISpec() []byte { return openAPISpec }

//go:noinline
func APIDocsHTML() string { return apiDocsHTML }

//go:noinline
func FaviconSVG() []byte { return faviconSVG }

//go:noinline
func FaviconICO() []byte { return faviconICO }
