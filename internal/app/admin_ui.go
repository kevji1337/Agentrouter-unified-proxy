package app

import _ "embed"

//go:embed assets/admin.html
var adminDashboardHTML string

//go:embed assets/openapi.json
var openAPISpec []byte

//go:embed assets/docs.html
var apiDocsHTML string
