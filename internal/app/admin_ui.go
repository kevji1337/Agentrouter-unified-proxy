package app

import "agentrouter-unified-proxy/internal/app/assets"

var (
	adminDashboardHTML = assets.AdminDashboardHTML()
	openAPISpec        = assets.OpenAPISpec()
	apiDocsHTML        = assets.APIDocsHTML()
	faviconSVG         = assets.FaviconSVG()
	faviconICO         = assets.FaviconICO()
)
