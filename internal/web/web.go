package web

import (
	"embed"
	"encoding/base64"
)

//go:embed index.html app.js style.css screen.html echarts.min.js topojson-client.min.js world-110m.js china-standard-gs2023-2762.jpg
//go:embed brand-logo.png brand-icon.svg favicon.ico
var FS embed.FS

//go:embed brand-icon.svg
var brandIcon []byte

var brandIconDataURI = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(brandIcon)

// BrandIconDataURI returns the embedded mark for pages served on protected sites.
func BrandIconDataURI() string {
	return brandIconDataURI
}
