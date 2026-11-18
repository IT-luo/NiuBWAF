package web

import "embed"

//go:embed index.html app.js style.css screen.html echarts.min.js
var FS embed.FS