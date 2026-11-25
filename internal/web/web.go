package web

import "embed"

//go:embed index.html app.js style.css screen.html echarts.min.js topojson-client.min.js world-110m.js china-standard-gs2023-2762.jpg
var FS embed.FS
