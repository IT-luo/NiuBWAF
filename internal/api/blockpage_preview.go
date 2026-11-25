package api

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"niubwaf/internal/proxy"
)

const blockPreviewPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

func (a *API) previewBlockPage(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Template string `json:"template"`
	}
	if r.Method == http.MethodPost && !decodeJSON(w, r, &input, jsonBodyLimit) {
		return
	}
	page := proxy.RenderBlockPage(input.Template, map[string]string{
		"REQ_ID": "7f2c4d91a638", "REASON": "站点访问策略限制",
		"CLIENT_IP": "192.0.2.10", "DOMAIN": "app.example",
		"TIME": time.Now().Format("2006-01-02 15:04:05"), "RULE_ID": "949110",
	})
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", blockPreviewPolicy+"; frame-ancestors 'none'")
		_, _ = io.WriteString(w, page)
		return
	}
	preview, err := isolateBlockPreview(page)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "无法生成拦截页预览")
		return
	}
	writeJSON(w, map[string]string{"html": preview})
}

func isolateBlockPreview(page string) (string, error) {
	doc, err := html.ParseWithOptions(strings.NewReader(page), html.ParseOptionEnableScripting(false))
	if err != nil {
		return "", err
	}
	removePreviewNavigation(doc)
	for node := range doc.Descendants() {
		if node.DataAtom != atom.Head {
			continue
		}
		node.InsertBefore(&html.Node{
			Type: html.ElementNode, Data: "meta", DataAtom: atom.Meta,
			Attr: []html.Attribute{{Key: "http-equiv", Val: "Content-Security-Policy"}, {Key: "content", Val: blockPreviewPolicy}},
		}, node.FirstChild)
		break
	}
	var preview bytes.Buffer
	if err := html.Render(&preview, doc); err != nil {
		return "", err
	}
	return preview.String(), nil
}

// Sandbox and CSP block scripts and subresources. Strip links and refresh directives
// so a preview also stays on its own document when a user clicks inside it.
func removePreviewNavigation(node *html.Node) {
	for child := node.FirstChild; child != nil; {
		next := child.NextSibling
		if child.Type == html.ElementNode {
			switch strings.ToLower(child.Data) {
			case "base", "link", "script", "iframe", "frame", "frameset", "object", "embed", "portal", "fencedframe",
				"animate", "animatemotion", "animatetransform", "set", "discard":
				node.RemoveChild(child)
			case "meta":
				for _, attr := range child.Attr {
					if attr.Key == "http-equiv" {
						node.RemoveChild(child)
						break
					}
				}
			default:
				attrs := child.Attr[:0]
				for _, attr := range child.Attr {
					if attr.Key != "href" && !strings.HasPrefix(attr.Key, "on") {
						attrs = append(attrs, attr)
					}
				}
				child.Attr = attrs
				removePreviewNavigation(child)
			}
		}
		child = next
	}
}
