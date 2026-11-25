package apispec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const MaxDocumentBytes = 512 << 10

type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Name   string `json:"name,omitempty"`
}

type Policy struct {
	Mode      string
	Prefix    string
	Endpoints []Endpoint
	router    routers.Router
}

// Compile builds an immutable policy. OpenAPI paths are matched against the
// ingress URL of the associated site, independently of example server URLs.
func Compile(ctx context.Context, mode, prefix, document string) (*Policy, error) {
	prefix = strings.TrimSpace(prefix)
	switch mode {
	case "off", "observe", "block":
	default:
		return nil, fmt.Errorf("模式须为 off、observe 或 block")
	}
	u, err := url.ParseRequestURI(prefix)
	if err != nil || u.Path != prefix || u.RawQuery != "" || prefix != path.Clean(prefix) ||
		!strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "\\%{}") {
		return nil, fmt.Errorf("校验范围须为绝对路径，例如 /api")
	}
	p := &Policy{Mode: mode, Prefix: prefix, Endpoints: []Endpoint{}}
	if mode == "off" && strings.TrimSpace(document) == "" {
		return p, nil
	}
	if len(document) == 0 || len(document) > MaxDocumentBytes {
		return nil, fmt.Errorf("OpenAPI 文档大小须在 1 字节至 512 KiB 之间")
	}
	loader := openapi3.NewLoader()
	loader.Context = ctx
	doc, err := loader.LoadFromData([]byte(document))
	if err != nil {
		return nil, fmt.Errorf("无法读取 OpenAPI 文档: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.0.") && !strings.HasPrefix(doc.OpenAPI, "3.1.") {
		return nil, fmt.Errorf("请上传 OpenAPI 3.0 或 3.1 文档")
	}
	if doc.Paths == nil {
		return nil, fmt.Errorf("OpenAPI 文档没有接口路径")
	}
	doc.Servers = nil
	for name, item := range doc.Paths.Map() {
		if item == nil {
			return nil, fmt.Errorf("路径 %q 缺少定义", name)
		}
		item.Servers = nil
		for method, operation := range item.Operations() {
			if operation == nil || !inScope(prefix, name) {
				continue
			}
			p.Endpoints = append(p.Endpoints, Endpoint{Method: method, Path: name, Name: operation.OperationID})
		}
	}
	if len(p.Endpoints) == 0 || len(p.Endpoints) > 1000 {
		return nil, fmt.Errorf("校验范围内须有 1–1000 个接口")
	}
	sort.Slice(p.Endpoints, func(i, j int) bool {
		if p.Endpoints[i].Path != p.Endpoints[j].Path {
			return p.Endpoints[i].Path < p.Endpoints[j].Path
		}
		return p.Endpoints[i].Method < p.Endpoints[j].Method
	})
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("OpenAPI 文档校验失败: %w", err)
	}
	p.router, err = gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("无法建立 API 路由: %w", err)
	}
	return p, nil
}

func inScope(prefix, candidate string) bool {
	return prefix == "/" || candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

var requestOptions = openapi3filter.Options{
	AuthenticationFunc:                openapi3filter.NoopAuthenticationFunc,
	SkipSettingDefaults:               true,
	RejectWhenRequestBodyNotSpecified: true,
}

// Check returns a safe diagnostic without retaining values from the request.
func (p *Policy) Check(r *http.Request, body []byte) string {
	if p == nil || p.Mode == "off" || (!inScope(p.Prefix, r.URL.Path) && !inScope(p.Prefix, path.Clean(r.URL.Path))) {
		return ""
	}
	route, params, err := p.router.FindRoute(r)
	if err != nil {
		return "接口路径或请求方法未登记"
	}
	for key, value := range params {
		decoded, err := url.PathUnescape(value)
		if err != nil {
			return "接口路径参数的编码无效"
		}
		params[key] = decoded
	}
	req := r.Clone(r.Context())
	if len(body) == 0 {
		req.Body = http.NoBody
		req.GetBody = nil
	} else {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	input := &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route, Options: &requestOptions}
	if err := openapi3filter.ValidateRequest(req.Context(), input); err != nil {
		return "请求参数或请求体不符合接口契约"
	}
	return ""
}
