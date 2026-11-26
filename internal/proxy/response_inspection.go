package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"niubwaf/internal/engine"
	"niubwaf/internal/metrics"
)

// errResponseInspectionBlocked tells ReverseProxy to close the upstream body
// without forwarding any of its headers, including on an upgrade handshake.
var errResponseInspectionBlocked = errors.New("response blocked by WAF")

func responseMediaType(headers http.Header) string {
	values := headers.Values("Content-Type")
	if len(values) != 1 {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return ""
	}
	return mediaType
}

// responseBodyInspectionSkip reports why only the response headers are inspected.
func responseBodyInspectionSkip(method string, resp *http.Response, mediaType, encoding string) string {
	switch {
	case resp.StatusCode == http.StatusSwitchingProtocols || mediaType == "text/event-stream":
		return "stream"
	case method == http.MethodHead || resp.Body == nil || resp.ContentLength == 0 ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified:
		return "no_body"
	case resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "":
		return "range"
	}
	switch mediaType {
	case "text/plain", "text/html", "text/xml", "application/xml", "application/json":
	default:
		return "media_type"
	}
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		return "encoding"
	}
	return ""
}

// readResponseInspectionBody bounds both compressed input and decoded output.
// Replay the original wire prefix so successful responses keep their bytes,
// content encoding, length, and remaining stream.
func readResponseInspectionBody(resp *http.Response, encoding string, limit int) ([]byte, string, error) {
	inputLimit := limit
	if encoding == "gzip" {
		inputLimit = max(limit+1024, 32<<10)
	}
	original := resp.Body
	wire, err := io.ReadAll(io.LimitReader(original, int64(inputLimit)+1))
	if err != nil {
		return nil, "read_error", err
	}
	resp.Body = &multiReadCloser{io.MultiReader(bytes.NewReader(wire), original), original}
	partialInput := len(wire) > inputLimit
	if encoding != "gzip" {
		if partialInput {
			return wire[:limit], "partial", nil
		}
		return wire, "complete", nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(wire))
	if err != nil {
		if partialInput && errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, "partial", nil
		}
		return nil, "decode_error", nil
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil && !(partialInput && errors.Is(err, io.ErrUnexpectedEOF)) {
		return decoded[:min(len(decoded), limit)], "decode_error", nil
	}
	if partialInput || len(decoded) > limit {
		return decoded[:min(len(decoded), limit)], "partial", nil
	}
	return decoded, "complete", nil
}

func (p *Proxy) inspectUpstreamResponse(r *http.Request, site *cachedSite, req *engine.RequestInfo, resp *http.Response) (engine.Result, error) {
	mediaType := responseMediaType(resp.Header)
	encoding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	coverage := responseBodyInspectionSkip(r.Method, resp, mediaType, encoding)
	headers := resp.Header
	var readBody func() ([]byte, error)
	var readErr error
	if coverage == "" {
		// Coraza compares the MIME type literally. Normalize its input while
		// retaining Content-Type parameters and all of the upstream wire headers.
		rawType, params, hasParams := strings.Cut(headers.Get("Content-Type"), ";")
		if rawType != mediaType {
			headers = headers.Clone()
			if hasParams {
				params = ";" + params
			}
			headers.Set("Content-Type", mediaType+params)
		}
		coverage = "engine_error"
		readBody = func() ([]byte, error) {
			var body []byte
			body, coverage, readErr = readResponseInspectionBody(resp, encoding, p.Engine.ScanLimit())
			return body, readErr
		}
	}
	result, err := p.Engine.DetectResponse(site.WAFMode, site.excl, req, resp.StatusCode, headers, readBody)
	switch {
	case result.Blocked:
		coverage = "blocked"
	case readErr != nil:
		coverage = "read_error"
	case err != nil:
		coverage = "engine_error"
	}
	metrics.Default.IncResponseInspection(coverage)
	return result, readErr
}

func (p *Proxy) injectDynamicResponse(resp *http.Response, r *http.Request, ip string, siteID int64) error {
	const limit = 5 << 20
	if responseMediaType(resp.Header) != "text/html" ||
		responseBodyInspectionSkip(r.Method, resp, "text/html", "") != "" ||
		resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > limit {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if len(body) > limit {
		resp.Body = &multiReadCloser{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	body = p.injectDynamic(body, ip, siteID)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	return nil
}
