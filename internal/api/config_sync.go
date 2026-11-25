package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"niubwaf/internal/store"
)

const configSyncWrapperLimit = store.MaxConfigPackageBytes + 64<<10

type configExportRequest struct {
	SourceLabel string `json:"source_label"`
}

type configImportPreviewRequest struct {
	Package store.ConfigPackage `json:"package"`
	Mode    string              `json:"mode"`
}

type configImportApplyRequest struct {
	Package        store.ConfigPackage `json:"package"`
	Mode           string              `json:"mode"`
	PackageSHA256  string              `json:"package_sha256"`
	TargetSHA256   string              `json:"target_sha256"`
	PreviewSHA256  string              `json:"preview_sha256"`
	ConfirmDeletes int                 `json:"confirm_deletes"`
}

type configImportApplyResponse struct {
	OK      bool                      `json:"ok"`
	Preview store.ConfigImportPreview `json:"preview"`
}

// decodeConfigSyncJSON 对嵌套配置包也启用 DisallowUnknownFields。
func decodeConfigSyncJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(contentType, "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "Content-Type 必须为 application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSONDecodeErr(w, err)
		return false
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			writeErr(w, http.StatusBadRequest, "请求体只能包含一个 JSON 值")
		} else {
			writeJSONDecodeErr(w, err)
		}
		return false
	}
	return true
}

// exportConfig 处理 POST /api/config/export，响应体即 ConfigPackage JSON。
func (a *API) exportConfig(w http.ResponseWriter, r *http.Request) {
	var req configExportRequest
	if !decodeConfigSyncJSON(w, r, &req, 4096) {
		return
	}
	pkg, err := a.Store.ExportConfig(req.SourceLabel)
	if err != nil {
		writeConfigSyncError(w, err)
		return
	}
	a.audit(r, "导出配置包", fmt.Sprintf("sites=%d rules=%d exclusions=%d ips=%d", len(pkg.Payload.Sites), len(pkg.Payload.CustomRules), len(pkg.Payload.Exclusions), len(pkg.Payload.IPLists)))
	w.Header().Set("Content-Disposition", `attachment; filename="niubwaf-config.json"`)
	writeJSON(w, pkg)
}

// previewConfigImport 处理 POST /api/config/import/preview，不修改任何数据。
func (a *API) previewConfigImport(w http.ResponseWriter, r *http.Request) {
	var req configImportPreviewRequest
	if !decodeConfigSyncJSON(w, r, &req, configSyncWrapperLimit) {
		return
	}
	preview, err := a.Store.PreviewConfigImport(&req.Package, req.Mode)
	if err != nil {
		writeConfigSyncError(w, err)
		return
	}
	writeJSON(w, preview)
}

// applyConfigImport 处理 POST /api/config/import/apply，要求带回 preview 的三个摘要。
func (a *API) applyConfigImport(w http.ResponseWriter, r *http.Request) {
	var req configImportApplyRequest
	if !decodeConfigSyncJSON(w, r, &req, configSyncWrapperLimit) {
		return
	}
	preview, err := a.Store.ApplyConfigImport(&req.Package, req.Mode, store.ConfigApplyExpectation{
		PackageSHA256: req.PackageSHA256, TargetSHA256: req.TargetSHA256,
		PreviewSHA256: req.PreviewSHA256, ConfirmDeletes: req.ConfirmDeletes,
	})
	if err != nil {
		writeConfigSyncError(w, err)
		return
	}
	// Store 已在提交时原子交换 settings 缓存；Reload 同步重建代理规则、站点、名单与证书视图。
	if a.Proxy != nil {
		a.Proxy.Reload()
		if preview.ReputationChanged {
			a.Proxy.RefreshReputation()
		}
	}
	a.audit(r, "应用配置导入", fmt.Sprintf("mode=%s deletes=%d diff=%d", preview.Mode, configSyncAPIDeleteCount(preview.Stats), len(preview.Diff)))
	writeJSON(w, configImportApplyResponse{OK: true, Preview: *preview})
}

func configSyncAPIDeleteCount(stats map[string]store.ConfigChangeStats) int {
	total := 0
	for _, stat := range stats {
		total += stat.Delete
	}
	return total
}

func writeConfigSyncError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrConfigConflict):
		writeErr(w, http.StatusConflict, "目标配置已在预览后变化，请重新预览")
	case errors.Is(err, store.ErrConfigDigest):
		writeErr(w, http.StatusBadRequest, "package/target/preview 摘要不匹配，请重新预览")
	case errors.Is(err, store.ErrConfigDeleteConfirm):
		writeErr(w, http.StatusBadRequest, "replace 的 confirm_deletes 必须等于预览删除总数")
	case errors.Is(err, store.ErrConfigInvalid):
		// store 的校验错误只含自然键/字段名，不回显上游 URL、秘密或 conditions 内容。
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "配置同步数据库操作失败")
	}
}
