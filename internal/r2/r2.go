package r2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// operationsTimeout は Cloudflare GraphQL Analytics API 呼び出しのタイムアウト。
const operationsTimeout = 15 * time.Second

// Config は R2 接続設定
type Config struct {
	AccountID string
	APIToken  string
	Buckets   []string
	Bucket    string
}

// BucketInfo はバケット別ストレージ情報
type BucketInfo struct {
	PayloadSize string `json:"payloadSize"`
	ObjectCount string `json:"objectCount"`
}

// StorageInfo はストレージ合計
type StorageInfo struct {
	PayloadSize string                `json:"payloadSize"`
	ObjectCount string                `json:"objectCount"`
	Buckets     map[string]BucketInfo `json:"buckets"`
}

// OperationsInfo は月間操作回数
type OperationsInfo struct {
	ClassA int    `json:"class_a"`
	ClassB int    `json:"class_b"`
	Month  string `json:"month"`
}

// MetricsData は R2 メトリクスの取得結果
type MetricsData struct {
	Storage    *StorageInfo    `json:"storage"`
	Operations *OperationsInfo `json:"operations"`
	Error      string          `json:"error,omitempty"`
}

var classATypes = map[string]bool{
	"PutObject": true, "CopyObject": true, "DeleteObject": true,
	"DeleteObjects": true, "CreateMultipartUpload": true, "CompleteMultipartUpload": true,
	"UploadPart": true, "UploadPartCopy": true, "PutBucket": true,
	"ListMultipartUploads": true, "AbortMultipartUpload": true, "ListParts": true,
}
var classBTypes = map[string]bool{
	"GetObject": true, "HeadObject": true, "ListObjects": true,
	"ListObjectsV2": true, "ListBuckets": true, "HeadBucket": true,
	"GetBucketVersioning": true, "GetBucketLocation": true,
	"ReportUsageSummary": true,
}

// accountIDUnsafeChars は accountID 正規化用の正規表現（毎回コンパイルを避けパッケージ変数化）。
var accountIDUnsafeChars = regexp.MustCompile(`[^a-zA-Z0-9]`)

// AccountIDSafe は accountID を英数字のみに正規化して返す（空文字時は空文字）。
func AccountIDSafe(accountID string) string {
	id := strings.TrimSpace(accountID)
	if id == "" {
		return ""
	}
	return accountIDUnsafeChars.ReplaceAllString(id, "")
}

// EndpointURL は R2 S3 互換エンドポイント URL を返す（accountID 未設定時は空文字）。
func EndpointURL(accountID string) string {
	safe := AccountIDSafe(accountID)
	if safe == "" {
		return ""
	}
	return fmt.Sprintf("https://%s.r2.cloudflarestorage.com", safe)
}

// ListFiles は R2 バケット/プレフィックス配下のファイル行を新しい順で返す。
func ListFiles(cfg Config, bucket, prefix string) []string {
	endpoint := EndpointURL(cfg.AccountID)
	if endpoint == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/local/bin/aws", "s3", "ls",
		"s3://"+bucket+"/"+prefix,
		"--endpoint-url", endpoint,
		"--profile", "r2")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// aws s3 ls は古い順で出力するため逆順（新しい順）に並べ替える
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return lines
}

// GetMetrics は Cloudflare R2 のストレージ容量と月間操作回数を返す
func GetMetrics(cfg Config) MetricsData {
	accountIDSafe := AccountIDSafe(cfg.AccountID)
	if accountIDSafe == "" || cfg.APIToken == "" {
		return MetricsData{Error: "Cloudflare credentials not configured ([cloudflare_r2].account_id / api_token)"}
	}

	buckets := append([]string(nil), cfg.Buckets...)
	if len(buckets) == 0 && strings.TrimSpace(cfg.Bucket) != "" {
		buckets = []string{strings.TrimSpace(cfg.Bucket)}
	}

	result := MetricsData{}

	if len(buckets) > 0 {
		endpointURL := EndpointURL(cfg.AccountID)
		storage := &StorageInfo{Buckets: map[string]BucketInfo{}}
		totalSize, totalCount := int64(0), int64(0)

		for _, bucket := range buckets {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, "/usr/local/bin/aws", "s3", "ls",
				"s3://"+bucket, "--recursive", "--summarize",
				"--endpoint-url", endpointURL,
				"--profile", "r2")
			out, _ := cmd.Output()
			cancel()

			var bSize, bCount int64
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Total Objects:") {
					fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Total Objects:")), "%d", &bCount)
				} else if strings.HasPrefix(line, "Total Size:") {
					fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Total Size:")), "%d", &bSize)
				}
			}
			storage.Buckets[bucket] = BucketInfo{
				PayloadSize: fmt.Sprintf("%d", bSize),
				ObjectCount: fmt.Sprintf("%d", bCount),
			}
			totalSize += bSize
			totalCount += bCount
		}
		storage.PayloadSize = fmt.Sprintf("%d", totalSize)
		storage.ObjectCount = fmt.Sprintf("%d", totalCount)
		result.Storage = storage
	}

	if ops, err := CollectOperations(accountIDSafe, cfg.APIToken); err == nil {
		result.Operations = ops
	}
	return result
}

// CollectOperations は当月の R2 操作回数（Class A / Class B）を Cloudflare GraphQL
// Analytics API から取得する。accountIDSafe は AccountIDSafe 済みの値を渡すこと
// （英数字のみにサニタイズ済みのため query 文字列への埋め込みに注入余地はない）。
//
// C3（r2-logic-duplicated-drift）: monitor 用 GetMetrics と agent collector で重複していた
// GraphQL 取得ロジックの正準実装。手動 JSON 連結をやめ json.Marshal で組み立て、レスポンスは
// io.LimitReader で上限（5MiB）を設ける（暴走レスポンスでのメモリ枯渇防止）。
func CollectOperations(accountIDSafe, apiToken string) (*OperationsInfo, error) {
	now := time.Now().UTC()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	startOfNext := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	gqlQuery := fmt.Sprintf(
		`{ viewer { accounts(filter: {accountTag: "%s"}) { r2OperationsAdaptiveGroups(filter: {datetime_geq: "%s", datetime_lt: "%s"}, limit: 100) { dimensions { actionType } sum { requests } } } } }`,
		accountIDSafe,
		startOfMonth.Format(time.RFC3339),
		startOfNext.Format(time.RFC3339),
	)

	reqPayload, err := json.Marshal(map[string]string{"query": gqlQuery})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", bytes.NewReader(reqPayload))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: operationsTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gqlResp struct {
		Data struct {
			Viewer struct {
				Accounts []struct {
					Ops []struct {
						Sum struct {
							Requests int `json:"requests"`
						} `json:"sum"`
						Dimensions struct {
							ActionType string `json:"actionType"`
						} `json:"dimensions"`
					} `json:"r2OperationsAdaptiveGroups"`
				} `json:"accounts"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5*1024*1024)).Decode(&gqlResp); err != nil {
		return nil, err
	}
	if len(gqlResp.Data.Viewer.Accounts) == 0 {
		return nil, fmt.Errorf("no accounts in response")
	}

	ops := &OperationsInfo{Month: now.Format("2006-01")}
	for _, row := range gqlResp.Data.Viewer.Accounts[0].Ops {
		at := row.Dimensions.ActionType
		cnt := row.Sum.Requests
		if classATypes[at] {
			ops.ClassA += cnt
		} else if classBTypes[at] {
			ops.ClassB += cnt
		}
	}
	return ops, nil
}
