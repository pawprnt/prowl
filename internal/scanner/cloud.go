package scanner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type CloudAuditResult struct {
	Target    string              `json:"target"`
	Timestamp time.Time           `json:"timestamp"`
	S3        *S3Result           `json:"s3,omitempty"`
	Azure     *AzureResult        `json:"azure,omitempty"`
	GCS       *GCSResult          `json:"gcs,omitempty"`
	Firebase  *FirebaseResult     `json:"firebase,omitempty"`
	ES        *ElasticsearchResult `json:"elasticsearch,omitempty"`
	Mongo     *MongoResult        `json:"mongodb,omitempty"`
	Redis     *RedisResult        `json:"redis,omitempty"`
	Memcached *MemcachedResult    `json:"memcached,omitempty"`
	Errors    []string            `json:"errors,omitempty"`
}

type S3Result struct {
	Bucket    string       `json:"bucket"`
	Exists    bool         `json:"exists"`
	Public    bool         `json:"public_read"`
	ACL       string       `json:"acl,omitempty"`
	Objects   []S3Object   `json:"objects,omitempty"`
	Listed    bool         `json:"listed"`
}

type S3Object struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"last_modified,omitempty"`
}

type AzureResult struct {
	Container string       `json:"container"`
	Exists    bool         `json:"exists"`
	Public    bool         `json:"public_read"`
	Objects   []AzureBlob  `json:"objects,omitempty"`
}

type AzureBlob struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type GCSResult struct {
	Bucket  string     `json:"bucket"`
	Exists  bool       `json:"exists"`
	Public  bool       `json:"public_read"`
	Objects []GCSObject `json:"objects,omitempty"`
}

type GCSObject struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type FirebaseResult struct {
	URL     string            `json:"url"`
	Open    bool              `json:"open_read"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

type ElasticsearchResult struct {
	URL     string   `json:"url"`
	Open    bool     `json:"open"`
	Indices []string `json:"indices,omitempty"`
	Version string   `json:"version,omitempty"`
}

type MongoResult struct {
	URL     string   `json:"url"`
	Open    bool     `json:"open"`
	DBs     []string `json:"databases,omitempty"`
}

type RedisResult struct {
	URL     string   `json:"url"`
	Open    bool     `json:"open"`
	Info    string   `json:"info,omitempty"`
}

type MemcachedResult struct {
	URL     string   `json:"url"`
	Open    bool     `json:"open"`
	Items   []string `json:"items,omitempty"`
}

func CheckAWSDirectories(ctx context.Context, bucket string) (*S3Result, error) {
	printProgress("Checking S3 bucket: %s", bucket)
	result := &S3Result{Bucket: bucket}

	client := &http.Client{Timeout: 10 * time.Second}

	url := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Exists = true
		result.Listed = true
		result.Public = true

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		result.ACL = parseS3ACL(string(body))

		var xmlResult struct {
			Contents []struct {
				Key          string `xml:"Key"`
				Size         int64  `xml:"Size"`
				LastModified string `xml:"LastModified"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &xmlResult); err == nil {
			for _, obj := range xmlResult.Contents {
				result.Objects = append(result.Objects, S3Object{
					Key:          obj.Key,
					Size:         obj.Size,
					LastModified: obj.LastModified,
				})
			}
		}
	} else if resp.StatusCode == 403 {
		result.Exists = true
		result.Public = false
	} else if resp.StatusCode == 404 {
		result.Exists = false
	}

	printProgress("S3 bucket %s: exists=%v, public=%v, objects=%d",
		bucket, result.Exists, result.Public, len(result.Objects))
	return result, nil
}

func CheckAzureBlob(ctx context.Context, container string) (*AzureResult, error) {
	printProgress("Checking Azure blob container: %s", container)
	result := &AzureResult{Container: container}

	client := &http.Client{Timeout: 10 * time.Second}

	url := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list&container=%s", container, container)
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Exists = true
		result.Public = true

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		bodyStr := string(body)

		for _, line := range strings.Split(bodyStr, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "<Name>") {
				start := strings.Index(line, "<Name>") + 6
				end := strings.Index(line, "</Name>")
				if end > start {
					name := line[start:end]
					result.Objects = append(result.Objects, AzureBlob{Name: name})
				}
			}
		}
	} else if resp.StatusCode == 403 {
		result.Exists = true
		result.Public = false
	}

	printProgress("Azure blob %s: exists=%v, public=%v, objects=%d",
		container, result.Exists, result.Public, len(result.Objects))
	return result, nil
}

func CheckGCSBucket(ctx context.Context, bucket string) (*GCSResult, error) {
	printProgress("Checking GCS bucket: %s", bucket)
	result := &GCSResult{Bucket: bucket}

	client := &http.Client{Timeout: 10 * time.Second}

	url := fmt.Sprintf("https://storage.googleapis.com/%s?maxResults=100", bucket)
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.Exists = true
		result.Public = true

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		var xmlResult struct {
			Contents []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &xmlResult); err == nil {
			for _, obj := range xmlResult.Contents {
				result.Objects = append(result.Objects, GCSObject{
					Name: obj.Key,
					Size: obj.Size,
				})
			}
		}
	} else if resp.StatusCode == 403 {
		result.Exists = true
		result.Public = false
	}

	printProgress("GCS bucket %s: exists=%v, public=%v, objects=%d",
		bucket, result.Exists, result.Public, len(result.Objects))
	return result, nil
}

func CheckFirebaseURL(ctx context.Context, url string) (*FirebaseResult, error) {
	printProgress("Checking Firebase: %s", url)
	result := &FirebaseResult{URL: url}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	if !strings.HasSuffix(url, ".json") {
		url = strings.TrimRight(url, "/") + "/.json"
	}
	result.URL = url

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			result.Open = true
			result.Data = data
		} else if len(body) > 0 && string(body) != "null" {
			result.Open = true
		}
	}

	printProgress("Firebase: open=%v", result.Open)
	return result, nil
}

func CheckElasticsearch(ctx context.Context, url string) (*ElasticsearchResult, error) {
	printProgress("Checking Elasticsearch: %s", url)
	result := &ElasticsearchResult{URL: url}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		var info struct {
			Version struct {
				Number string `json:"number"`
			} `json:"version"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &info); err == nil {
			result.Open = true
			result.Version = info.Version.Number
		}

		indicesResp, err := client.Get(url + "_cat/indices?format=json")
		if err == nil {
			defer indicesResp.Body.Close()
			indicesBody, _ := io.ReadAll(io.LimitReader(indicesResp.Body, 65536))
			var indices []struct {
				Index string `json:"index"`
			}
			if err := json.Unmarshal(indicesBody, &indices); err == nil {
				for _, idx := range indices {
					if !strings.HasPrefix(idx.Index, ".") {
						result.Indices = append(result.Indices, idx.Index)
					}
				}
			}
		}
	}

	printProgress("Elasticsearch: open=%v, indices=%d", result.Open, len(result.Indices))
	return result, nil
}

func CheckMongoDB(ctx context.Context, url string) (*MongoResult, error) {
	printProgress("Checking MongoDB: %s", url)
	result := &MongoResult{URL: url}

	if !strings.HasPrefix(url, "mongodb") {
		url = "mongodb://" + url
	}

	conn, err := netDialTimeout("tcp", extractMongoHost(url), 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	initMsg := buildMongoInit(extractMongoHost(url))
	_, err = conn.Write(initMsg)
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return result, nil
	}

	result.Open = true

	listCmd := buildMongoCommand("listDatabases", 1)
	_, err = conn.Write(listCmd)
	if err != nil {
		return result, nil
	}

	n, err = conn.Read(resp)
	if err == nil && n > 0 {
		respStr := string(resp[:n])
		if strings.Contains(respStr, "databases") {
			result.DBs = append(result.DBs, "accessible")
		}
	}

	printProgress("MongoDB: open=%v, databases=%d", result.Open, len(result.DBs))
	return result, nil
}

func CheckRedis(ctx context.Context, url string) (*RedisResult, error) {
	printProgress("Checking Redis: %s", url)
	result := &RedisResult{URL: url}

	host := url
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	conn, err := netDialTimeout("tcp", host+":6379", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return result, nil
	}

	respStr := string(resp[:n])
	if strings.Contains(respStr, "PONG") || strings.Contains(respStr, "OK") {
		result.Open = true
	}

	_, err = conn.Write([]byte("*1\r\n$4\r\nINFO\r\n"))
	if err == nil {
		n, err = conn.Read(resp)
		if err == nil && n > 0 {
			result.Info = string(resp[:n])
		}
	}

	printProgress("Redis: open=%v", result.Open)
	return result, nil
}

func CheckMemcached(ctx context.Context, url string) (*MemcachedResult, error) {
	printProgress("Checking Memcached: %s", url)
	result := &MemcachedResult{URL: url}

	host := url
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	conn, err := netDialTimeout("tcp", host+":11211", 5*time.Second)
	if err != nil {
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("version\r\n"))
	if err != nil {
		return result, nil
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return result, nil
	}

	respStr := string(resp[:n])
	if strings.HasPrefix(respStr, "VERSION") {
		result.Open = true
	}

	_, err = conn.Write([]byte("stats items\r\n"))
	if err == nil {
		n, err = conn.Read(resp)
		if err == nil && n > 0 {
			lines := strings.Split(string(resp[:n]), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "slab") {
					result.Items = append(result.Items, line)
				}
			}
		}
	}

	printProgress("Memcached: open=%v, items=%d", result.Open, len(result.Items))
	return result, nil
}

func FullCloudAudit(ctx context.Context, target, outputDir string) (CloudAuditResult, error) {
	result := CloudAuditResult{
		Target:    target,
		Timestamp: time.Now(),
	}

	printProgress("=== Cloud Security Audit on %s ===", target)

	s3, err := CheckAWSDirectories(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("s3: %v", err))
	} else {
		result.S3 = s3
	}

	azure, err := CheckAzureBlob(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("azure: %v", err))
	} else {
		result.Azure = azure
	}

	gcs, err := CheckGCSBucket(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("gcs: %v", err))
	} else {
		result.GCS = gcs
	}

	firebase, err := CheckFirebaseURL(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("firebase: %v", err))
	} else {
		result.Firebase = firebase
	}

	es, err := CheckElasticsearch(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("elasticsearch: %v", err))
	} else {
		result.ES = es
	}

	mongo, err := CheckMongoDB(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("mongodb: %v", err))
	} else {
		result.Mongo = mongo
	}

	redis, err := CheckRedis(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("redis: %v", err))
	} else {
		result.Redis = redis
	}

	memcached, err := CheckMemcached(ctx, target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("memcached: %v", err))
	} else {
		result.Memcached = memcached
	}

	if outputDir != "" {
		os.MkdirAll(outputDir, 0755)
		saveResult(outputDir, "cloud_audit.json", result)
	}

	return result, nil
}

func parseS3ACL(body string) string {
	if strings.Contains(body, "<StringEffect>Allow</StringEffect>") {
		return "public-read"
	}
	return "private"
}

func extractMongoHost(url string) string {
	host := strings.TrimPrefix(url, "mongodb://")
	host = strings.TrimPrefix(host, "mongodb+srv://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, "?"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func buildMongoInit(host string) []byte {
	doc := fmt.Sprintf(`{"ismaster":1,"client":{"application":{"name":"prowl"},"driver":{"name":"go","version":"1.0"}},"host":"%s"}`, host)
	msg := fmt.Sprintf("\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xdd\x07\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x21\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	_ = doc
	return []byte(msg)
}

func buildMongoCommand(command string, n int) []byte {
	msg := fmt.Sprintf(`{"%s":%d}`, command, n)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(msg)))
	binary.LittleEndian.PutUint32(header[4:8], uint32(n))
	binary.LittleEndian.PutUint32(header[8:12], 0)
	binary.LittleEndian.PutUint32(header[12:16], 2013)
	return append(header, []byte(msg)...)
}

func netDialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}
