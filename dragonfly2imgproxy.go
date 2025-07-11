// Package dragonfly2imgproxy is a plugin to convert dragonfly url to imgproxy
package dragonfly2imgproxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 正規表示式應該在全域或初始化時編譯一次，避免在每次請求中重複編譯。
var (
	// 用於解析 Dragonfly URL 中的 Base64 字串
	// e.g., /media/BASE64STRING.jpg
	urlRegex = regexp.MustCompile(`\/media\/(.+?)(\.gif|.png|.jpeg|.jpg|.webp|.avif|.svg)*$`)
	// 用於解析 Dragonfly 的 'thumb' 參數
	// e.g., 400x300#
	thumbRegex = regexp.MustCompile(`^(\d+)x(|\d+)(|>|#)$`)
)

// Config configures the middleware.
type Config struct {
	DragonflySecret string `json:"dragonflySecret" yaml:"dragonflySecret" toml:"dragonflySecret"`
	URLPrefix       string `json:"urlPrefix" yaml:"urlPrefix" toml:"urlPrefix"`
}

// CreateConfig returns a config instance.
func CreateConfig() *Config {
	return &Config{
		DragonflySecret: "",
		URLPrefix:       "",
	}
}

type Dragonfly2imgproxy struct {
	name   string
	config *Config
	next   http.Handler
}

// New returns a plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.DragonflySecret) == 0 {
		return nil, errors.New("DragonflySecret required")
	}

	return &Dragonfly2imgproxy{
		name:   name,
		config: config,
		next:   next,
	}, nil

}

// ServeHTTP serves an HTTP request.
func (d *Dragonfly2imgproxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	// Get base64 from url path
	match := urlRegex.FindStringSubmatch(req.URL.Path)
	if len(match) < 3 {
		log.Println("Failed to extract base64 string from URL. match=" + strconv.Itoa((len(match))))
		http.Error(rw, "Failed to extract base64 string from URL.", http.StatusInternalServerError)
		return
	}
	base64String := match[1]

	// Get sha from query string
	sha := req.URL.Query().Get("sha")
	if len(sha) == 0 {
		log.Println("Failed to get sha from query string.")
		http.Error(rw, "Failed to get sha from query string.", http.StatusInternalServerError)
		return
	}

	// Base64 decode jobs
	jobBytes, err := base64.RawURLEncoding.DecodeString(base64String)
	if err != nil {
		log.Println("Base64 decode error:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	// to job string
	job_string := string(jobBytes)
	// parse jobs
	var jobs [][]string
	err = json.Unmarshal([]byte(job_string), &jobs)
	if err != nil {
		log.Println("Parse JSON failed:", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if calculateSHA(d.config.DragonflySecret, jobs) != sha {
		log.Println("SHA validate failed")
		http.Error(rw, "SHA validate failed", http.StatusInternalServerError)
		return
	}
	var imgproxy_url = generate_imgproxy_url(d.config.URLPrefix, jobs)
	log.Println("generate imgproxy url=" + imgproxy_url)
	// auto_convert=false replace Accept header with only traditional image format
	if req.URL.Query().Get("convert") == "false" {
		log.Println("convert=false turn off Accept Header")
		req.Header.Del("Accept")
	}
	req.URL.Path = imgproxy_url
	req.URL.RawQuery = "" // clean query string
	req.RequestURI = imgproxy_url

	d.next.ServeHTTP(rw, req)
}

func customEscape(s string) string {
	encoded := url.QueryEscape(s)
	// space -> %20
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	return encoded
}

// Generate imgproxy url
func generate_imgproxy_url(url_prefix string, jobs [][]string) string {
	imgproxy_url := url_prefix
	thumb_operation := ""
	var is_gif = false
	var is_svg = false
	for _, job := range jobs {
		if job[0] == "f" { //fetch image
			filePath := job[1]
			dir, fileName := filepath.Split(filePath)
			encodedFileName := customEscape(fileName)
			encodedFilePath := filepath.Join(dir, encodedFileName)
			imgproxy_url += encodedFilePath
			imgproxy_url = "/plain/" + imgproxy_url
			if strings.HasSuffix(imgproxy_url, ".gif") {
				is_gif = true
			}
			if strings.HasSuffix(imgproxy_url, ".svg") {
				is_svg = true
			}
		} else if job[0] == "p" { // process image
			if job[1] == "thumb" { // thumb only
				match := thumbRegex.FindStringSubmatch(job[2])
				if len(match) < 1 {
					fmt.Println("Failed to extract job")
					return "Failed to extract job"
				}
				width := match[1]
				height := match[2]
				operation := match[3] // only support > #
				if operation == ">" {
					thumb_operation += "/rs:fit:" + width + ":" + height + ":0"
				} else if operation == "#" {
					thumb_operation += "/rs:fill:" + width + ":" + height + ":g:ce"
				} else {
					thumb_operation += "/rs:fit:" + width + ":" + height
				}
				if is_gif { // force gif format
					thumb_operation += "/f:gif"
				}
			}
		}
	}
	if is_svg {
		imgproxy_url = "/f:svg" + imgproxy_url
	}
	return "/insecure" + thumb_operation + imgproxy_url
}

// calculateSHA
func calculateSHA(secret string, jobs [][]string) string {
	message := ""
	for _, job := range jobs {
		if job[0] == "f" { // fetch + url
			message += "f" + job[1]
		} else if job[0] == "p" { // process + thumb + size
			message += "p" + job[1] + job[2]
		}
	}
	// calculate
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	digest := h.Sum(nil)
	shaHex := fmt.Sprintf("%x", digest)
	log.Println("message:", message)
	log.Println("calculated sha:", shaHex[:16])
	return shaHex[:16]
}
