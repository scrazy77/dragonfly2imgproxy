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

	regex := regexp.MustCompile(`\/media\/(.+?)\.(gif|png|jpeg|jpg|webp|avif)\?sha=(\w+)`)
	match := regex.FindStringSubmatch(req.URL.Path + "?" + req.URL.RawQuery)
	if len(match) < 4 {
		log.Println("Failed to extract base64 string and SHA from URL. match=" + strconv.Itoa((len(match))))
		http.Error(rw, "Failed to extract base64 string and SHA from URL.", http.StatusInternalServerError)
		return
	}
	base64String := match[1]

	sha := match[3]
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

	req.URL.Path = imgproxy_url
	req.URL.RawQuery = "" // clean query string
	req.RequestURI = req.URL.RequestURI()

	d.next.ServeHTTP(rw, req)
}

// Generate imgproxy url
func generate_imgproxy_url(url_prefix string, jobs [][]string) string {
	imgproxy_url := url_prefix
	thumb_operation := ""
	var is_gif = false
	for _, job := range jobs {
		if job[0] == "f" { //fetch image
			filePath := job[1]
			dir, fileName := filepath.Split(filePath)
			encodedFileName := url.PathEscape(fileName)
			encodedFilePath := filepath.Join(dir, encodedFileName)
			imgproxy_url += encodedFilePath
			imgproxy_url = "/plain/" + imgproxy_url
			if strings.HasSuffix(imgproxy_url, ".gif") {
				is_gif = true
			}
		} else if job[0] == "p" { // process image
			if job[1] == "thumb" { // thumb only
				regex := regexp.MustCompile(`^(\d+)x(|\d+)(|>|#)$`)
				match := regex.FindStringSubmatch(job[2])
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
