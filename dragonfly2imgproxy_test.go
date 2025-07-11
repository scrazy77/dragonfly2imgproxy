package dragonfly2imgproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testSecret    = "my-super-secret-key"
	testURLPrefix = "https://images.example.com/"
)

// 測試設定檔建立
func TestNew(t *testing.T) {
	// 測試案例: DragonflySecret 為空
	t.Run("should return error if DragonflySecret is empty", func(t *testing.T) {
		cfg := CreateConfig()
		_, err := New(context.Background(), nil, cfg, "test-plugin")
		if err == nil {
			t.Fatal("expected an error but got nil")
		}
		if err.Error() != "DragonflySecret required" {
			t.Errorf("expected error message 'DragonflySecret required', but got '%s'", err.Error())
		}
	})

	// 測試案例: 提供合法的 DragonflySecret
	t.Run("should create a new plugin instance successfully", func(t *testing.T) {
		cfg := CreateConfig()
		cfg.DragonflySecret = testSecret
		handler, err := New(context.Background(), nil, cfg, "test-plugin")
		if err != nil {
			t.Fatalf("expected no error but got: %v", err)
		}
		if handler == nil {
			t.Fatal("expected a handler but got nil")
		}
	})
}

// 測試 SHA 簽章計算
func TestCalculateSHA(t *testing.T) {
	jobs := [][]string{
		{"f", "public/images/some-image.jpg"},
		{"p", "thumb", "400x300#"},
	}
	// 預期的訊息字串為 "f" + "public/images/some-image.jpg" + "p" + "thumb" + "400x300#"
	// 預期的 SHA-256 HMAC (取前16個字元)
	expectedSHA := "ed169fbef25cac31"

	calculatedSHA := calculateSHA(testSecret, jobs)

	if calculatedSHA != expectedSHA {
		t.Errorf("expected SHA '%s', but got '%s'", expectedSHA, calculatedSHA)
	}
}

// 測試 URL 編碼輔助函式
func TestCustomEscape(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "string with space",
			input:    "file name.jpg",
			expected: "file%20name.jpg",
		},
		{
			name:     "string with plus",
			input:    "file+name.jpg",
			expected: "file%2Bname.jpg",
		},
		{
			name:     "already encoded",
			input:    "file%20name.jpg",
			expected: "file%2520name.jpg", // % becomes %25
		},
		{
			name:     "simple string",
			input:    "image.png",
			expected: "image.png",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := customEscape(tc.input); got != tc.expected {
				t.Errorf("customEscape(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

// 測試 imgproxy URL 的產生
func TestGenerateImgproxyURL(t *testing.T) {
	testCases := []struct {
		name        string
		urlPrefix   string
		jobs        [][]string
		expectedURL string
	}{
		{
			name:        "simple fetch",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/image.jpg"}},
			expectedURL: "/insecure/plain/https://images.example.com/public/image.jpg",
		},
		{
			name:        "fetch with thumb fill",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/image.png"}, {"p", "thumb", "100x100#"}},
			expectedURL: "/insecure/rs:fill:100:100:g:ce/plain/https://images.example.com/public/image.png",
		},
		{
			name:        "fetch with thumb fit",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/image.webp"}, {"p", "thumb", "200x>"}},
			expectedURL: "/insecure/rs:fit:200::0/plain/https://images.example.com/public/image.webp",
		},
		{
			name:        "fetch with simple resize",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/image.jpeg"}, {"p", "thumb", "300x"}},
			expectedURL: "/insecure/rs:fit:300:/plain/https://images.example.com/public/image.jpeg",
		},
		{
			name:        "gif with thumb should force gif format",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/animated.gif"}, {"p", "thumb", "150x150#"}},
			expectedURL: "/insecure/rs:fill:150:150:g:ce/f:gif/plain/https://images.example.com/public/animated.gif",
		},
		{
			name:        "svg should force svg format",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/vector.svg"}},
			expectedURL: "/insecure/f:svg/plain/https://images.example.com/public/vector.svg",
		},
		{
			name:        "filename with spaces",
			urlPrefix:   testURLPrefix,
			jobs:        [][]string{{"f", "public/my nice image.jpg"}},
			expectedURL: "/insecure/plain/https://images.example.com/public/my%20nice%20image.jpg",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := generate_imgproxy_url(tc.urlPrefix, tc.jobs)
			if url != tc.expectedURL {
				t.Errorf("expected URL '%s', but got '%s'", tc.expectedURL, url)
			}
		})
	}
}

// 測試 ServeHTTP 中介軟體
func TestServeHTTP(t *testing.T) {
	// --- 測試用的 next handler ---
	// 這個 handler 會被我們的中介軟體呼叫，我們可以在這裡驗證請求是否被正確修改
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Next-Handler-Called", "true")
		rw.Header().Set("X-Request-URL", req.URL.String())
		rw.Header().Set("X-Request-URI", req.RequestURI)
		rw.Header().Set("X-Accept-Header", req.Header.Get("Accept"))
		rw.WriteHeader(http.StatusOK)
	})

	// --- 建立中介軟體實例 ---
	cfg := CreateConfig()
	cfg.DragonflySecret = testSecret
	cfg.URLPrefix = testURLPrefix
	middleware, err := New(context.Background(), next, cfg, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	// --- 定義測試用的 jobs 和對應的 SHA ---
	jobs := [][]string{
		{"f", "public/images/test.jpg"},
		{"p", "thumb", "400x300#"},
	}
	jobsJSON, _ := json.Marshal(jobs)
	jobsB64 := base64.RawURLEncoding.EncodeToString(jobsJSON)
	// W1siZiIsInB1YmxpYy9pbWFnZXMvdGVzdC5qcGciXSxbInAiLCJ0aHVtYiIsIjQwMHgzMDMjIl1d
	// t.Log(jobsB64)

	validSHA := calculateSHA(testSecret, jobs) // 63b86940d587c67c
	// t.Log(validSHA)

	// --- 表格驅動測試 ---
	testCases := []struct {
		name                string
		reqURL              string
		initialAcceptHeader string
		expectedStatusCode  int
		expectedBody        string
		verifyNext          func(t *testing.T, header http.Header)
	}{
		{
			name:                "valid request should be rewritten and passed to next handler",
			reqURL:              fmt.Sprintf("/media/%s.jpg?sha=%s", jobsB64, validSHA),
			initialAcceptHeader: "image/avif,image/webp,*/*",
			expectedStatusCode:  http.StatusOK,
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") != "true" {
					t.Error("next handler was not called")
				}
				expectedPath := "/insecure/rs:fill:400:300:g:ce/plain/https://images.example.com/public/images/test.jpg"
				if header.Get("X-Request-URL") != expectedPath {
					t.Errorf("expected request URL to be '%s', but got '%s'", expectedPath, header.Get("X-Request-URL"))
				}
				// 驗證 Accept header 未被改變
				if header.Get("X-Accept-Header") != "image/avif,image/webp,*/*" {
					t.Errorf("expected Accept header to be unchanged, but got '%s'", header.Get("X-Accept-Header"))
				}
			},
		},
		{
			name:                "valid request with convert=false should clear Accept header",
			reqURL:              fmt.Sprintf("/media/%s.jpg?sha=%s&convert=false", jobsB64, validSHA),
			initialAcceptHeader: "image/avif,image/webp,*/*",
			expectedStatusCode:  http.StatusOK,
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") != "true" {
					t.Error("next handler was not called")
				}
				// 驗證 Accept header 已被清除
				if header.Get("X-Accept-Header") != "" {
					t.Errorf("expected Accept header to be empty, but got '%s'", header.Get("X-Accept-Header"))
				}
			},
		},
		{
			name:               "invalid sha should return 500 error",
			reqURL:             fmt.Sprintf("/media/%s.jpg?sha=invalidsha", jobsB64),
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       "SHA validate failed\n",
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") == "true" {
					t.Error("next handler should not have been called on error")
				}
			},
		},
		{
			name:               "missing sha should return 500 error",
			reqURL:             fmt.Sprintf("/media/%s.jpg", jobsB64),
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       "Failed to get sha from query string.\n",
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") == "true" {
					t.Error("next handler should not have been called on error")
				}
			},
		},
		{
			name:               "invalid base64 should return 500 error",
			reqURL:             fmt.Sprintf("/media/!not-valid-base64/image.jpg?sha=%s", validSHA),
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       "illegal base64 data at input byte 0\n",
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") == "true" {
					t.Error("next handler should not have been called on error")
				}
			},
		},
		{
			name:               "url not matching regex should return 500 error",
			reqURL:             "/foo/bar",
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       "Failed to extract base64 string from URL.\n",
			verifyNext: func(t *testing.T, header http.Header) {
				if header.Get("X-Next-Handler-Called") == "true" {
					t.Error("next handler should not have been called on error")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.reqURL, nil)
			if tc.initialAcceptHeader != "" {
				req.Header.Set("Accept", tc.initialAcceptHeader)
			}

			middleware.ServeHTTP(recorder, req)

			// 驗證狀態碼
			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("expected status code %d, but got %d", tc.expectedStatusCode, recorder.Code)
			}

			// 驗證回應內容
			body, _ := io.ReadAll(recorder.Body)
			if tc.expectedBody != "" && string(body) != tc.expectedBody {
				t.Errorf("expected body '%s', but got '%s'", tc.expectedBody, string(body))
			}

			// 執行針對 next handler 的驗證
			if tc.verifyNext != nil {
				tc.verifyNext(t, recorder.Header())
			}
		})
	}
}
