package dragonfly2imgproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestEdgeCases_URLParsing tests various edge cases for URL parsing
func TestEdgeCases_URLParsing(t *testing.T) {
	testCases := []struct {
		name               string
		url                string
		expectedStatusCode int
		expectedError      string
	}{
		{
			name:               "root_path",
			url:                "/",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "Failed to extract base64 string from URL",
		},
		{
			name:               "missing_media_prefix",
			url:                "/images/test.jpg",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "Failed to extract base64 string from URL",
		},
		{
			name:               "media_only",
			url:                "/media/",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "Failed to extract base64 string from URL",
		},
		{
			name:               "multiple_extensions",
			url:                "/media/base64string.jpg.png?sha=test",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "invalid character",
		},
		{
			name:               "no_extension",
			url:                "/media/base64string?sha=test",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "invalid character",
		},
		{
			name:               "unsupported_extension",
			url:                "/media/base64string.bmp?sha=test",
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "illegal base64 data",
		},
	}
	
	// Setup middleware
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	
	cfg := &Config{
		DragonflySecret: "test-secret",
		URLPrefix:       "https://test.com/",
	}
	
	middleware, _ := New(nil, next, cfg, "test-plugin")
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			
			middleware.ServeHTTP(recorder, req)
			
			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tc.expectedStatusCode, recorder.Code)
			}
			
			body := recorder.Body.String()
			if !strings.Contains(body, tc.expectedError) {
				t.Errorf("expected error containing '%s', got '%s'", tc.expectedError, body)
			}
		})
	}
}

// TestEdgeCases_Base64Decoding tests edge cases for base64 decoding
func TestEdgeCases_Base64Decoding(t *testing.T) {
	testCases := []struct {
		name          string
		base64String  string
		expectedError string
	}{
		{
			name:          "invalid_base64_chars",
			base64String:  "!!!invalid!!!",
			expectedError: "illegal base64 data",
		},
		{
			name:          "base64_with_padding",
			base64String:  "dGVzdA==",
			expectedError: "illegal base64 data",
		},
		{
			name:          "empty_base64",
			base64String:  "",
			expectedError: "illegal base64 data",
		},
		{
			name:          "valid_base64_invalid_json",
			base64String:  base64.RawURLEncoding.EncodeToString([]byte("not json")),
			expectedError: "invalid character",
		},
		{
			name:          "valid_base64_empty_json_array",
			base64String:  base64.RawURLEncoding.EncodeToString([]byte("[]")),
			expectedError: "SHA validate failed",
		},
	}
	
	// Setup middleware
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	
	cfg := &Config{
		DragonflySecret: "test-secret",
		URLPrefix:       "https://test.com/",
	}
	
	middleware, _ := New(nil, next, cfg, "test-plugin")
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			url := fmt.Sprintf("/media/%s.jpg?sha=dummy", tc.base64String)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			
			middleware.ServeHTTP(recorder, req)
			
			if recorder.Code != http.StatusInternalServerError {
				t.Errorf("expected status code 500, got %d", recorder.Code)
			}
			
			body := recorder.Body.String()
			if !strings.Contains(body, tc.expectedError) {
				t.Errorf("expected error containing '%s', got '%s'", tc.expectedError, body)
			}
		})
	}
}

// TestEdgeCases_JobProcessing tests edge cases for job processing
func TestEdgeCases_JobProcessing(t *testing.T) {
	testCases := []struct {
		name          string
		jobs          [][]string
		expectedError string
	}{
		{
			name:          "empty_job_array",
			jobs:          [][]string{},
			expectedError: "",
		},
		{
			name:          "invalid_job_type",
			jobs:          [][]string{{"x", "invalid"}},
			expectedError: "",
		},
		{
			name:          "missing_job_params",
			jobs:          [][]string{{"f"}},
			expectedError: "",
		},
		{
			name:          "invalid_thumb_geometry",
			jobs:          [][]string{{"f", "test.jpg"}, {"p", "thumb", "invalid"}},
			expectedError: "Failed to extract job",
		},
		{
			name:          "negative_dimensions",
			jobs:          [][]string{{"f", "test.jpg"}, {"p", "thumb", "-100x-100"}},
			expectedError: "Failed to extract job",
		},
		{
			name:          "zero_dimensions",
			jobs:          [][]string{{"f", "test.jpg"}, {"p", "thumb", "0x0"}},
			expectedError: "",
		},
		{
			name:          "very_large_dimensions",
			jobs:          [][]string{{"f", "test.jpg"}, {"p", "thumb", "99999x99999#"}},
			expectedError: "",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := generate_imgproxy_url("https://test.com/", tc.jobs)
			
			if tc.expectedError != "" && !strings.Contains(result, tc.expectedError) {
				t.Errorf("expected error containing '%s', got '%s'", tc.expectedError, result)
			}
		})
	}
}

// TestEdgeCases_SpecialCharacters tests handling of special characters in filenames
func TestEdgeCases_SpecialCharacters(t *testing.T) {
	testCases := []struct {
		name         string
		filename     string
		expectedPath string
	}{
		{
			name:         "unicode_characters",
			filename:     "画像.jpg",
			expectedPath: "%E7%94%BB%E5%83%8F.jpg",
		},
		{
			name:         "multiple_spaces",
			filename:     "my   image   file.jpg",
			expectedPath: "my%20%20%20image%20%20%20file.jpg",
		},
		{
			name:         "special_url_chars",
			filename:     "image@2x[1].jpg",
			expectedPath: "image%402x%5B1%5D.jpg",
		},
		{
			name:         "path_traversal_attempt",
			filename:     "../../../etc/passwd",
			expectedPath: "../../../etc/passwd",
		},
		{
			name:         "null_byte",
			filename:     "image\x00.jpg",
			expectedPath: "image%00.jpg",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jobs := [][]string{{"f", tc.filename}}
			result := generate_imgproxy_url("https://test.com/", jobs)
			
			if !strings.Contains(result, tc.expectedPath) {
				t.Errorf("expected path to contain '%s', got '%s'", tc.expectedPath, result)
			}
		})
	}
}

// TestEdgeCases_HeaderHandling tests edge cases for HTTP header handling
func TestEdgeCases_HeaderHandling(t *testing.T) {
	// Setup
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Echo back the Accept header for verification
		rw.Header().Set("X-Received-Accept", req.Header.Get("Accept"))
		rw.WriteHeader(http.StatusOK)
	})
	
	cfg := &Config{
		DragonflySecret: "test-secret",
		URLPrefix:       "https://test.com/",
	}
	
	middleware, _ := New(nil, next, cfg, "test-plugin")
	
	// Prepare valid request
	jobs := [][]string{{"f", "test.jpg"}}
	jobsJSON, _ := json.Marshal(jobs)
	jobsB64 := base64.RawURLEncoding.EncodeToString(jobsJSON)
	validSHA := calculateSHA(cfg.DragonflySecret, jobs)
	
	testCases := []struct {
		name           string
		acceptHeader   string
		queryParams    string
		expectedAccept string
	}{
		{
			name:           "empty_accept_header",
			acceptHeader:   "",
			queryParams:    "",
			expectedAccept: "",
		},
		{
			name:           "complex_accept_header",
			acceptHeader:   "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
			queryParams:    "",
			expectedAccept: "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
		},
		{
			name:           "convert_false_with_accept",
			acceptHeader:   "image/webp,*/*",
			queryParams:    "&convert=false",
			expectedAccept: "",
		},
		{
			name:           "convert_true_with_accept",
			acceptHeader:   "image/webp,*/*",
			queryParams:    "&convert=true",
			expectedAccept: "image/webp,*/*",
		},
		{
			name:           "multiple_convert_params",
			acceptHeader:   "image/webp",
			queryParams:    "&convert=true&convert=false",
			expectedAccept: "image/webp",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			url := fmt.Sprintf("/media/%s.jpg?sha=%s%s", jobsB64, validSHA, tc.queryParams)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			
			if tc.acceptHeader != "" {
				req.Header.Set("Accept", tc.acceptHeader)
			}
			
			middleware.ServeHTTP(recorder, req)
			
			if recorder.Code != http.StatusOK {
				t.Errorf("expected status code 200, got %d", recorder.Code)
			}
			
			receivedAccept := recorder.Header().Get("X-Received-Accept")
			if receivedAccept != tc.expectedAccept {
				t.Errorf("expected Accept header '%s', got '%s'", tc.expectedAccept, receivedAccept)
			}
		})
	}
}

// TestConcurrentRequests tests the middleware under concurrent load
func TestConcurrentRequests(t *testing.T) {
	// Setup
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	
	cfg := &Config{
		DragonflySecret: "test-secret",
		URLPrefix:       "https://test.com/",
	}
	
	middleware, _ := New(nil, next, cfg, "test-plugin")
	
	// Prepare multiple different requests
	requests := []struct {
		jobs [][]string
	}{
		{jobs: [][]string{{"f", "image1.jpg"}, {"p", "thumb", "100x100"}}},
		{jobs: [][]string{{"f", "image2.gif"}, {"p", "thumb", "200x200#"}}},
		{jobs: [][]string{{"f", "vector.svg"}}},
		{jobs: [][]string{{"f", "photo with spaces.jpg"}, {"p", "thumb", "300x>"}}},
		{jobs: [][]string{{"f", "large.png"}, {"p", "thumb", "1920x1080#"}}},
	}
	
	// Run concurrent requests
	concurrency := 50
	iterations := 100
	
	for i := 0; i < iterations; i++ {
		var wg sync.WaitGroup
		wg.Add(concurrency)
		
		for j := 0; j < concurrency; j++ {
			go func(index int) {
				defer wg.Done()
				
				req := requests[index%len(requests)]
				jobsJSON, _ := json.Marshal(req.jobs)
				jobsB64 := base64.RawURLEncoding.EncodeToString(jobsJSON)
				validSHA := calculateSHA(cfg.DragonflySecret, req.jobs)
				
				recorder := httptest.NewRecorder()
				httpReq := httptest.NewRequest(
					http.MethodGet,
					fmt.Sprintf("/media/%s.jpg?sha=%s", jobsB64, validSHA),
					nil,
				)
				
				middleware.ServeHTTP(recorder, httpReq)
				
				if recorder.Code != http.StatusOK {
					t.Errorf("concurrent request failed with status %d", recorder.Code)
				}
			}(j)
		}
		
		wg.Wait()
	}
}