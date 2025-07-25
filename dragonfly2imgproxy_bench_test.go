package dragonfly2imgproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Benchmark for calculateSHA function
func BenchmarkCalculateSHA(b *testing.B) {
	secret := "benchmark-secret-key"
	jobs := [][]string{
		{"f", "public/images/benchmark.jpg"},
		{"p", "thumb", "800x600#"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateSHA(secret, jobs)
	}
}

// Benchmark for calculateSHA with varying job sizes
func BenchmarkCalculateSHA_MultipleJobs(b *testing.B) {
	secret := "benchmark-secret-key"
	
	testCases := []struct {
		name string
		jobs [][]string
	}{
		{
			name: "1_job",
			jobs: [][]string{
				{"f", "public/images/benchmark.jpg"},
			},
		},
		{
			name: "3_jobs",
			jobs: [][]string{
				{"f", "public/images/benchmark.jpg"},
				{"p", "thumb", "800x600#"},
				{"p", "thumb", "400x300>"},
			},
		},
		{
			name: "5_jobs",
			jobs: [][]string{
				{"f", "public/images/benchmark.jpg"},
				{"p", "thumb", "800x600#"},
				{"p", "thumb", "400x300>"},
				{"p", "thumb", "200x200"},
				{"p", "thumb", "100x100#"},
			},
		},
	}
	
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = calculateSHA(secret, tc.jobs)
			}
		})
	}
}

// Benchmark for generate_imgproxy_url function
func BenchmarkGenerateImgproxyURL(b *testing.B) {
	urlPrefix := "https://cdn.example.com/"
	jobs := [][]string{
		{"f", "public/images/benchmark.jpg"},
		{"p", "thumb", "800x600#"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generate_imgproxy_url(urlPrefix, jobs)
	}
}

// Benchmark for different image formats
func BenchmarkGenerateImgproxyURL_Formats(b *testing.B) {
	urlPrefix := "https://cdn.example.com/"
	
	testCases := []struct {
		name string
		jobs [][]string
	}{
		{
			name: "jpeg",
			jobs: [][]string{
				{"f", "public/images/test.jpg"},
				{"p", "thumb", "400x300#"},
			},
		},
		{
			name: "gif",
			jobs: [][]string{
				{"f", "public/images/animated.gif"},
				{"p", "thumb", "400x300#"},
			},
		},
		{
			name: "svg",
			jobs: [][]string{
				{"f", "public/images/vector.svg"},
				{"p", "thumb", "400x300#"},
			},
		},
		{
			name: "filename_with_spaces",
			jobs: [][]string{
				{"f", "public/images/my nice image.jpg"},
				{"p", "thumb", "400x300#"},
			},
		},
	}
	
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = generate_imgproxy_url(urlPrefix, tc.jobs)
			}
		})
	}
}

// Benchmark for customEscape function
func BenchmarkCustomEscape(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"simple", "image.jpg"},
		{"with_spaces", "my image file.jpg"},
		{"with_special_chars", "image+file@2x.jpg"},
		{"already_encoded", "image%20file.jpg"},
		{"long_filename", "this_is_a_very_long_filename_with_many_characters_and_underscores.jpg"},
	}
	
	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = customEscape(tc.input)
			}
		})
	}
}

// Benchmark for the entire ServeHTTP flow
func BenchmarkServeHTTP(b *testing.B) {
	// Setup
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	
	cfg := &Config{
		DragonflySecret: "benchmark-secret",
		URLPrefix:       "https://cdn.example.com/",
	}
	
	middleware, _ := New(nil, next, cfg, "benchmark-plugin")
	
	// Prepare request
	jobs := [][]string{
		{"f", "public/images/benchmark.jpg"},
		{"p", "thumb", "800x600#"},
	}
	jobsJSON, _ := json.Marshal(jobs)
	jobsB64 := base64.RawURLEncoding.EncodeToString(jobsJSON)
	validSHA := calculateSHA(cfg.DragonflySecret, jobs)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/media/%s.jpg?sha=%s", jobsB64, validSHA), nil)
		middleware.ServeHTTP(recorder, req)
	}
}

// Benchmark comparing old vs new string concatenation approach
// This simulates the old approach for comparison
func BenchmarkStringConcatenation_Old(b *testing.B) {
	jobs := [][]string{
		{"f", "public/images/benchmark.jpg"},
		{"p", "thumb", "800x600#"},
		{"p", "thumb", "400x300>"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		message := ""
		for _, job := range jobs {
			switch job[0] {
			case "f":
				message += "f" + job[1]
			case "p":
				message += "p" + job[1] + job[2]
			}
		}
		_ = message
	}
}

// Benchmark for the new strings.Builder approach
func BenchmarkStringConcatenation_New(b *testing.B) {
	jobs := [][]string{
		{"f", "public/images/benchmark.jpg"},
		{"p", "thumb", "800x600#"},
		{"p", "thumb", "400x300>"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var builder strings.Builder
		for _, job := range jobs {
			switch job[0] {
			case "f":
				builder.WriteString("f")
				builder.WriteString(job[1])
			case "p":
				builder.WriteString("p")
				builder.WriteString(job[1])
				builder.WriteString(job[2])
			}
		}
		_ = builder.String()
	}
}