# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a Traefik plugin middleware that translates Dragonfly image URLs to imgproxy format. Dragonfly is a Ruby gem for on-the-fly image processing, while imgproxy is a fast and secure standalone image processing server.

## Essential Commands

```bash
# Run tests
go test -v ./...

# Build the plugin
go build -v ./...

# Update dependencies
go mod tidy

# Run a specific test
go test -v -run TestServeHTTP

# Check for any issues
go vet ./...
```

## Architecture Overview

### URL Translation Flow

1. **Input Format**: `/media/BASE64_ENCODED_JOBS.jpg?sha=SIGNATURE`
   - BASE64_ENCODED_JOBS contains JSON array of image processing jobs
   - SHA is HMAC-SHA256 signature for security validation

2. **Output Format**: `/insecure/OPERATIONS/plain/IMAGE_URL`
   - Example: `/insecure/rs:fill:400:300:g:ce/plain/https://images.example.com/public/image.jpg`

### Core Components

- **ServeHTTP**: Main entry point that intercepts requests and performs URL translation
- **calculateSHA**: Validates request signatures using HMAC-SHA256
- **generate_imgproxy_url**: Constructs imgproxy URLs from Dragonfly job specifications

### Job Types

- **"f" (fetch)**: Specifies the source image URL
- **"p" (process)**: Defines image transformations (currently only supports "thumb" operations)

### Performance Considerations

The codebase uses `strings.Builder` for efficient string concatenation and pre-compiled regex patterns stored as package variables.

## Configuration

Required configuration in Traefik:
```yaml
dragonflySecret: "your-secret-key"  # Required for HMAC validation
urlPrefix: "https://your-cdn.com/"  # Base URL for image sources
```

## Testing Strategy

The test suite covers:
- URL parsing and base64 decoding
- SHA signature validation
- Image format detection (GIF, SVG special handling)
- Error cases (invalid URLs, missing signatures, etc.)
- URL encoding edge cases (spaces, special characters)

## Special Features

- **convert=false**: Query parameter to disable Accept header (prevents automatic format conversion)
- **GIF preservation**: Automatically adds `/f:gif` for GIF files during resize operations
- **SVG handling**: Forces SVG format output for SVG inputs
- **Custom URL encoding**: Preserves spaces as %20 instead of +