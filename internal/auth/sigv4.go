package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// multiSpaceRE collapses runs of whitespace to a single space, as required by
// the SigV4 canonical-header spec.
var multiSpaceRE = regexp.MustCompile(`\s+`)

// AWSSigV4 implements a simplified AWS Signature V4 signer sufficient for
// JSON API calls (Bedrock, Lambda invoke, Secrets Manager). It does NOT
// handle all SigV4 edge cases (e.g. S3 chunked uploads, presigned URLs,
// repeated query params with value sorting). For full SigV4 compliance,
// inject a RequestTransformer backed by the official AWS SDK signer.
type AWSSigV4 struct {
	accessKey    string
	secretKey    string
	sessionToken string
	region       string
	service      string
}

// NewAWSSigV4 creates an AWSSigV4 signer.
func NewAWSSigV4(accessKey, secretKey, sessionToken, region, service string) *AWSSigV4 {
	return &AWSSigV4{
		accessKey:    accessKey,
		secretKey:    secretKey,
		sessionToken: sessionToken,
		region:       region,
		service:      service,
	}
}

// Transform signs the HTTP request with AWS SigV4.
func (s *AWSSigV4) Transform(req *http.Request) error {
	// 1. Read body and compute payload hash
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("auth: sigv4: read body: %w", err)
		}
	}
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Reset body
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	// 2. Set X-Amz-Date if not already set (allows tests to pin timestamp)
	amzDate := req.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = time.Now().UTC().Format("20060102T150405Z")
		req.Header.Set("X-Amz-Date", amzDate)
	}
	dateStamp := amzDate[:8]

	// 3. Set security token if present
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}

	// 4. Ensure Host header is set
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}

	// Build signed headers list
	signedHeaders := s.buildSignedHeaders(req)
	signedHeaderStr := strings.Join(signedHeaders, ";")

	// Build canonical headers
	canonicalHeaders := s.buildCanonicalHeaders(req, signedHeaders)

	// Build canonical request
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := s.buildCanonicalQueryString(req.URL)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaderStr,
		payloadHash,
	}, "\n")

	// 5. Build string to sign
	scope := dateStamp + "/" + s.region + "/" + s.service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// 6. Derive signing key
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte(s.service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// 7. Compute signature
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	// 8. Set Authorization header
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signedHeaderStr, signature,
	)
	req.Header.Set("Authorization", authHeader)

	return nil
}

func (s *AWSSigV4) buildSignedHeaders(req *http.Request) []string {
	headers := make(map[string]bool)
	// Always include host, x-amz-content-sha256, x-amz-date
	headers["host"] = true
	headers["x-amz-content-sha256"] = true
	headers["x-amz-date"] = true
	if s.sessionToken != "" {
		headers["x-amz-security-token"] = true
	}
	// Include any x-amz- headers
	for key := range req.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-") {
			headers[lower] = true
		}
	}

	sorted := make([]string, 0, len(headers))
	for h := range headers {
		sorted = append(sorted, h)
	}
	sort.Strings(sorted)
	return sorted
}

func (s *AWSSigV4) buildCanonicalHeaders(req *http.Request, signedHeaders []string) string {
	var b strings.Builder
	for _, h := range signedHeaders {
		var val string
		if h == "host" {
			val = req.Host
			if val == "" {
				val = req.URL.Host
			}
		} else {
			val = req.Header.Get(h)
		}
		// AWS SigV4 requires trimming leading/trailing whitespace and
		// collapsing sequential spaces to a single space.
		val = strings.TrimSpace(val)
		val = multiSpaceRE.ReplaceAllString(val, " ")
		b.WriteString(h)
		b.WriteByte(':')
		b.WriteString(val)
		b.WriteByte('\n')
	}
	return b.String()
}

func (s *AWSSigV4) buildCanonicalQueryString(u *url.URL) string {
	return canonicalQueryString(u.RawQuery)
}

// canonicalQueryString builds the SigV4 canonical query string. It re-encodes
// each key=value pair with AWS URI encoding (%20 for spaces, not +) and sorts
// the encoded pairs lexicographically.
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	params := strings.Split(rawQuery, "&")
	var encoded []string
	for _, p := range params {
		k, v, _ := strings.Cut(p, "=")
		encoded = append(encoded, awsURIEncode(k)+"="+awsURIEncode(v))
	}
	sort.Strings(encoded)
	return strings.Join(encoded, "&")
}

// awsURIEncode percent-encodes a string using the AWS URI encoding rules:
// unreserved characters (A-Z a-z 0-9 - _ . ~) are not encoded; everything
// else is percent-encoded with uppercase hex digits. Notably, spaces become
// %20 (not +).
func awsURIEncode(s string) string {
	var buf strings.Builder
	for _, b := range []byte(s) {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~' {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "%%%02X", b)
		}
	}
	return buf.String()
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
