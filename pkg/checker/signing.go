package checker

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Signer signs S3 requests with AWS Signature Version 4 (header
// authentication) or Version 2 (query authentication). Both checkers
// share this implementation; the signing clock is passed explicitly so
// tests can verify signatures against published AWS test vectors.
type Signer struct {
	AccessKey string
	SecretKey string
	Region    string
}

// SignV4 adds AWS Signature Version 4 headers to the request
func (s Signer) SignV4(req *http.Request, now time.Time) error {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\n", req.Host, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		buildCanonicalQueryString(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		"UNSIGNED-PAYLOAD",
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, s.Region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashSHA256(canonicalRequest),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(sigV4SigningKey(s.SecretKey, dateStamp, s.Region), stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKey, credentialScope, signedHeaders, signature))

	return nil
}

// SignV2Query adds AWS Signature Version 2 query authentication to the
// request per the S3 REST authentication specification: HMAC-SHA1
// digest, Base64 encoding, and the Expires value in the string-to-sign.
// The Date header is omitted on query-authenticated requests.
func (s Signer) SignV2Query(req *http.Request, canonicalResource string, expiresAt time.Time) error {
	// Query authentication replaces the Date line with the Expires value
	req.Header.Del("Date")

	expires := fmt.Sprintf("%d", expiresAt.Unix())
	stringToSign := strings.Join([]string{
		req.Method,
		req.Header.Get("Content-MD5"),
		req.Header.Get("Content-Type"),
		expires,
		canonicalResource,
	}, "\n")

	mac := hmac.New(sha1.New, []byte(s.SecretKey))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	q := req.URL.Query()
	q.Set("AWSAccessKeyId", s.AccessKey)
	q.Set("Expires", expires)
	q.Set("Signature", signature)
	req.URL.RawQuery = q.Encode()

	return nil
}

// sigV2SubResources are the query parameters included in the SigV2
// canonicalized resource per the S3 specification
var sigV2SubResources = map[string]bool{
	"acl": true, "analytics": true, "cors": true, "delete": true,
	"inventory": true, "lifecycle": true, "location": true, "logging": true,
	"metrics": true, "notification": true, "partNumber": true, "policy": true,
	"replication": true, "requestPayment": true,
	"response-cache-control": true, "response-content-disposition": true,
	"response-content-encoding": true, "response-content-language": true,
	"response-content-type": true, "response-expires": true,
	"restore": true, "select": true, "select-type": true, "tagging": true,
	"torrent": true, "uploadId": true, "uploads": true, "versionId": true,
	"versioning": true, "versions": true, "website": true,
}

// BuildCanonicalResource computes the SigV2 canonicalized resource: the
// bucket, the object path, and any recognized sub-resources
func (s Signer) BuildCanonicalResource(req *http.Request, bucket string, pathStyle bool) string {
	var resource strings.Builder
	if pathStyle {
		// The path already contains the bucket
		if req.URL.Path == "" {
			resource.WriteString("/")
		} else {
			resource.WriteString(req.URL.Path)
		}
	} else {
		// Virtual-hosted style: the bucket moves into the resource path.
		// A bucket root request has Request-URI "/", so an empty path signs
		// with a trailing slash ("/bucket/?acl" in the AWS examples).
		resource.WriteString("/")
		resource.WriteString(bucket)
		if req.URL.Path == "" {
			resource.WriteString("/")
		} else {
			resource.WriteString(req.URL.Path)
		}
	}

	// Append recognized sub-resources, sorted
	values, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return resource.String()
	}
	var subs []string
	for key := range values {
		if sigV2SubResources[key] {
			if value := values.Get(key); value == "" {
				subs = append(subs, key)
			} else {
				subs = append(subs, key+"="+value)
			}
		}
	}
	if len(subs) > 0 {
		sort.Strings(subs)
		resource.WriteString("?")
		resource.WriteString(strings.Join(subs, "&"))
	}

	return resource.String()
}

// buildCanonicalQueryString builds the canonical query string according
// to the AWS SigV4 specification: URL-encoded parameters, sorted
func buildCanonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// If parsing fails, return the raw query as-is
		return rawQuery
	}

	var params []string
	for key, vals := range values {
		encodedKey := url.QueryEscape(key)
		if len(vals) == 0 {
			params = append(params, encodedKey+"=")
		} else {
			for _, val := range vals {
				params = append(params, encodedKey+"="+url.QueryEscape(val))
			}
		}
	}
	sort.Strings(params)
	return strings.Join(params, "&")
}

// sigV4SigningKey derives the SigV4 signing key from the secret
func sigV4SigningKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "s3")
	return hmacSHA256(kService, "aws4_request")
}

// hashSHA256 returns the lowercase hex SHA-256 digest of the input
func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// hmacSHA256 returns the HMAC-SHA256 of the input with the key
func hmacSHA256(key []byte, input string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}
