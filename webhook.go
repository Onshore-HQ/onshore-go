package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// VerifyWebhook checks a webhook from Onshore. Pass the body exactly as received and
// the X-Rv-Signature header. During a secret rotation the header holds two signatures;
// either is enough. Deliveries older than tolerance (5 minutes when zero) fail.
func VerifyWebhook(secret string, rawBody []byte, signatureHeader string, tolerance time.Duration) bool {
	return verifyAt(secret, rawBody, signatureHeader, tolerance, time.Now())
}

func verifyAt(secret string, rawBody []byte, header string, tolerance time.Duration, now time.Time) bool {
	if tolerance <= 0 {
		tolerance = 5 * time.Minute
	}
	var at int64 = -1
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				at = n
			}
		case "v1":
			sigs = append(sigs, v)
		}
	}
	if at < 0 {
		return false
	}
	if d := now.Sub(time.Unix(at, 0)); d > tolerance || d < -tolerance {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(at, 10) + "."))
	m.Write(rawBody)
	want := m.Sum(nil)
	ok := false
	for _, s := range sigs {
		if got, err := hex.DecodeString(s); err == nil && hmac.Equal(got, want) {
			ok = true
		}
	}
	return ok
}
