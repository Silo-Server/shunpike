package n4

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
)

// PinnedTLS authenticates TLS 1.3 peers by an already trusted base64 SHA-256
// SPKI digest. Malformed pins, absent certificates and mismatches fail closed.
// Callers set ALPN. Certificate chain and hostname trust come from the pin.
func PinnedTLS(spkiSHA256Base64 string) *tls.Config {
	want, decodeErr := base64.StdEncoding.DecodeString(spkiSHA256Base64)
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if decodeErr != nil || len(want) != sha256.Size || len(cs.PeerCertificates) == 0 {
			return errors.New("invalid TLS pin or missing certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return errors.New("TLS SPKI pin mismatch")
		}
		return nil
	}}
}
