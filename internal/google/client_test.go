package google

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/google"
)

func serviceAccountJSON(t *testing.T, privateKey string) []byte {
	b, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "test@example.iam.gserviceaccount.com",
		"private_key":  privateKey,
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	return b
}

func TestNormalizeServiceAccountKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))

	tests := map[string]string{
		"valid":               validPEM,
		"valid pkcs1":         pkcs1PEM,
		"literal newlines":    strings.ReplaceAll(validPEM, "\n", `\n`),
		"double-escaped":      strings.ReplaceAll(validPEM, "\n", `\\n`),
		"literal crlf":        strings.ReplaceAll(validPEM, "\n", `\r\n`),
		"spaces for newlines": strings.ReplaceAll(validPEM, "\n", " "),
		"newlines stripped":   strings.ReplaceAll(validPEM, "\n", ""),
		"pkcs1 literal \\n":   strings.ReplaceAll(pkcs1PEM, "\n", `\n`),
		"bare base64, no PEM": base64.StdEncoding.EncodeToString(der),
	}

	for name, privateKey := range tests {
		t.Run(name, func(t *testing.T) {
			raw := serviceAccountJSON(t, privateKey)

			normalized, err := normalizeServiceAccountKey(raw)
			require.NoError(t, err)

			cfg, err := google.JWTConfigFromJSON(normalized)
			require.NoError(t, err)

			// Mirrors golang.org/x/oauth2/internal.ParseKey, which runs lazily
			// when the first token is requested.
			block, _ := pem.Decode(cfg.PrivateKey)
			require.NotNil(t, block, "private key is not PEM")
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}
			require.NoError(t, err)
			assert.Equal(t, rsaKey.D, parsed.(*rsa.PrivateKey).D)
		})
	}
}

func TestNormalizeServiceAccountKeyPassesThroughInvalidInput(t *testing.T) {
	for _, in := range [][]byte{[]byte("not json"), []byte(`{"type":"service_account"}`)} {
		out, err := normalizeServiceAccountKey(in)
		require.NoError(t, err)
		assert.Equal(t, in, out)
	}
}
