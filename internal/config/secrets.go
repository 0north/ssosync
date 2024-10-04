package config

import (
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// Secrets ...
type Secrets struct {
	svc *secretsmanager.SecretsManager
}

// NewSecrets ...
func NewSecrets(svc *secretsmanager.SecretsManager) *Secrets {
	return &Secrets{
		svc: svc,
	}
}

func (s *Secrets) GoogleAdminEmail() (string, error) {
	return s.getSecret("SSOSyncV2GoogleAdminEmail")
}

// SCIMAccessToken ...
func (s *Secrets) SCIMAccessToken() (string, error) {
	return s.getSecret("SSOSyncV2SCIMAccessToken")
}

// SCIMEndpointUrl ...
func (s *Secrets) SCIMEndpointUrl() (string, error) {
	return s.getSecret("SSOSyncV2SCIMEndpointUrl")
}

// GoogleCredentials ...
func (s *Secrets) GoogleCredentials() (string, error) {
	return s.getSecret("SSOSyncV2GoogleCredentials")
}

// Region ...
func (s *Secrets) Region() (string, error) {
	return s.getSecret("SSOSyncV2Region")
}

// Identity Store ID ...
func (s *Secrets) IdentityStoreID() (string, error) {
	return s.getSecret("SSOSyncV2IdentityStoreID")
}

func (s *Secrets) getSecret(secretKey string) (string, error) {
	r, err := s.svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretKey),
		VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		return "", err
	}

	var secretString string

	if r.SecretString != nil {
		secretString = *r.SecretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(r.SecretBinary)))
		l, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, r.SecretBinary)
		if err != nil {
			return "", err
		}
		secretString = string(decodedBinarySecretBytes[:l])
	}

	return secretString, nil
}