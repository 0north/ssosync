//go:build integration
// +build integration

/* NOTE; these require `AWS_PRFOILE="master"` */
package google_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/require"

	"github.com/awslabs/ssosync/internal/config"
	"github.com/awslabs/ssosync/internal/google"
)

// TestLiveSecretsListUsersAndGroups reads the Google admin email and service
// account key from the deployed Secrets Manager secrets, the same way the
// Lambda does, and verifies they can list users and groups in Google Workspace.
//
// Requires AWS credentials for the account hosting the SSOSyncV2* secrets:
//
//	AWS_PROFILE=<profile> make test-integration
func TestLiveSecretsListUsersAndGroups(t *testing.T) {
	s := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	secrets := config.NewSecrets(secretsmanager.New(s))

	adminEmail, err := secrets.GoogleAdminEmail()
	require.NoError(t, err, "cannot read SSOSyncV2GoogleAdminEmail")
	require.NotEmpty(t, adminEmail)

	creds, err := secrets.GoogleCredentials()
	require.NoError(t, err, "cannot read SSOSyncV2GoogleCredentials")
	require.NotEmpty(t, creds)

	client, err := google.NewClient(context.Background(), adminEmail, []byte(creds))
	require.NoError(t, err)

	users, err := client.GetUsers("")
	require.NoError(t, err, "listing users failed")
	require.NotEmpty(t, users, "expected at least one user")
	t.Logf("listed %d users", len(users))

	groups, err := client.GetGroups("")
	require.NoError(t, err, "listing groups failed")
	require.NotEmpty(t, groups, "expected at least one group")
	t.Logf("listed %d groups", len(groups))
}
