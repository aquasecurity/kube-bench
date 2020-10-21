/*
Package credentials providers helper functions for dealing with AWS credentials
passed in to resource providers from CloudFormation.
*/
package credentials

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
)

// CloudFormationCredentialsProviderName ...
const CloudFormationCredentialsProviderName = "CloudFormationCredentialsProvider"

const InvalidSessionError = "InvalidSession"

// NewProvider ...
func NewProvider(accessKeyID string, secretAccessKey string, sessionToken string) credentials.Provider {
	return &CloudFormationCredentialsProvider{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}
}

// CloudFormationCredentialsProvider ...
type CloudFormationCredentialsProvider struct {
	retrieved bool

	// AccessKeyID ...
	AccessKeyID string `json:"accessKeyId"`

	// SecretAccessKey ...
	SecretAccessKey string `json:"secretAccessKey"`

	// SessionToken ...
	SessionToken string `json:"sessionToken"`
}

// Retrieve ...
func (c *CloudFormationCredentialsProvider) Retrieve() (credentials.Value, error) {
	c.retrieved = false

	value := credentials.Value{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		ProviderName:    CloudFormationCredentialsProviderName,
	}

	c.retrieved = true

	return value, nil
}

// IsExpired ...
func (c *CloudFormationCredentialsProvider) IsExpired() bool {
	return false
}

// SessionFromCredentialsProvider creates a new AWS SDK session from a credentials provider
//
// A credentials provider is an interface in the AWS SDK's credentials package (aws/credentials)
// We transform it into a session for later use in the RPDK
func SessionFromCredentialsProvider(provider credentials.Provider) *session.Session {
	creds := credentials.NewCredentials(provider)

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: creds,
		},
	}))

	return sess
}
