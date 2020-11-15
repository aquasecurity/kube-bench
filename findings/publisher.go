package findings

import (
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
	"github.com/pkg/errors"
)

// A Publisher represents an object that publishes metrics to AWS Cloudwatch.
type Publisher struct {
	client securityhubiface.SecurityHubAPI // AWS Security Hub Service Client
}

// New creates a new Publisher.
func New(client securityhubiface.SecurityHubAPI) *Publisher {
	return &Publisher{
		client: client,
	}
}

func (p *Publisher) PublishFinding(finding []*securityhub.AwsSecurityFinding) error {
	i := securityhub.BatchImportFindingsInput{}
	i.Findings = finding
	var errs error = nil

	// Split the slice into batches of 100 finding.
	batch := 100

	for i := 0; i < len(finding); i += batch {
		j := i + batch
		if j > len(finding) {
			j = len(finding)
		}
		i := securityhub.BatchImportFindingsInput{}
		i.Findings = finding
		o, err := p.client.BatchImportFindings(&i) // Process the batch.
		if o.FailedCount == nil {
			errs = errors.Wrap(err, "finding publish failed")
		}
		if err != nil {
			errs = errors.Wrap(err, "finding publish failed")
		}
	}
	return errs
}
