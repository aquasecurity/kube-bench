package findings

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/pkg/errors"
)

// A Publisher represents an object that publishes finds to AWS Security Hub.
type Publisher struct {
	client securityhub.Client // AWS Security Hub Service Client
}

// A PublisherOutput represents an object that contains information about the service call.
type PublisherOutput struct {
	// The number of findings that failed to import.
	//
	// FailedCount is a required field
	FailedCount int32

	// The list of findings that failed to import.
	FailedFindings []types.ImportFindingsError

	// The number of findings that were successfully imported.
	//
	// SuccessCount is a required field
	SuccessCount int32
}

// New creates a new Publisher.
func New(client securityhub.Client) *Publisher {
	return &Publisher{
		client: client,
	}
}

// PublishFinding publishes findings to AWS Security Hub Service
func (p *Publisher) PublishFinding(finding []types.AwsSecurityFinding) (*PublisherOutput, error) {
	o := PublisherOutput{}
	i := securityhub.BatchImportFindingsInput{}
	i.Findings = finding
	var errs error

	// Split the slice into batches of 100 finding.
	batch := 100

	for i := 0; i < len(finding); i += batch {
		i := securityhub.BatchImportFindingsInput{}
		i.Findings = finding
		r, err := p.client.BatchImportFindings(context.Background(), &i) // Process the batch.
		if err != nil {
			errs = errors.Wrap(err, "finding publish failed")
		}
		if r != nil {
			if r.FailedCount != 0 {
				o.FailedCount += r.FailedCount
			}
			if r.SuccessCount != 0 {
				o.SuccessCount += r.SuccessCount
			}
			o.FailedFindings = append(o.FailedFindings, r.FailedFindings...)
		}
	}
	return &o, errs
}
