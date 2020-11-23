package findings

import (
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
	"github.com/pkg/errors"
)

// A Publisher represents an object that publishes finds to AWS Security Hub.
type Publisher struct {
	client securityhubiface.SecurityHubAPI // AWS Security Hub Service Client
}

// A PublisherOutput represents an object that contains information about the service call.
type PublisherOutput struct {
	// The number of findings that failed to import.
	//
	// FailedCount is a required field
	FailedCount int64

	// The list of findings that failed to import.
	FailedFindings []*securityhub.ImportFindingsError

	// The number of findings that were successfully imported.
	//
	// SuccessCount is a required field
	SuccessCount int64
}

// New creates a new Publisher.
func New(client securityhubiface.SecurityHubAPI) *Publisher {
	return &Publisher{
		client: client,
	}
}

// PublishFinding publishes findings to AWS Security Hub Service
func (p *Publisher) PublishFinding(finding []*securityhub.AwsSecurityFinding) (*PublisherOutput, error) {
	o := PublisherOutput{}
	i := securityhub.BatchImportFindingsInput{}
	i.Findings = finding
	var errs error

	// Split the slice into batches of 100 finding.
	batch := 100

	for i := 0; i < len(finding); i += batch {
		j := i + batch
		if j > len(finding) {
			j = len(finding)
		}
		i := securityhub.BatchImportFindingsInput{}
		i.Findings = finding
		r, err := p.client.BatchImportFindings(&i) // Process the batch.
		if err != nil {
			errs = errors.Wrap(err, "finding publish failed")
		}
		if r.FailedCount != nil {
			o.FailedCount += *r.FailedCount
		}
		if r.SuccessCount != nil {
			o.SuccessCount += *r.SuccessCount
		}
		for _, ff := range r.FailedFindings {
			o.FailedFindings = append(o.FailedFindings, ff)
		}
	}
	return &o, errs
}
