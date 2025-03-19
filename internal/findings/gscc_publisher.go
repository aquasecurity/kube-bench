package findings

import (
	"context"
	"fmt"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	securitypb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/pkg/errors"
)

// Publisher represents an object that publishes findings to GCP Security Command Center (SCC).
type GSCCPublisher struct {
	client *securitycenter.Client // GCP SCC Client
	sourceID string               // SCC Source ID
}

type GSCCPublisherOutput struct {
	// The number of findings that failed to import.
	//
	// FailedCount is a required field
	FailedCount int32

	// The list of findings that failed to import.
	FailedFindings []string

	// The number of findings that were successfully imported.
	//
	// SuccessCount is a required field
	SuccessCount int32
}

// New creates a new Publisher.
func NewGSCC(client *securitycenter.Client, sourceID string) *GSCCPublisher {
	return &GSCCPublisher{
		client:   client,
		sourceID: sourceID,
	}
}

// PublishFinding publishes findings to GCP SCC.
func (p *GSCCPublisher) PublishFinding(findings []*securitypb.Finding) (*GSCCPublisherOutput, error) {
	o := GSCCPublisherOutput{}
	var errs error
	ctx := context.Background()

	for _, finding := range findings {
		req := &securitypb.CreateFindingRequest{
			Parent:    p.sourceID,
			FindingId: finding.GetName(), // Ensure unique finding ID
			Finding:   finding,
		}

		resp, err := p.client.CreateFinding(ctx, req)
		if err != nil {
			errs = errors.Wrap(err, "finding publish failed")
			o.FailedCount++
			o.FailedFindings = append(o.FailedFindings, finding.GetName())
			continue
		}
		fmt.Printf("Finding created: %s\n", resp.Name)
		o.SuccessCount++
	}

	return &o, errs
}
