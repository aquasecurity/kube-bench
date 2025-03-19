package cmd

import (
	"context"
	"fmt"
	"log"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	securitypb "cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/aquasecurity/kube-bench/internal/findings"
	"github.com/spf13/viper"
)

// GCP_REGION and ORG_ID should be set in the config
const GCP_REGION = "GCP_REGION"
const ORG_ID = "GCP_ORG_ID"

func writeGSCCFinding(in []*securitypb.Finding) error {
	r := viper.GetString(GCP_REGION)
	if len(r) == 0 {
		return fmt.Errorf("%s not set", GCP_REGION)
	}
	orgId := viper.GetString(ORG_ID)
	if len(orgId) == 0 {
		return fmt.Errorf("%s not set", ORG_ID)
	}
	ctx := context.Background()
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create SCC client: %w", err)
	}
	defer client.Close()
	
	// SCC Source ID - replace with your actual SCC source ID
	sourceID := fmt.Sprintf("organizations/%s/sources/1234567890", orgId)

// Iterate over findings and publish them
	for _, f := range in {
		req := &securitypb.CreateFindingRequest{
			Parent:    sourceID,
			FindingId: f.GetName(), // Ensure unique finding ID
			Finding:   f,
		}

		resp, err := client.CreateFinding(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to create finding %s: %w", f.GetName(), err)
		}
		fmt.Printf("Finding created: %s\n", resp.Name)
	}

	return nil

	// svc := securityhub.NewFromConfig(cfg)
	// p := findings.New(*svc)
	// out, perr := p.GSCCPublishFinding(in)
	// printGSCC(out)
	// return perr
}

func printGSCC(out *findings.PublisherOutput) {
	if out.SuccessCount > 0 {
		log.Printf("Number of findings that were successfully imported:%v\n", out.SuccessCount)
	}
	if out.FailedCount > 0 {
		log.Printf("Number of findings that failed to import:%v\n", out.FailedCount)
		for _, f := range out.FailedFindings {
			log.Printf("ID:%s", *f.Id)
			log.Printf("Message:%s", *f.ErrorMessage)
			log.Printf("Error Code:%s", *f.ErrorCode)
		}
	}
}
