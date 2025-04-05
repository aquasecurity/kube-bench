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

const GCP_REGION = "GCP_REGION"
const GCP_PROJECT_ID = "GCP_PROJECT_ID"
const GCP_SCC_SOURCE_ID = "GCP_SCC_SOURCE_ID"

func writeGSCCFinding(in []*securitypb.Finding) error {
	r := viper.GetString(GCP_REGION)
	if len(r) == 0 {
		return fmt.Errorf("%s not set", GCP_REGION)
	}
	projectId := viper.GetString(GCP_PROJECT_ID)
	if len(projectId) == 0 {
		return fmt.Errorf("%s not set", GCP_PROJECT_ID)
	}
	sccSourceId := viper.GetString(GCP_SCC_SOURCE_ID)
	if len(sccSourceId) == 0 {
		return fmt.Errorf("%s not set", GCP_SCC_SOURCE_ID)
	}

	ctx := context.Background()
	client, err := securitycenter.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create SCC client: %w", err)
	}
	defer client.Close()

	p := findings.NewGSCC(client, sccSourceId)
	out, perr := p.PublishFinding(in)
	printGSCC(out)
	return perr
}

func printGSCC(out *findings.GSCCPublisherOutput) {
	if out.SuccessCount > 0 {
		log.Printf("Number of findings that were successfully imported:%v\n", out.SuccessCount)
	}
	if out.FailedCount > 0 {
		log.Printf("Number of findings that failed to import:%v\n", out.FailedCount)
		for _, f := range out.FailedFindings {
			log.Printf("ID:%s", f.Finding.GetName())
			log.Printf("Message:%s", f.Error)
		}
	}
}
