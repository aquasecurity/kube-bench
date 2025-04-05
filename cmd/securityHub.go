package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/aquasecurity/kube-bench/internal/findings"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/spf13/viper"
)

// REGION ...
const AWS_REGION = "AWS_REGION"

func writeASSFFinding(in []types.AwsSecurityFinding) error {
	r := viper.GetString(AWS_REGION)
	if len(r) == 0 {
		return fmt.Errorf("%s not set", AWS_REGION)
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(r))
	if err != nil {
		return err
	}

	svc := securityhub.NewFromConfig(cfg)
	p := findings.New(*svc)
	out, perr := p.PublishFinding(in)
	printASSF(out)
	return perr
}

func printASSF(out *findings.PublisherOutput) {
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
