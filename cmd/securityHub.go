package cmd

import (
	"fmt"
	"log"

	"github.com/aquasecurity/kube-bench/internal/findings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/spf13/viper"
)

//REGION ...
const REGION = "AWS_REGION"

func writeFinding(in []*securityhub.AwsSecurityFinding) error {
	r := viper.GetString(REGION)
	if len(r) == 0 {
		return fmt.Errorf("%s not set", REGION)
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(r)},
	)
	if err != nil {
		return err
	}
	svc := securityhub.New(sess)
	p := findings.New(svc)
	out, perr := p.PublishFinding(in)
	print(out)
	return perr
}

func print(out *findings.PublisherOutput) {
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
