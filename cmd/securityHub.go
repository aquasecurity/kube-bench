package cmd

import (
	"github.com/aquasecurity/kube-bench/findings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

func writeFinding(in []*securityhub.AwsSecurityFinding) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)
	if err != nil {
		return err
	}
	svc := securityhub.New(sess)
	p := findings.New(svc)
	perr := p.PublishFinding(in)
	if err != nil {
		return perr
	}
	return nil
}
