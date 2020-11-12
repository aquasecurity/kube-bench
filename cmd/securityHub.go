package cmd

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

func writeFinding(findings []*securityhub.AwsSecurityFinding) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)
	if err != nil {
		return err
	}
	p := findings.New(sess)
	o, err := p.publishFinding(findings)
	if err != nil {
		return nil
	}
	return nil
}
