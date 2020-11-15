package cmd

import (
	"github.com/aquasecurity/kube-bench/findings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/spf13/viper"
)

func writeFinding(in []*securityhub.AwsSecurityFinding) error {
	r := viper.GetString("AWS_REGION")
	if len(r) == 0 {
		//return errors.New("AWS_REGION environment variable missing")
		r = "us-east-1"
	}
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")},
	)
	if err != nil {
		return err
	}
	svc := securityhub.New(sess)
	p := findings.New(svc)
	perr := p.PublishFinding(in)
	if perr != nil {
		return perr
	}
	return nil
}
