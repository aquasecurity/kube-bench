package cmd

import (
	"fmt"

	"github.com/aquasecurity/kube-bench/findings"
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
	perr := p.PublishFinding(in)
	if perr != nil {
		return perr
	}
	return nil
}
