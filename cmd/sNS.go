package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/spf13/viper"
)

func getConfig(name string) (string, error) {
	r := viper.GetString(name)
	if len(r) == 0 {
		return "", fmt.Errorf("%s not set", name)
	}
	return r, nil
}

func writeFindingToSns(jsonInfo string) {
	region, _ := getConfig("AWS_REGION")
	snstopic, _ := getConfig("SNSTOPIC_ARN")

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)

	svc := sns.New(sess)

	_, err := svc.Publish(&sns.PublishInput{
		TopicArn: aws.String(snstopic),
		Message:  aws.String(jsonInfo),
	})
	if err != nil {
		fmt.Println(err.Error())
	}
}

