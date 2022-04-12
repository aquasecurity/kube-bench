module github.com/aquasecurity/kube-bench

go 1.16

require (
	github.com/aws/aws-sdk-go v1.43.37
	github.com/fatih/color v1.13.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/magiconair/properties v1.8.6
	github.com/onsi/ginkgo v1.16.5
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.10.0
	github.com/stretchr/testify v1.7.1
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/postgres v1.3.1
	gorm.io/gorm v1.23.3
	k8s.io/client-go v0.23.5
)
