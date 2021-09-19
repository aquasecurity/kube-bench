module github.com/aquasecurity/kube-bench

go 1.16

require (
	github.com/aws/aws-sdk-go v1.40.37
	github.com/fatih/color v1.12.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/magiconair/properties v1.8.5
	github.com/onsi/ginkgo v1.16.4
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/postgres v1.1.1
	gorm.io/gorm v1.21.15
	k8s.io/client-go v0.22.1
)
