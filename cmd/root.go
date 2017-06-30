// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgDir  = "./cfg"
	cfgFile string

	jsonFmt       bool
	checkList     string
	groupList     string
	masterFile    string
	nodeFile      string
	federatedFile string

	kubeConfDir     string
	etcdConfDir     string
	flanneldConfDir string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   os.Args[0],
	Short: "Run CIS Benchmarks checks against a Kubernetes deployment",
	Long:  `This tool runs the CIS Kubernetes 1.6 Benchmark v1.0.0 checks.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	RootCmd.PersistentFlags().StringVarP(&checkList,
		"check",
		"c",
		"",
		`A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"`,
	)
	RootCmd.PersistentFlags().StringVarP(&groupList,
		"group",
		"g",
		"",
		`Run all the checks under this comma-delimited list of groups. Example --group="1.1"`,
	)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./cfg/config.yaml)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config") // name of config file (without extension)
		viper.AddConfigPath(cfgDir)   // adding ./cfg as first search path
	}

	viper.SetEnvPrefix("CISK8S")
	viper.AutomaticEnv() // read in environment variables that match

	// Set defaults
	viper.SetDefault("kubeConfDir", "/etc/kubernetes")
	viper.SetDefault("etcdConfDir", "/etc/etcd")
	viper.SetDefault("flanneldConfDir", "/etc/sysconfig")

	viper.SetDefault("masterFile", cfgDir+"/master.yaml")
	viper.SetDefault("nodeFile", cfgDir+"/node.yaml")
	viper.SetDefault("federatedFile", cfgDir+"/federated.yaml")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		colorPrint(check.FAIL, fmt.Sprintf("Failed to read config file: %v\n", err))
		os.Exit(1)
	}
}
