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

package main

import (
	goflag "flag"
	"fmt"
	"os"

	"github.com/aquasecurity/bench-common/check"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	envVarsPrefix      = "KUBE_BENCH"
	defaultKubeVersion = "1.6"
	kubeVersion        string
	cfgFile            string
	cfgDir             string
	jsonFmt            bool
	pgSQL              bool
	checkList          string
	groupList          string
	masterFile         string
	nodeFile           string
	federatedFile      string
	noResults          bool
	noSummary          bool
	noRemediations     bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   os.Args[0],
	Short: "Run CIS Benchmarks checks against a Kubernetes deployment",
	Long:  `This tool runs the CIS Kubernetes Benchmark (http://www.cisecurity.org/benchmark/kubernetes/)`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	goflag.Set("logtostderr", "true")
	goflag.CommandLine.Parse([]string{})

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Output control
	RootCmd.PersistentFlags().BoolVar(&noResults, "noresults", false, "Disable printing of results section")
	RootCmd.PersistentFlags().BoolVar(&noSummary, "nosummary", false, "Disable printing of summary section")
	RootCmd.PersistentFlags().BoolVar(&noRemediations, "noremediations", false, "Disable printing of remediations section")
	RootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	RootCmd.PersistentFlags().BoolVar(&pgSQL, "pgsql", false, "Save the results to PostgreSQL")

	RootCmd.PersistentFlags().StringVarP(
		&checkList,
		"check",
		"c",
		"",
		`A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"`,
	)
	RootCmd.PersistentFlags().StringVarP(
		&groupList,
		"group",
		"g",
		"",
		`Run all the checks under this comma-delimited list of groups. Example --group="1.1"`,
	)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./cfg/config.yaml)")
	RootCmd.PersistentFlags().StringVarP(&cfgDir, "config-dir", "D", "./cfg/", "config directory")
	RootCmd.PersistentFlags().StringVar(&kubeVersion, "version", "", "Manually specify Kubernetes version, automatically detected if unset")

	goflag.CommandLine.VisitAll(func(goflag *goflag.Flag) {
		RootCmd.PersistentFlags().AddGoFlag(goflag)
	})

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config") // name of config file (without extension)
		viper.AddConfigPath(cfgDir)   // adding ./cfg as first search path
	}

	viper.SetEnvPrefix(envVarsPrefix)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		colorPrint(check.FAIL, fmt.Sprintf("Failed to read config file: %v\n", err))
		os.Exit(1)
	}
}
