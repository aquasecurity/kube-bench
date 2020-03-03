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
	goflag "flag"
	"fmt"
	"os"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type FilterOpts struct {
	CheckList string
	GroupList string
	Scored    bool
	Unscored  bool
}

var (
	envVarsPrefix       = "KUBE_BENCH"
	defaultKubeVersion  = "1.11"
	kubeVersion         string
	benchmarkVersion    string
	cfgFile             string
	cfgDir              = "./cfg/"
	jsonFmt             bool
	junitFmt            bool
	pgSQL               bool
	masterFile          = "master.yaml"
	nodeFile            = "node.yaml"
	etcdFile            = "etcd.yaml"
	controlplaneFile    = "controlplane.yaml"
	policiesFile        = "policies.yaml"
	managedservicesFile = "managedservices.yaml"
	noResults           bool
	noSummary           bool
	noRemediations      bool
	filterOpts          FilterOpts
	includeTestOutput   bool
	outputFile          string
	configFileError     error
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   os.Args[0],
	Short: "Run CIS Benchmarks checks against a Kubernetes deployment",
	Long:  `This tool runs the CIS Kubernetes Benchmark (https://www.cisecurity.org/benchmark/kubernetes/)`,
	Run: func(cmd *cobra.Command, args []string) {
		benchmarkVersion, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
		if err != nil {
			exitWithError(fmt.Errorf("unable to determine benchmark version: %v", err))
		}

		if isMaster() {
			glog.V(1).Info("== Running master checks ==\n")
			runChecks(check.MASTER, loadConfig(check.MASTER))

			// Control Plane is only valid for CIS 1.5 and later,
			// this a gatekeeper for previous versions
			if validTargets(benchmarkVersion, []string{string(check.CONTROLPLANE)}) {
				glog.V(1).Info("== Running control plane checks ==\n")
				runChecks(check.CONTROLPLANE, loadConfig(check.CONTROLPLANE))
			}
		}

		// Etcd is only valid for CIS 1.5 and later,
		// this a gatekeeper for previous versions.
		if validTargets(benchmarkVersion, []string{string(check.ETCD)}) && isEtcd() {
			glog.V(1).Info("== Running etcd checks ==\n")
			runChecks(check.ETCD, loadConfig(check.ETCD))
		}

		glog.V(1).Info("== Running node checks ==\n")
		runChecks(check.NODE, loadConfig(check.NODE))

		// Policies is only valid for CIS 1.5 and later,
		// this a gatekeeper for previous versions.
		if validTargets(benchmarkVersion, []string{string(check.POLICIES)}) {
			glog.V(1).Info("== Running policies checks ==\n")
			runChecks(check.POLICIES, loadConfig(check.POLICIES))
		}

		// Managedservices is only valid for GKE 1.0 and later,
		// this a gatekeeper for previous versions.
		if validTargets(benchmarkVersion, []string{string(check.MANAGEDSERVICES)}) {
			glog.V(1).Info("== Running managed services checks ==\n")
			runChecks(check.MANAGEDSERVICES, loadConfig(check.MANAGEDSERVICES))
		}

	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	goflag.CommandLine.Parse([]string{})

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		// flush before exit non-zero
		glog.Flush()
		os.Exit(-1)
	}
	// flush before exit
	glog.Flush()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Output control
	RootCmd.PersistentFlags().BoolVar(&noResults, "noresults", false, "Disable printing of results section")
	RootCmd.PersistentFlags().BoolVar(&noSummary, "nosummary", false, "Disable printing of summary section")
	RootCmd.PersistentFlags().BoolVar(&noRemediations, "noremediations", false, "Disable printing of remediations section")
	RootCmd.PersistentFlags().BoolVar(&jsonFmt, "json", false, "Prints the results as JSON")
	RootCmd.PersistentFlags().BoolVar(&junitFmt, "junit", false, "Prints the results as JUnit")
	RootCmd.PersistentFlags().BoolVar(&pgSQL, "pgsql", false, "Save the results to PostgreSQL")
	RootCmd.PersistentFlags().BoolVar(&filterOpts.Scored, "scored", true, "Run the scored CIS checks")
	RootCmd.PersistentFlags().BoolVar(&filterOpts.Unscored, "unscored", true, "Run the unscored CIS checks")
	RootCmd.PersistentFlags().BoolVar(&includeTestOutput, "include-test-output", false, "Prints the actual result when test fails")
	RootCmd.PersistentFlags().StringVar(&outputFile, "outputfile", "", "Writes the JSON results to output file")

	RootCmd.PersistentFlags().StringVarP(
		&filterOpts.CheckList,
		"check",
		"c",
		"",
		`A comma-delimited list of checks to run as specified in CIS document. Example --check="1.1.1,1.1.2"`,
	)
	RootCmd.PersistentFlags().StringVarP(
		&filterOpts.GroupList,
		"group",
		"g",
		"",
		`Run all the checks under this comma-delimited list of groups. Example --group="1.1"`,
	)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./cfg/config.yaml)")
	RootCmd.PersistentFlags().StringVarP(&cfgDir, "config-dir", "D", cfgDir, "config directory")
	RootCmd.PersistentFlags().StringVar(&kubeVersion, "version", "", "Manually specify Kubernetes version, automatically detected if unset")
	RootCmd.PersistentFlags().StringVar(&benchmarkVersion, "benchmark", "", "Manually specify CIS benchmark version. It would be an error to specify both --version and --benchmark flags")

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

	// Read flag values from environment variables.
	// Precedence: Command line flags take precedence over environment variables.
	viper.SetEnvPrefix(envVarsPrefix)
	viper.AutomaticEnv()

	if kubeVersion == "" {
		if env := viper.Get("version"); env != nil {
			kubeVersion = env.(string)
		}
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error for now to prevent commands
			// which don't need the config file exiting.
			configFileError = err
		} else {
			// Config file was found but another error was produced
			colorPrint(check.FAIL, fmt.Sprintf("Failed to read config file: %v\n", err))
			os.Exit(1)
		}
	}
}
