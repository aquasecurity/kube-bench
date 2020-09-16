// Copyright © 2017-2019 Aqua Security Software Ltd. <info@aquasec.com>
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

	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// masterCmd represents the master command
var masterCmd = &cobra.Command{
	Use:   "master",
	Short: "Run Kubernetes benchmark checks from the master.yaml file.",
	Long:  `Run Kubernetes benchmark checks from the master.yaml file in cfg/<version>.`,
	Run: func(cmd *cobra.Command, args []string) {
		bv, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
		if err != nil {
			exitWithError(fmt.Errorf("unable to determine benchmark version: %v", err))
		}

		filename := loadConfig(check.MASTER, bv)
		runChecks(check.MASTER, filename)
		writeOutput(controlsCollection)
	},
}

func init() {
	masterCmd.PersistentFlags().StringVarP(&masterFile,
		"file",
		"f",
		"/master.yaml",
		"Alternative YAML file for master checks",
	)

	RootCmd.AddCommand(masterCmd)
}
