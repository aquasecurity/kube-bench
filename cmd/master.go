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
	"github.com/aquasecurity/kube-bench/check"
	"github.com/spf13/cobra"
)

// masterCmd represents the master command
var masterCmd = &cobra.Command{
	Use:   "master",
	Short: "Checks for Kubernetes master node.",
	Long:  `Checks for Kubernetes master node.`,
	Run: func(cmd *cobra.Command, args []string) {
		runChecks(check.MASTER)
	},
}

func init() {
	masterCmd.PersistentFlags().StringVarP(&masterFile,
		"file",
		"f",
		cfgDir+"/master.yaml",
		"Alternative YAML file for master checks",
	)

	RootCmd.AddCommand(masterCmd)
}
