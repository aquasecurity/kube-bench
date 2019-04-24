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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

var (
	errmsgs string
)

func runChecks(nodetype check.NodeType) {
	var summary check.Summary

	def := loadConfig(nodetype)
	in, err := ioutil.ReadFile(def)
	if err != nil {
		exitWithError(fmt.Errorf("error opening %s controls file: %v", nodetype, err))
	}

	glog.V(1).Info(fmt.Sprintf("Using benchmark file: %s\n", def))

	// Get the set of exectuables and config files we care about on this type of node.
	typeConf := viper.Sub(string(nodetype))
	binmap, err := getBinaries(typeConf)

	// Checks that the executables we need for the node type are running.
	if err != nil {
		exitWithError(err)
	}

	confmap := getConfigFiles(typeConf)
	svcmap := getServiceFiles(typeConf)
	kubeconfmap := getKubeConfigFiles(typeConf)

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s = makeSubstitutions(s, "bin", binmap)
	s = makeSubstitutions(s, "conf", confmap)
	s = makeSubstitutions(s, "svc", svcmap)
	s = makeSubstitutions(s, "kubeconfig", kubeconfmap)

	controls, err := check.NewControls(nodetype, []byte(s))
	if err != nil {
		exitWithError(fmt.Errorf("error setting up %s controls: %v", nodetype, err))
	}

	if groupList != "" && checkList == "" {
		ids := cleanIDs(groupList)
		summary = controls.RunGroup(ids...)
	} else if checkList != "" && groupList == "" {
		ids := cleanIDs(checkList)
		summary = controls.RunChecks(ids...)
	} else if checkList != "" && groupList != "" {
		exitWithError(fmt.Errorf("group option and check option can't be used together"))
	} else {
		summary = controls.RunGroup()
	}

	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
		}

		fmt.Println(string(out))
	} else {
		// if we want to store in PostgreSQL, convert to JSON and save it
		if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && pgSQL {
			out, err := controls.JSON()
			if err != nil {
				exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
			}

			savePgsql(string(out))
		} else {
			prettyPrint(controls, summary)
		}
	}
}

// colorPrint outputs the state in a specific colour, along with a message string
func colorPrint(state check.State, s string) {
	colors[state].Printf("[%s] ", state)
	fmt.Printf("%s", s)
}

// prettyPrint outputs the results to stdout in human-readable format
func prettyPrint(r *check.Controls, summary check.Summary) {
	// Print check results.
	if !noResults {
		colorPrint(check.INFO, fmt.Sprintf("%s %s\n", r.ID, r.Text))
		for _, g := range r.Groups {
			colorPrint(check.INFO, fmt.Sprintf("%s %s\n", g.ID, g.Text))
			for _, c := range g.Checks {
				colorPrint(c.State, fmt.Sprintf("%s %s\n", c.ID, c.Text))
			}
		}

		fmt.Println()
	}

	// Print remediations.
	if !noRemediations {
		if summary.Fail > 0 || summary.Warn > 0 {
			colors[check.WARN].Printf("== Remediations ==\n")
			for _, g := range r.Groups {
				for _, c := range g.Checks {
					if c.State == check.FAIL || c.State == check.WARN {
						fmt.Printf("%s %s\n", c.ID, c.Remediation)
					}
				}
			}
			fmt.Println()
		}
	}

	// Print summary setting output color to highest severity.
	if !noSummary {
		var res check.State
		if summary.Fail > 0 {
			res = check.FAIL
		} else if summary.Warn > 0 {
			res = check.WARN
		} else {
			res = check.PASS
		}

		colors[res].Printf("== Summary ==\n")
		fmt.Printf("%d checks PASS\n%d checks FAIL\n%d checks WARN\n%d checks INFO\n",
			summary.Pass, summary.Fail, summary.Warn, summary.Info,
		)
	}
}

// loadConfig finds the correct config dir based on the kubernetes version,
// merges any specific config.yaml file found with the main config
// and returns the benchmark file to use.
func loadConfig(nodetype check.NodeType) string {
	var file string
	var err error

	switch nodetype {
	case check.MASTER:
		file = masterFile
	case check.NODE:
		file = nodeFile
	case check.FEDERATED:
		file = federatedFile
	}

	runningVersion := ""
	if kubeVersion == "" {
		runningVersion, err = getKubeVersion()
		if err != nil {
			exitWithError(fmt.Errorf("Version check failed: %s\nAlternatively, you can specify the version with --version", err))
		}
	}
	path, err := getConfigFilePath(kubeVersion, runningVersion, file)
	if err != nil {
		exitWithError(fmt.Errorf("can't find %s controls file in %s: %v", nodetype, cfgDir, err))
	}

	// Merge kubernetes version specific config if any.
	viper.SetConfigFile(path + "/config.yaml")
	err = viper.MergeInConfig()
	if err != nil {
		if os.IsNotExist(err) {
			glog.V(2).Info(fmt.Sprintf("No version-specific config.yaml file in %s", path))
		} else {
			exitWithError(fmt.Errorf("couldn't read config file %s: %v", path+"/config.yaml", err))
		}
	} else {
		glog.V(1).Info(fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))
	}
	return filepath.Join(path, file)
}

// isMaster verify if master components are running on the node.
func isMaster() bool {
	glog.V(2).Info("Checking if the current node is running master components")
	masterConf := viper.Sub(string(check.MASTER))
	components, err := getBinaries(masterConf)

	if err != nil {
		glog.V(2).Info(err)
		return false
	}
	if len(components) == 0 {
		glog.V(2).Info("No master binaries specified")
		return false
	}
	return true
}
