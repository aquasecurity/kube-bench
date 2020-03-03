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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// NewRunFilter constructs a Predicate based on FilterOpts which determines whether tested Checks should be run or not.
func NewRunFilter(opts FilterOpts) (check.Predicate, error) {

	if opts.CheckList != "" && opts.GroupList != "" {
		return nil, fmt.Errorf("group option and check option can't be used together")
	}

	var groupIDs map[string]bool
	if opts.GroupList != "" {
		groupIDs = cleanIDs(opts.GroupList)
	}

	var checkIDs map[string]bool
	if opts.CheckList != "" {
		checkIDs = cleanIDs(opts.CheckList)
	}

	return func(g *check.Group, c *check.Check) bool {
		var test = true
		if len(groupIDs) > 0 {
			_, ok := groupIDs[g.ID]
			test = test && ok
		}

		if len(checkIDs) > 0 {
			_, ok := checkIDs[c.ID]
			test = test && ok
		}

		test = test && (opts.Scored && c.Scored || opts.Unscored && !c.Scored)

		return test
	}, nil
}

func runChecks(nodetype check.NodeType, testYamlFile string) {
	var summary check.Summary

	// Verify config file was loaded into Viper during Cobra sub-command initialization.
	if configFileError != nil {
		colorPrint(check.FAIL, fmt.Sprintf("Failed to read config file: %v\n", configFileError))
		os.Exit(1)
	}

	in, err := ioutil.ReadFile(testYamlFile)
	if err != nil {
		exitWithError(fmt.Errorf("error opening %s test file: %v", testYamlFile, err))
	}

	glog.V(1).Info(fmt.Sprintf("Using test file: %s\n", testYamlFile))

	// Get the viper config for this section of tests
	typeConf := viper.Sub(string(nodetype))
	if typeConf == nil {
		colorPrint(check.FAIL, fmt.Sprintf("No config settings for %s\n", string(nodetype)))
		os.Exit(1)
	}

	// Get the set of executables we need for this section of the tests
	binmap, err := getBinaries(typeConf, nodetype)

	// Checks that the executables we need for the section are running.
	if err != nil {
		exitWithError(fmt.Errorf("failed to get a set of executables needed for tests: %v", err))
	}

	confmap := getFiles(typeConf, "config")
	svcmap := getFiles(typeConf, "service")
	kubeconfmap := getFiles(typeConf, "kubeconfig")
	cafilemap := getFiles(typeConf, "ca")

	// Variable substitutions. Replace all occurrences of variables in controls files.
	s := string(in)
	s = makeSubstitutions(s, "bin", binmap)
	s = makeSubstitutions(s, "conf", confmap)
	s = makeSubstitutions(s, "svc", svcmap)
	s = makeSubstitutions(s, "kubeconfig", kubeconfmap)
	s = makeSubstitutions(s, "cafile", cafilemap)

	controls, err := check.NewControls(nodetype, []byte(s))
	if err != nil {
		exitWithError(fmt.Errorf("error setting up %s controls: %v", nodetype, err))
	}

	runner := check.NewRunner()
	filter, err := NewRunFilter(filterOpts)
	if err != nil {
		exitWithError(fmt.Errorf("error setting up run filter: %v", err))
	}

	summary = controls.RunChecks(runner, filter)

	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && junitFmt {
		out, err := controls.JUnit()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JUnit format: %v", err))
		}

		PrintOutput(string(out), outputFile)
		// if we successfully ran some tests and it's json format, ignore the warnings
	} else if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && jsonFmt {
		out, err := controls.JSON()
		if err != nil {
			exitWithError(fmt.Errorf("failed to output in JSON format: %v", err))
		}

		PrintOutput(string(out), outputFile)
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

				if includeTestOutput && c.State == check.FAIL && len(c.ActualValue) > 0 {
					printRawOutput(c.ActualValue)
				}
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
	case check.CONTROLPLANE:
		file = controlplaneFile
	case check.ETCD:
		file = etcdFile
	case check.POLICIES:
		file = policiesFile
	case check.MANAGEDSERVICES:
		file = managedservicesFile
	}

	benchmarkVersion, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
	if err != nil {
		exitWithError(fmt.Errorf("failed to get benchMark version: %v", err))
	}

	path, err := getConfigFilePath(benchmarkVersion, file)
	if err != nil {
		exitWithError(fmt.Errorf("can't find %s controls file in %s: %v", nodetype, cfgDir, err))
	}

	// Merge version-specific config if any.
	mergeConfig(path)

	return filepath.Join(path, file)
}

func mergeConfig(path string) error {
	viper.SetConfigFile(path + "/config.yaml")
	err := viper.MergeInConfig()
	if err != nil {
		if os.IsNotExist(err) {
			glog.V(2).Info(fmt.Sprintf("No version-specific config.yaml file in %s", path))
		} else {
			return fmt.Errorf("couldn't read config file %s: %v", path+"/config.yaml", err)
		}
	}

	glog.V(1).Info(fmt.Sprintf("Using config file: %s\n", viper.ConfigFileUsed()))

	return nil
}

func mapToBenchmarkVersion(kubeToBenchmarkMap map[string]string, kv string) (string, error) {
	kvOriginal := kv
	cisVersion, found := kubeToBenchmarkMap[kv]
	glog.V(2).Info(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	for !found && (kv != defaultKubeVersion && !isEmpty(kv)) {
		kv = decrementVersion(kv)
		cisVersion, found = kubeToBenchmarkMap[kv]
		glog.V(2).Info(fmt.Sprintf("mapToBenchmarkVersion for k8sVersion: %q cisVersion: %q found: %t\n", kv, cisVersion, found))
	}

	if !found {
		glog.V(1).Info(fmt.Sprintf("mapToBenchmarkVersion unable to find a match for: %q", kvOriginal))
		glog.V(3).Info(fmt.Sprintf("mapToBenchmarkVersion kubeToBenchmarkSMap: %#v", kubeToBenchmarkMap))
		return "", fmt.Errorf("unable to find a matching Benchmark Version match for kubernetes version: %s", kvOriginal)
	}

	return cisVersion, nil
}

func loadVersionMapping(v *viper.Viper) (map[string]string, error) {
	kubeToBenchmarkMap := v.GetStringMapString("version_mapping")
	if kubeToBenchmarkMap == nil || (len(kubeToBenchmarkMap) == 0) {
		return nil, fmt.Errorf("config file is missing 'version_mapping' section")
	}

	return kubeToBenchmarkMap, nil
}

func getBenchmarkVersion(kubeVersion, benchmarkVersion string, v *viper.Viper) (bv string, err error) {
	if !isEmpty(kubeVersion) && !isEmpty(benchmarkVersion) {
		return "", fmt.Errorf("It is an error to specify both --version and --benchmark flags")
	}

	if isEmpty(benchmarkVersion) {
		if isEmpty(kubeVersion) {
			kubeVersion, err = getKubeVersion()
			if err != nil {
				return "", fmt.Errorf("Version check failed: %s\nAlternatively, you can specify the version with --version", err)
			}
		}

		kubeToBenchmarkMap, err := loadVersionMapping(v)
		if err != nil {
			return "", err
		}

		benchmarkVersion, err = mapToBenchmarkVersion(kubeToBenchmarkMap, kubeVersion)
		if err != nil {
			return "", err
		}

		glog.V(2).Info(fmt.Sprintf("Mapped Kubernetes version: %s to Benchmark version: %s", kubeVersion, benchmarkVersion))
	}

	glog.V(1).Info(fmt.Sprintf("Kubernetes version: %q to Benchmark version: %q", kubeVersion, benchmarkVersion))
	return benchmarkVersion, nil
}

// isMaster verify if master components are running on the node.
func isMaster() bool {
	loadConfig(check.MASTER)
	return isThisNodeRunning(check.MASTER)
}

// isEtcd verify if etcd components are running on the node.
func isEtcd() bool {
	return isThisNodeRunning(check.ETCD)
}

func isThisNodeRunning(nodeType check.NodeType) bool {
	glog.V(2).Infof("Checking if the current node is running %s components", nodeType)
	etcdConf := viper.Sub(string(nodeType))
	if etcdConf == nil {
		glog.V(2).Infof("No %s components found to be running", nodeType)
		return false
	}

	components, err := getBinariesFunc(etcdConf, nodeType)
	if err != nil {
		glog.V(2).Info(err)
		return false
	}
	if len(components) == 0 {
		glog.V(2).Infof("No %s binaries specified", nodeType)
		return false
	}

	return true
}

func printRawOutput(output string) {
	for _, row := range strings.Split(output, "\n") {
		fmt.Println(fmt.Sprintf("\t %s", row))
	}
}

func writeOutputToFile(output string, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, output)
	return w.Flush()
}

func PrintOutput(output string, outputFile string) {
	if len(outputFile) == 0 {
		fmt.Println(output)
	} else {
		err := writeOutputToFile(output, outputFile)
		if err != nil {
			exitWithError(fmt.Errorf("Failed to write to output file %s: %v", outputFile, err))
		}
	}
}

var benchmarkVersionToTargetsMap = map[string][]string{
	"cis-1.3": []string{string(check.MASTER), string(check.NODE)},
	"cis-1.4": []string{string(check.MASTER), string(check.NODE)},
	"cis-1.5": []string{string(check.MASTER), string(check.NODE), string(check.CONTROLPLANE), string(check.ETCD), string(check.POLICIES)},
	"gke-1.0": []string{string(check.MASTER), string(check.NODE), string(check.CONTROLPLANE), string(check.ETCD), string(check.POLICIES), string(check.MANAGEDSERVICES)},
}

// validTargets helps determine if the targets
// are legitimate for the benchmarkVersion.
func validTargets(benchmarkVersion string, targets []string) bool {
	providedTargets, found := benchmarkVersionToTargetsMap[benchmarkVersion]
	if !found {
		return false
	}

	for _, pt := range targets {
		f := false
		for _, t := range providedTargets {
			if pt == strings.ToLower(t) {
				f = true
				break
			}
		}

		if !f {
			return false
		}
	}

	return true
}
