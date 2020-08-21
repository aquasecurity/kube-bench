package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/kube-bench/check"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringSliceP("targets", "s", []string{},
		`Specify targets of the benchmark to run. These names need to match the filenames in the cfg/<version> directory.
	For example, to run the tests specified in master.yaml and etcd.yaml, specify --targets=master,etcd
	If no targets are specified, run tests from all files in the cfg/<version> directory.
	`)
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run tests",
	Long:  `Run tests. If no arguments are specified, runs tests from all files`,
	Run: func(cmd *cobra.Command, args []string) {
		targets, err := cmd.Flags().GetStringSlice("targets")
		if err != nil {
			exitWithError(fmt.Errorf("unable to get `targets` from command line :%v", err))
		}

		bv, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
		if err != nil {
			exitWithError(fmt.Errorf("unable to get benchmark version. error: %v", err))
		}

		glog.V(2).Infof("Checking targets %v for %v", targets, bv)
		benchmarkVersionToTargetsMap, err := loadTargetMapping(viper.GetViper())
		if err != nil {
			exitWithError(fmt.Errorf("error loading targets: %v", err))
		}
		valid, err := validTargets(bv, targets, viper.GetViper())
		if err != nil {
			exitWithError(fmt.Errorf("error validating targets: %v", err))
		}
		if len(targets) > 0 && !valid {
			exitWithError(fmt.Errorf(fmt.Sprintf(`The specified --targets "%s" are not configured for the CIS Benchmark %s\n Valid targets %v`, strings.Join(targets, ","), bv, benchmarkVersionToTargetsMap[bv])))
		}

		// Merge version-specific config if any.
		path := filepath.Join(cfgDir, bv)
		mergeConfig(path)

		err = run(targets, bv)
		if err != nil {
			fmt.Printf("Error in run: %v\n", err)
		}
	},
}

func run(targets []string, benchmarkVersion string) (err error) {
	yamlFiles, err := getTestYamlFiles(targets, benchmarkVersion)
	if err != nil {
		return err
	}

	glog.V(3).Infof("Running tests from files %v\n", yamlFiles)

	for _, yamlFile := range yamlFiles {
		_, name := filepath.Split(yamlFile)
		testType := check.NodeType(strings.Split(name, ".")[0])
		runChecks(testType, yamlFile)
	}

	writeOutput(controlsCollection)
	return nil
}

func getTestYamlFiles(targets []string, benchmarkVersion string) (yamlFiles []string, err error) {
	// Check that the specified targets have corresponding YAML files in the config directory
	configFileDirectory := filepath.Join(cfgDir, benchmarkVersion)
	for _, target := range targets {
		filename := translate(target) + ".yaml"
		file := filepath.Join(configFileDirectory, filename)
		if _, err := os.Stat(file); err != nil {
			return nil, fmt.Errorf("file %s not found for version %s", filename, benchmarkVersion)
		}
		yamlFiles = append(yamlFiles, file)
	}

	// If no targets were specified, we will run tests from all the files in the directory
	if len(yamlFiles) == 0 {
		yamlFiles, err = getYamlFilesFromDir(configFileDirectory)
		if err != nil {
			return nil, err
		}
	}

	return yamlFiles, err
}

func translate(target string) string {
	return strings.Replace(strings.ToLower(target), "worker", "node", -1)
}
