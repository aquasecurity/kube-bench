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
	runCmd.Flags().StringSliceP("sections", "s", []string{},
		`Specify sections of the benchmark to run. These names need to match the filenames in the cfg/<version> directory.
	For example, to run the tests specified in master.yaml and etcd.yaml, specify --sections=master,etcd 
	If no sections are specified, run tests from all files in the cfg/<version> directory.
	`)
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run tests",
	Long:  `Run tests. If no arguments are specified, runs tests from all files`,
	Run: func(cmd *cobra.Command, args []string) {
		sections, err := cmd.Flags().GetStringSlice("sections")
		if err != nil {
			exitWithError(err)
		}

		benchmarkVersion, err := getBenchmarkVersion(kubeVersion, benchmarkVersion, viper.GetViper())
		if err != nil {
			exitWithError(err)
		}

		// Merge version-specific config if any.
		path := filepath.Join(cfgDir, benchmarkVersion)
		mergeConfig(path)

		err = run(sections, benchmarkVersion)
		if err != nil {
			fmt.Printf("Error in run: %v\n", err)
		}
	},
}

func run(sections []string, benchmarkVersion string) (err error) {

	yamlFiles, err := getTestYamlFiles(sections, benchmarkVersion)
	if err != nil {
		return err
	}

	glog.V(3).Infof("Running tests from files %v\n", yamlFiles)

	for _, yamlFile := range yamlFiles {
		_, name := filepath.Split(yamlFile)
		testType := check.NodeType(strings.Split(name, ".")[0])
		runChecks(testType, yamlFile)
	}

	return nil
}

func getTestYamlFiles(sections []string, benchmarkVersion string) (yamlFiles []string, err error) {

	// Check that the specified sections have corresponding YAML files in the config directory
	configFileDirectory := filepath.Join(cfgDir, benchmarkVersion)
	for _, section := range sections {
		filename := section + ".yaml"
		file := filepath.Join(configFileDirectory, filename)
		if _, err := os.Stat(file); err != nil {
			return nil, fmt.Errorf("file %s not found for version %s", filename, benchmarkVersion)
		}
		yamlFiles = append(yamlFiles, file)
	}

	// If no sections were specified, we will run tests from all the files in the directory
	if len(yamlFiles) == 0 {
		yamlFiles, err = getYamlFilesFromDir(configFileDirectory)
		if err != nil {
			return nil, err
		}
	}

	return yamlFiles, err
}
